"""Measure MVW traffic against one local app with a Docker CPU and memory limit."""

from __future__ import annotations

import argparse
import asyncio
import cProfile
import json
import math
import os
import pstats
import statistics
import subprocess
import sys
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from tools.load_check import OP_NAMES, expect, prepare, run_app, test_database

PAGES = tuple(zip(OP_NAMES[:3], ("/", "/external-agents", "/approvals"), strict=True))


class _StartupPipe:
    def send(self, value):
        print(json.dumps(value), flush=True)

    def close(self):
        pass


def inside():
    """Run only inside the local benchmark container. Credentials travel over pipes."""
    dsn, people, pool_size, profile, expected_cpu, expected_memory, workers = json.loads(sys.stdin.readline())
    quota, period = Path("/sys/fs/cgroup/cpu.max").read_text().split()
    memory = Path("/sys/fs/cgroup/memory.max").read_text().strip()
    if quota == "max" or int(quota) / int(period) != expected_cpu or memory != str(expected_memory):
        raise RuntimeError("The Docker daemon did not enforce the requested CPU and memory limits.")
    recorder = cProfile.Profile()
    try:
        with TemporaryDirectory(prefix="second-shift-mvw-") as directory:
            if profile:
                recorder.enable()
            run_app(_StartupPipe(), directory, dsn, people, pool_size, workers)
    finally:
        if profile:
            recorder.disable()
            pstats.Stats(recorder).dump_stats("/benchmark/request-profile.pstats")


def summary(timings, errors, threshold):
    return {
        name: {
            "count": len(times),
            "median_ms": round(statistics.median(times), 2),
            "p95_ms": round(sorted(times)[math.ceil(0.95 * len(times)) - 1], 2),
            "max_ms": round(max(times), 2),
            "under_target": sum(delta < threshold for delta in times),
            "errors": dict(errors[name]),
        }
        for name, times in timings.items()
    }


class Workload:
    """One measured request tracker used by the serial, burst and steady scenarios."""

    def __init__(self, client, team_token):
        self.client = client
        self.team_token = team_token
        self.timings = defaultdict(list)
        self.errors = defaultdict(Counter)

    async def request(self, name, method, path, headers, payload=None):
        began = time.perf_counter()
        try:
            reply = await self.client.request(method, path, headers=headers, json=payload)
            expected = 201 if name == "Report run" else 200
            if reply.status_code != expected:
                code = str(reply.status_code)
                if code == "503" and b"external request capacity is busy" in reply.content:
                    code = "503 gateway busy"
                self.errors[name][code] += 1
            elif name == "Screen" and reply.json().get("allowed") is not True:
                self.errors[name]["screen refused"] += 1
            elif name == "Teams card" and "Rejected by" not in reply.text:
                self.errors[name]["decision not recorded"] += 1
        except (ValueError, httpx.HTTPError) as error:
            self.errors[name][type(error).__name__] += 1
        finally:
            self.timings[name].append((time.perf_counter() - began) * 1000)

    async def page(self, cookie, page_index):
        name, path = PAGES[page_index % len(PAGES)]
        await self.request(name, "GET", path, {"Cookie": f"ss_session={cookie}"})

    async def agent(self, headers, key):
        await self.request("Screen", "POST", "/api/v1/external/screen", headers, {"tool": "load_read", "risk": "low"})
        await self.request("Report run", "POST", "/api/v1/external/runs", headers, {
            "title": "Local MVW load check", "outcome": "success", "tools": ["load_read"],
            "tool_calls": 1, "idempotency_key": key,
        })

    async def teams(self, card):
        await self.request("Teams card", "POST", "/webhook/teams", {"Authorization": f"Bearer {self.team_token}"}, card)


async def wait_for_ready(client):
    for _ in range(150):
        try:
            if (await client.get("/readyz")).status_code == 200:
                return
        except httpx.TransportError:
            pass
        await asyncio.sleep(0.2)
    raise RuntimeError("The local benchmark app did not become ready.")


async def serial(client, token, person, key, cards):
    work = Workload(client, token)
    for sequence, card in enumerate(cards):
        for index in range(len(PAGES)):
            await work.page(person, index)
        await work.agent(key, f"serial-{sequence}")
        await work.teams(card)
    return summary(work.timings, work.errors, 200)


async def burst(client, token, people, size):
    work = Workload(client, token)
    await asyncio.gather(*(work.page(person, index) for index, person in enumerate(people[:size])))
    return summary(work.timings, work.errors, 2000)


async def steady(client, token, people, keys, cards, seconds):
    work = Workload(client, token)
    period = 30
    loop = asyncio.get_running_loop()
    starts = loop.time()

    async def every(index, count, action):
        offset = index * period / count
        for sequence in range(math.ceil(seconds / period)):
            when = offset + sequence * period
            if when >= seconds:
                break
            await asyncio.sleep(max(0, starts + when - loop.time()))
            await action(sequence)

    async def card_request(index, card):
        await asyncio.sleep(max(0, starts + (index + 1) * seconds / (len(cards) + 1) - loop.time()))
        await work.teams(card)

    await asyncio.gather(
        *(every(index, len(people), lambda turn, p=person, i=index: work.page(p, i + turn))
          for index, person in enumerate(people)),
        *(every(index, len(keys), lambda turn, h=key, i=index: work.agent(h, f"steady-{i}-{turn}"))
          for index, key in enumerate(keys)),
        *(card_request(index, card) for index, card in enumerate(cards)),
    )
    return summary(work.timings, work.errors, 1000)


async def measure(payload, args):
    origin, administrator, people, token = payload
    async with httpx.AsyncClient(base_url=origin, trust_env=False, timeout=180,
                                 limits=httpx.Limits(max_connections=800, max_keepalive_connections=150)) as client:
        await wait_for_ready(client)
        agents = 1 if args.profile else args.agents
        card_count = 4 if args.profile else 14
        keys, cards = await prepare(client, origin, administrator, agents, card_count)
        for _, path in PAGES:
            expect(await client.get(path, headers={"Cookie": f"ss_session={people[0]}"}), 200, "Page warm-up")
        result = {"serial": await serial(client, token, people[0], keys[0], cards[:4])}
        if not args.profile:
            result["burst"] = await burst(client, token, people, args.burst)
            result["steady"] = await steady(client, token, people, keys, cards[4:], args.seconds)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="second-shift:benchmark")
    parser.add_argument("--cpus", type=float, required=True)
    parser.add_argument("--memory-gib", type=int, required=True)
    parser.add_argument("--pool-size", type=int, default=8)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--people", type=int, default=500)
    parser.add_argument("--agents", type=int, default=100)
    parser.add_argument("--burst", type=int, default=100)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.burst <= args.people or min(args.agents, args.pool_size, args.seconds, args.workers) < 1:
        parser.error("Choose positive workload counts and a burst no larger than the number of people.")
    dsn = os.environ.get("SECOND_SHIFT_LOAD_DSN")
    if not dsn:
        parser.error("Set SECOND_SHIFT_LOAD_DSN for the disposable loopback PostgreSQL service.")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    name = "second-shift-mvw-" + uuid.uuid4().hex[:12]
    with test_database(dsn) as (_, _, isolated_dsn):
        command = [
            "docker", "run", "--rm", "-i", "--name", name, "--network", "host",
            "--cpus", str(args.cpus), "--memory", f"{args.memory_gib}g", "--memory-swap", f"{args.memory_gib}g",
            "--volume", f"{Path.cwd()}:/checkout:ro",
            "--volume", f"{output.parent}:/benchmark",
            "--workdir", "/checkout", "--user", "0:0", "--entrypoint", "python", args.image,
            "-c", "from tools.mvw_benchmark import inside; inside()",
        ]
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as process:
            try:
                process.stdin.write(json.dumps([
                    isolated_dsn, 1 if args.profile else args.people, args.pool_size, args.profile,
                    args.cpus, args.memory_gib * 1024 ** 3, args.workers,
                ]) + "\n")
                process.stdin.close()
                startup = process.stdout.readline()
                if not startup:
                    raise RuntimeError("The local benchmark app could not start. Read the container error.")
                report = asyncio.run(measure(json.loads(startup), args))
                output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
                print(output)
            finally:
                subprocess.run(["docker", "stop", "--time", "10", name], check=False, stdout=subprocess.DEVNULL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
