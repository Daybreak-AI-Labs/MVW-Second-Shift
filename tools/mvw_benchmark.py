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
    (dsn, people, pool_size, profile, expected_cpu, expected_memory, workers,
     population, recorders) = json.loads(sys.stdin.readline())
    quota, period = Path("/sys/fs/cgroup/cpu.max").read_text().split()
    memory = Path("/sys/fs/cgroup/memory.max").read_text().strip()
    if quota == "max" or int(quota) / int(period) != expected_cpu or memory != str(expected_memory):
        raise RuntimeError("The Docker daemon did not enforce the requested CPU and memory limits.")
    recorder = cProfile.Profile()
    try:
        with TemporaryDirectory(prefix="second-shift-mvw-") as directory:
            if profile:
                recorder.enable()
            run_app(_StartupPipe(), directory, dsn, people, pool_size, workers, population, recorders)
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
        self.retries = Counter()

    def report(self, target):
        result = summary(self.timings, self.errors, target)
        for name, item in result.items():
            if self.retries[name]:
                item["retried"] = self.retries[name]
        return result

    async def request(self, name, method, path, headers, payload=None, *, retry_busy=False):
        began = time.perf_counter()
        try:
            for attempt in range(3):
                reply = await self.client.request(method, path, headers=headers, json=payload)
                marked_busy = (reply.status_code == 503
                               and reply.headers.get("X-Second-Shift-Admission") == "busy"
                               and reply.headers.get("Retry-After") == "1")
                if not retry_busy or not marked_busy or attempt == 2:
                    break
                self.retries[name] += 1
                await asyncio.sleep(1)
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
            elif name == "Recorder instructions" and reply.json().get("record") is not True:
                self.errors[name]["recording not active"] += 1
            elif name == "Recorder hand-over" and reply.json().get("accepted") != 1:
                self.errors[name]["activity not accepted"] += 1
        except asyncio.CancelledError:
            self.errors[name]["measurement deadline"] += 1
            raise
        except (ValueError, httpx.HTTPError) as error:
            self.errors[name][type(error).__name__] += 1
        finally:
            self.timings[name].append((time.perf_counter() - began) * 1000)

    async def page(self, cookie, page_index):
        name, path = PAGES[page_index % len(PAGES)]
        await self.request(name, "GET", path, {"Cookie": f"ss_session={cookie}"})

    async def agent(self, headers, key):
        await self.request("Screen", "POST", "/api/v1/external/screen", headers, {"tool": "load_read", "risk": "low"},
                           retry_busy=True)
        await self.request("Report run", "POST", "/api/v1/external/runs", headers, {
            "title": "Local MVW load check", "outcome": "success", "tools": ["load_read"],
            "tool_calls": 1, "idempotency_key": key,
        }, retry_busy=True)

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
    return work.report(200)


async def burst(client, token, people, size):
    work = Workload(client, token)
    await asyncio.gather(*(work.page(person, index) for index, person in enumerate(people[:size])))
    return work.report(2000)


async def steady(client, token, people, keys, cards, seconds):
    work = Workload(client, token)
    period = 30
    run_id = uuid.uuid4().hex
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
        *(every(index, len(keys), lambda turn, h=key, i=index: work.agent(h, f"steady-{run_id}-{i}-{turn}"))
          for index, key in enumerate(keys)),
        *(card_request(index, card) for index, card in enumerate(cards)),
    )
    return work.report(1000)


async def recorder_hour(client, token, recorders, seconds):
    """Replay the recorder's five-second poll and its 30-second flush."""
    from recorder.second_shift_recorder import FLUSH_SECONDS

    work = Workload(client, token)
    poll = 5.0  # docs/ekko.md default recorder poll
    loop = asyncio.get_running_loop()
    starts = loop.time()
    wall_start = time.time()

    async def recorder(index, key, session):
        offset = index * poll / len(recorders)
        headers = {"Authorization": f"Bearer {key}"}
        for turn in range(math.ceil(seconds / poll)):
            when = offset + turn * poll
            if when >= seconds:
                break
            await asyncio.sleep(max(0, starts + when - loop.time()))
            await work.request("Recorder instructions", "GET", "/api/v1/external/ekko/instructions", headers)
            if turn and turn % round(FLUSH_SECONDS / poll) == 0:
                await work.request("Recorder hand-over", "POST", "/api/v1/external/ekko/handover", headers, {
                    "session_id": session, "batch_id": f"batch-{turn:04d}", "account": f"{index:064x}",
                    "activities": [{"app": "excel" if turn % 12 else "word", "action": "switch",
                                    "duration_seconds": FLUSH_SECONDS, "occurred_at": wall_start + when}],
                })

    try:
        async with asyncio.timeout(seconds + 30):
            await asyncio.gather(*(recorder(index, *item) for index, item in enumerate(recorders)))
    except TimeoutError:
        pass
    planned = {"Recorder instructions": 0, "Recorder hand-over": 0}
    flush_turns = round(FLUSH_SECONDS / poll)
    for index in range(len(recorders)):
        scheduled = math.ceil((seconds - index * poll / len(recorders)) / poll)
        planned["Recorder instructions"] += scheduled
        planned["Recorder hand-over"] += max(0, (scheduled - 1) // flush_turns)
    result = work.report(1000)
    for name, expected in planned.items():
        item = result.get(name)
        if item is None:
            result[name] = {"count": 0, "scheduled": expected, "errors": {"not sent": expected}}
        else:
            item["scheduled"] = expected
            if expected > item["count"]:
                item["errors"]["not sent"] = expected - item["count"]
    return result


class _TrafficClient:
    """A lightweight load driver that does not scan the idle sockets each time."""

    def __init__(self, origin, connections):
        import aiohttp

        self.aiohttp = aiohttp
        self.session = aiohttp.ClientSession(
            base_url=origin, connector=aiohttp.TCPConnector(limit=connections), trust_env=False,
            timeout=aiohttp.ClientTimeout(total=60), cookie_jar=aiohttp.DummyCookieJar(),
            auto_decompress=False,
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.session.close()

    async def request(self, method, path, *, headers=None, json=None):
        try:
            async with self.session.request(method, path, headers=headers, json=json, allow_redirects=False) as reply:
                return httpx.Response(reply.status, headers=dict(reply.headers), content=await reply.read())
        except (self.aiohttp.ClientError, TimeoutError) as exc:
            raise httpx.TransportError("The local benchmark request did not complete.") from exc

    async def get(self, path, **kwargs):
        return await self.request("GET", path, **kwargs)

    async def post(self, path, **kwargs):
        return await self.request("POST", path, **kwargs)


def client_for(origin, *, connections=800):
    try:
        return _TrafficClient(origin, connections)
    except ImportError:
        return httpx.AsyncClient(base_url=origin, trust_env=False, timeout=60,
                                 limits=httpx.Limits(max_connections=connections, max_keepalive_connections=connections))


async def measure_steady(payload, args):
    origin, administrator, people, token = payload[:4]
    async with client_for(origin) as client:
        await wait_for_ready(client)
        if args.recorders:
            return {"recorder": await recorder_hour(client, token, payload[4], args.seconds)}
        keys, cards = await prepare(client, origin, administrator, args.agents, args.cards)
        return {"steady": await steady(client, token, people, keys, cards, args.seconds)}


async def measure(payload, args):
    origin, administrator, people, token = payload[:4]
    async with client_for(origin) as client:
        await wait_for_ready(client)
        if args.recorders:
            return {"recorder": await recorder_hour(client, token, payload[4], args.seconds)}
        agents = 1 if args.profile else args.agents
        card_count = 4 if args.profile else 24 if args.mvw else 14
        keys, cards = await prepare(client, origin, administrator, agents, card_count)
        for _, path in PAGES:
            expect(await client.get(path, headers={"Cookie": f"ss_session={people[0]}"}), 200, "Page warm-up")
        result = {"serial": await serial(client, token, people[0], keys[0], cards[:4])}
        if not args.profile:
            result["burst"] = await burst(client, token, people, args.burst)
            if args.quick:
                return result
            result["steady"] = await steady(client, token, people, keys, cards[4:14], args.seconds)
            if args.mvw:
                result["burst500"] = await burst(client, token, people, 500)
                result["steady25"] = await steady(client, token, people, keys[:25], cards[14:], args.seconds)
                overload = Workload(client, token)
                await asyncio.gather(*(overload.agent(headers, f"overload-{index}") for index, headers in enumerate(keys)))
                result["overload"] = overload.report(2000)
    return result


async def measure_resources(payload, args, monitor_connection, database_name):
    """Sample database contention alongside the measured workload."""
    complete = asyncio.Event()
    samples = []

    def snapshot():
        return monitor_connection.execute(
            "SELECT count(*), count(*) FILTER (WHERE state = 'active'), "
            "count(*) FILTER (WHERE wait_event_type = 'Lock') "
            "FROM pg_stat_activity WHERE datname = %s", (database_name,),
        ).fetchone()

    async def monitor():
        while not complete.is_set():
            samples.append(await asyncio.to_thread(snapshot))
            try:
                await asyncio.wait_for(complete.wait(), timeout=1)
            except TimeoutError:
                continue

    task = asyncio.create_task(monitor())
    try:
        result = await measure(payload, args)
    finally:
        complete.set()
        await task
    totals = tuple(map(max, zip(*samples, strict=True)))
    result["database"] = dict(zip(("peak_connections", "peak_active", "peak_lock_waits"), totals, strict=True))
    return result


def target_failures(report):
    """Apply the round's strict latency and availability limits."""
    failures = []
    if any(name not in report["serial"] or report["serial"][name]["max_ms"] >= 200
           or report["serial"][name]["errors"] for name in OP_NAMES):
        failures.append("A serial operation took 200 ms or more, or failed.")
    pages = OP_NAMES[:3]
    for name, threshold in (("steady", "one second"), ("burst", "two seconds")):
        case = report[name]
        total = sum(case.get(page, {}).get("count", 0) for page in pages)
        under = sum(case.get(page, {}).get("under_target", 0) for page in pages)
        if not total or under * 100 < total * 95:
            failures.append(f"Fewer than 95% of {name} page requests finished under {threshold}.")
        if name == "steady" and any(not case.get(operation) or case[operation]["errors"]
                                    for operation in (*pages, "Teams card")):
            failures.append("A page or Teams request failed during steady traffic.")
    if any(item["errors"] for item in report.get("overload", {}).values()):
        failures.append("An agent still failed after the bounded retry.")
    return failures


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
    parser.add_argument("--mvw", action="store_true", help="also measure 500 arrivals and 25 agents")
    parser.add_argument("--quick", action="store_true", help="measure only the serial and 100-arrival cases")
    parser.add_argument("--require-targets", action="store_true", help="fail when a measured workload misses an MVW target")
    parser.add_argument("--population", type=int, default=0)
    parser.add_argument("--recorders", type=int, default=0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.burst <= args.people or min(args.agents, args.pool_size, args.seconds, args.workers) < 1:
        parser.error("Choose positive workload counts and a burst no larger than the number of people.")
    if (not 0 <= args.population <= 50_000 or not 0 <= args.recorders <= 2_500 or args.seconds > 3600
            or (args.mvw and (args.people < 500 or args.agents < 25))
            or (args.profile and (args.mvw or args.recorders))
            or (args.require_targets and (not args.mvw or args.quick or args.recorders))):
        parser.error("Use realistic workload counts and run the profiler and recorder load separately.")
    dsn = os.environ.get("SECOND_SHIFT_LOAD_DSN")
    if not dsn:
        parser.error("Set SECOND_SHIFT_LOAD_DSN for the disposable loopback PostgreSQL service.")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    name = "second-shift-mvw-" + uuid.uuid4().hex[:12]
    with test_database(dsn) as (monitor_connection, database_name, isolated_dsn):
        command = [
            "docker", "run", "--rm", "-i", "--name", name, "--network", "host",
            "--cpus", str(args.cpus), "--memory", f"{args.memory_gib}g", "--memory-swap", f"{args.memory_gib}g",
            "--volume", f"{Path.cwd()}:/checkout:ro",
            "--volume", f"{output.parent}:/benchmark",
            "--workdir", "/checkout", *(("--user", "0:0") if args.profile else ()), "--entrypoint", "python", args.image,
            "-c", "from tools.mvw_benchmark import inside; inside()",
        ]
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as process:
            try:
                process.stdin.write(json.dumps([
                    isolated_dsn, 1 if args.profile else args.people, args.pool_size, args.profile,
                    args.cpus, args.memory_gib * 1024 ** 3, args.workers, args.population, args.recorders,
                ]) + "\n")
                process.stdin.close()
                startup = process.stdout.readline()
                if not startup:
                    raise RuntimeError("The local benchmark app could not start. Read the container error.")
                report = asyncio.run(measure_resources(json.loads(startup), args, monitor_connection, database_name))
                output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
                print(output)
            finally:
                subprocess.run(["docker", "stop", "--time", "10", name], check=False, stdout=subprocess.DEVNULL)
    failures = target_failures(report) if args.require_targets else []
    for message in failures:
        print(message, file=sys.stderr)
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
