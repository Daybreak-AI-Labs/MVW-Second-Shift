"""Measure browser, agent, Teams and recorder traffic on local PostgreSQL."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import multiprocessing
import os
import secrets
import socket
import statistics
import time
import uuid
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

OP_NAMES = ("Home", "Outside agents", "Approvals", "Screen", "Report run", "Teams card")
BOT_ID = "0f0f0f0f-1111-2222-3333-444444444444"
TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TEAMS_ACTOR = "11111111-aaaa-aaaa-aaaa-111111111111"
# https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-authentication
TEAMS_SERVICE = "https://smba.trafficmanager.net/emea/"


@contextmanager
def test_database(dsn):
    """Use a loopback-only bootstrap login and clean up the dedicated data."""
    params = conninfo_to_dict(dsn)
    if params.get("host") != "127.0.0.1" or params.get("hostaddr", "127.0.0.1") != "127.0.0.1" or "service" in params:
        raise RuntimeError("Use an explicit 127.0.0.1 PostgreSQL address for this local check.")
    dsn = make_conninfo(dsn, hostaddr="127.0.0.1", connect_timeout=5)
    name = "ss_load_" + uuid.uuid4().hex
    password = secrets.token_urlsafe(32)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
            sql.Identifier(name), sql.Literal(password)))
        try:
            conn.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(name), sql.Identifier(name)))
            try:
                yield conn, name, make_conninfo(dsn, dbname=name, user=name, password=password, options="")
            finally:
                conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))
        finally:
            conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))


def configure_app(directory, origin, dsn, pool_size, recorders=0):
    for key in list(os.environ):
        if key.startswith(("MAVERICK_", "SECOND_SHIFT_", "AZURE_")):
            del os.environ[key]
    oidc_secret = secrets.token_urlsafe(48)
    encryption_key = secrets.token_bytes(32)
    os.environ.update({
        "MAVERICK_HOME": directory,
        "MAVERICK_CONFIG": str(Path(directory) / "config.toml"),
        "MAVERICK_WORLD_BACKEND": "postgres",
        "MAVERICK_PG_DSN": dsn,
        "MAVERICK_PG_POOL_SIZE": str(pool_size),
        "MAVERICK_PG_RLS": "1",
        "MAVERICK_CLIENT_ID": "load-workspace",
        "MAVERICK_PUBLIC_URL": origin,
        "MAVERICK_ENCRYPT_AT_REST": "1",
        "MAVERICK_ENCRYPT_STRICT": "1",
        "MAVERICK_ENCRYPTION_KEY": encryption_key.hex(),
        "MAVERICK_ENCRYPTION_KEY_DIGEST": "sha256:" + hashlib.sha256(encryption_key).hexdigest(),
        "MAVERICK_AUDIT_SIGNING_KEY": secrets.token_hex(32),
        "MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY": "1",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH": "1",
        "MAVERICK_EXTERNAL_AGENTS": "1",
        "MAVERICK_OIDC_ENABLED": "1",
        "MAVERICK_OIDC_CLIENT_ID": "local-load-check",
        "MAVERICK_OIDC_AUDIENCE": "local-load-check",
        "MAVERICK_OIDC_ISSUER": "https://login.example.invalid/v2.0",
        "MAVERICK_OIDC_REDIRECT_URI": f"{origin}/auth/callback",
        "MAVERICK_OIDC_CLIENT_SECRET": secrets.token_urlsafe(32),
        "MAVERICK_OIDC_SESSION_SECRET": oidc_secret,
        "SECOND_SHIFT_LOAD_BOT_SECRET": secrets.token_urlsafe(32),
    })
    Path(os.environ["MAVERICK_CONFIG"]).write_text(
        '[auth.oidc.role_map]\n"Load.Operator" = "operator"\n"Load.Admin" = "admin"\n'
        '[external_agents]\nmax_enrolled = 500\n'
        f'[governed_records]\npool_size = {pool_size}\n'
        f'[teams]\nenabled = true\napp_id = "{BOT_ID}"\ntenant_id = "{TENANT_ID}"\n'
        'app_secret_env = "SECOND_SHIFT_LOAD_BOT_SECRET"\n'
        + ('[ekko]\nenable = true\nallowed_apps = ["excel", "word"]\n' if recorders else ""), encoding="utf-8")
    return oidc_secret


def teams_test_token():
    """Create an ephemeral signer for the local benchmark."""
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    public.update(kid="load-check", use="sig", alg="RS256", endorsements=["msteams"])
    os.environ["SECOND_SHIFT_LOAD_JWKS"] = json.dumps({"keys": [public]})
    now = int(time.time())
    return jwt.encode({"iss": "https://api.botframework.com", "aud": BOT_ID, "iat": now,
                       "nbf": now - 1, "exp": now + 3600, "serviceurl": TEAMS_SERVICE},
                      private, algorithm="RS256", headers={"kid": "load-check"})


def benchmark_app():
    """Install the connector stand-in in each local benchmark worker."""
    from maverick import approval_notify
    from maverick_dashboard import teams_bot
    from maverick_dashboard.app import app

    bot = teams_bot.build_bot(transport=lambda *args, **kwargs: (200, {}),
                              keys=teams_bot.SigningKeys(jwks=json.loads(os.environ["SECOND_SHIFT_LOAD_JWKS"])))
    teams_bot.build_bot = lambda **kwargs: bot
    # The benchmark measures inbound card decisions only.
    approval_notify._spawn = lambda *args: None
    return app


def seed_people(population):
    """Prepopulate the real indexed identity and sign-out stores."""
    from maverick import teams_identity
    from maverick_dashboard import account_profiles, session_revocation, subject_directory

    def person(index):
        return f"load-person-{index}"

    now = time.time() - 60
    with account_profiles._keyed().transaction(account_profiles._migrate, write=True) as store:
        store.rows("people").seed((
            f"user:{person(idx)}",
            account_profiles._encode({"name": f"Employee {idx}", "email": f"{person(idx)}@example.test", "at": now}),
            "", now,
        ) for idx in range(population))
    with subject_directory._keyed().transaction(subject_directory._migrate, write=True) as store:
        store.rows("people").seed((
            subject_directory._subject_key(person(idx)), json.dumps({"sub": person(idx), "ts": now}), "", now,
        ) for idx in range(population))
        store.rows("aliases").seed((
            subject_directory._key(alias), subject_directory._subject_key(person(idx)), "", now,
        ) for idx in range(population) for alias in (f"{person(idx)}@example.test", str(uuid.UUID(int=idx))))
    with session_revocation._keyed().transaction(session_revocation._migrate, write=True) as store:
        store.rows("people").seed((f"user:{person(idx)}", json.dumps(now), "", now) for idx in range(population))
    with teams_identity._keyed().transaction(teams_identity._migrate, write=True) as store:
        store.rows("links").seed((
            str(uuid.UUID(int=idx)),
            json.dumps({"principal": f"user:{person(idx)}", "upn": f"{person(idx)}@example.test", "linked_at": now}),
            f"user:{person(idx)}", now,
        ) for idx in range(population))


def seed_recorders(count):
    """Enrol synthetic people and start their real Ekko sessions."""
    from maverick import config, ekko_device_keys
    from maverick.paths import current_tenant_id_strict
    from maverick.work_discovery_store import WorkDiscoveryStore

    policy = config.get_ekko_policy()
    tenant = current_tenant_id_strict()
    recorders = []
    for index in range(count):
        person = f"user:load-person-{index}"
        store = WorkDiscoveryStore(person, "load-recorder", tenant=tenant)
        enrollment = store.enroll(policy)
        session = store.create_session(policy=policy)
        key, _ = ekko_device_keys.create(person, "load-recorder", tenant=tenant,
                                         enrollment=ekko_device_keys.enrollment_fingerprint(enrollment))
        recorders.append((key, session.session_id))
    return recorders


def run_app(pipe, directory, dsn, people, pool_size, workers=1, population=0, recorders=0):
    """Run the normal app, bound only to loopback, using synthetic identities."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(4096)
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        session_secret = configure_app(directory, origin, dsn, pool_size, recorders)

        import uvicorn
        from starlette.requests import Request

        from maverick import record_documents, teams_identity
        from maverick_dashboard import rbac, sign_in_roles
        from maverick_dashboard._shared import _world
        from maverick_dashboard.oidc_login import mint_browser_session
        from maverick_dashboard.worker_coordination import supervisor

        signing_key = os.environ["MAVERICK_AUDIT_SIGNING_KEY"]
        world = _world()
        world.ping()
        if population:
            seed_people(population)
        recorder_keys = seed_recorders(recorders) if recorders else []
        record_documents.at(rbac.store_path()).write_text(json.dumps({"user:load-teams": "approver"}))
        teams_identity.link(TEAMS_ACTOR, "user:load-teams", actor="load-check")
        teams_token = teams_test_token()
        request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)})

        def session(user, role):
            return mint_browser_session(
                request, sub=user, secret=session_secret, via="oidc", mfa=True, ttl=3600,
                extra=sign_in_roles.session_extra({"roles": [role]}),
            )

        payload = (origin, session("load-admin", "Load.Admin"),
                   [session(f"load-person-{idx}", "Load.Operator") for idx in range(people)], teams_token)
        pipe.send((*payload, recorder_keys) if recorder_keys else payload)
        pipe.close()
        # The setup process uses the same synthetic signer as its fresh workers.
        if workers > 1:
            os.environ["MAVERICK_AUDIT_SIGNING_KEY"] = signing_key
        with supervisor(workers):
            uvicorn.run("tools.load_check:benchmark_app", factory=True, workers=workers, fd=listener.fileno(),
                        backlog=4096, access_log=False, log_level="error", lifespan="on")


def expect(response, status, name):
    if response.status_code != status:
        raise RuntimeError(f"{name} returned HTTP {response.status_code}. Check the local app logs.")
    return response.json() if response.content and response.headers.get("content-type", "").startswith("application/json") else {}


def card_activity(approval, binding, index):
    return {
        "type": "invoke", "name": "adaptiveCard/action", "id": f"load-card-{index}", "channelId": "msteams",
        "serviceUrl": TEAMS_SERVICE, "replyToId": str(index),
        "from": {"id": "29:load-teams", "aadObjectId": TEAMS_ACTOR, "name": "Load approver"},
        "conversation": {"id": "19:load-teams", "conversationType": "personal", "tenantId": TENANT_ID},
        "recipient": {"id": f"28:{BOT_ID}"}, "channelData": {"tenant": {"id": TENANT_ID}},
        "value": {"action": {"type": "Action.Execute", "verb": "reject",
                             "data": {"approval_id": approval, "binding": binding}}, "trigger": "manual"},
    }


async def prepare(client, origin, admin_session, agents, cards):
    admin = {"Origin": origin, "Cookie": f"ss_session={admin_session}"}
    keys, approvals = [], []
    roster = "/api/v1/external-agents"
    for index in range(agents):
        agent_id = f"load-agent-{index}"
        enrollment = {"id": agent_id, "platform": "custom", "max_risk": "medium", "approval_at": "medium",
                      "allow_tools": ["load_read:low", "load_card:medium"]}
        expect(await client.post(roster, headers=admin, json=enrollment), 201, "Agent enrollment")
        receipt = expect(await client.post(f"{roster}/{agent_id}/credentials", headers=admin, json={"surface": "rest"}),
                         200, "Agent key mint")
        keys.append({"Authorization": f"Bearer {receipt['token']}"})
    for index in range(cards):
        pending = expect(await client.post("/api/v1/external/screen", headers=keys[index % agents],
                                           json={"tool": "load_card", "risk": "medium"}), 200, "Create card")
        approvals.append(card_activity(pending["approval_id"], pending["approval_binding_sha256"], index))
    return keys, approvals


def t_cpu(pid):
    """Linux process user plus system CPU time, excluding the load driver."""
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


async def sample_database(conn, dbname, finished, samples):
    query = """SELECT count(*), count(*) FILTER (WHERE state <> 'idle'),
                      count(*) FILTER (WHERE wait_event_type = 'Lock')
               FROM pg_stat_activity WHERE datname = %s AND backend_type = 'client backend'"""
    while not finished.is_set():
        rows = await asyncio.to_thread(lambda: conn.execute(query, (dbname,)).fetchone())
        samples.append(rows)
        try:
            await asyncio.wait_for(finished.wait(), timeout=0.1)
        except TimeoutError:
            pass


async def measure(conn, dbname, process, payload, args):
    origin, admin, sessions, teams = payload
    results = {name: [] for name in OP_NAMES}
    failures = {name: Counter() for name in OP_NAMES}
    limits = httpx.Limits(max_connections=len(sessions) + args.agents + args.cards + 10, max_keepalive_connections=256)
    async with httpx.AsyncClient(base_url=origin, limits=limits, timeout=300, trust_env=False) as client:
        for _ in range(150):
            try:
                if (await client.get("/readyz")).status_code == 200:
                    break
            except httpx.TransportError:
                if not process.is_alive():
                    raise RuntimeError("The local app stopped before becoming ready.") from None
            await asyncio.sleep(0.2)
        else:
            raise RuntimeError("The local app did not become ready.")
        keys, cards = await prepare(client, origin, admin, args.agents, args.cards)

        async def request(name, method, path, headers, body=None):
            started = time.perf_counter()
            try:
                response = await client.request(method, path, headers=headers, json=body)
                expected = 201 if name == "Report run" else 200
                if response.status_code != expected:
                    code = str(response.status_code)
                    if code == "503" and b"external request capacity is busy" in response.content:
                        code = "503 gateway busy"
                    failures[name][code] += 1
                    return
                if name == "Screen" and not response.json().get("allowed"):
                    failures[name]["screen refused"] += 1
                elif name == "Teams card":
                    card = response.json()
                    if card.get("type") != "application/vnd.microsoft.card.adaptive" or "Rejected by" not in json.dumps(card):
                        failures[name]["decision not recorded"] += 1
            except httpx.HTTPError as error:
                failures[name][type(error).__name__] += 1
            except ValueError:
                failures[name]["unreadable response"] += 1
            finally:
                results[name].append((time.perf_counter() - started) * 1000)

        async def browser(cookie):
            headers = {"Cookie": f"ss_session={cookie}"}
            for name, path in zip(OP_NAMES[:3], ("/", "/external-agents", "/approvals"), strict=True):
                await request(name, "GET", path, headers)

        async def agent(index, headers):
            await request("Screen", "POST", "/api/v1/external/screen", headers, {"tool": "load_read", "risk": "low"})
            await request("Report run", "POST", "/api/v1/external/runs", headers, {
                "title": "Local load check", "outcome": "success", "tools": ["load_read"], "tool_calls": 1,
                "idempotency_key": f"local-load-{index}",
            })

        # Warm connection, template and authorization paths outside the sample.
        for path in ("/", "/external-agents", "/approvals"):
            expect(await client.get(path, headers={"Cookie": f"ss_session={sessions[0]}"}), 200, "Page warm-up")
        finished, samples = asyncio.Event(), []
        monitor = asyncio.create_task(sample_database(conn, dbname, finished, samples))
        cpu, start = t_cpu(process.pid), time.perf_counter()
        try:
            await asyncio.gather(
                *(browser(session) for session in sessions),
                *(agent(index, key) for index, key in enumerate(keys)),
                *(request("Teams card", "POST", "/webhook/teams", {"Authorization": f"Bearer {teams}"}, card) for card in cards),
            )
        finally:
            finished.set()
            await monitor
        wall = time.perf_counter() - start
        cpu = t_cpu(process.pid) - cpu

    latencies = {}
    for name, values in results.items():
        ordered = sorted(values)
        latencies[name] = {
            "requests": len(values), "median_ms": round(statistics.median(values), 1),
            "p95_ms": round(ordered[math.ceil(0.95 * len(values)) - 1], 1),
            "failures": dict(failures[name]),
        }
    return {"people": args.people, "agents": args.agents, "cards": args.cards, "pool_size": args.pool_size,
            "wall_seconds": round(wall, 2), "app_cpu_cores": round(cpu / wall, 2),
            "peak_connections": max(row[0] for row in samples), "peak_nonidle": max(row[1] for row in samples),
            "peak_pg_lock_waits": max(row[2] for row in samples), "postgres_samples": len(samples),
            "latencies": latencies}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--people", type=int, required=True)
    parser.add_argument("--agents", type=int, required=True)
    parser.add_argument("--cards", type=int, default=10)
    parser.add_argument("--pool-size", type=int, default=8)
    parser.add_argument("--mode", choices=("burst", "steady"), default="burst")
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--population", type=int, default=0)
    parser.add_argument("--recorders", type=int, default=0)
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()
    if not (1 <= args.people <= 1000 and 1 <= args.agents <= 500 and 1 <= args.cards <= args.agents and 1 <= args.pool_size <= 32):
        parser.error("Use 1–1000 people, 1–500 agents, 1–agents cards and a pool of 1–32.")
    if (not 0 <= args.population <= 50_000 or not 0 <= args.recorders <= 2_500
            or not 1 <= args.workers <= 8 or not 1 <= args.seconds <= 3600):
        parser.error("Use up to 50,000 saved people, 2,500 recorders, eight workers and one hour.")
    if args.recorders and args.mode != "steady":
        parser.error("Use the steady mode to measure recorders.")
    dsn = os.environ.get("SECOND_SHIFT_LOAD_DSN")
    if not dsn:
        parser.error("Set SECOND_SHIFT_LOAD_DSN to a local PostgreSQL login that can create roles and databases.")
    ctx = multiprocessing.get_context("spawn")
    try:
        with test_database(dsn) as (conn, name, app_dsn), TemporaryDirectory(prefix="second-shift-load-") as directory:
            receive, send = ctx.Pipe(duplex=False)
            process = ctx.Process(target=run_app, args=(send, directory, app_dsn, args.people, args.pool_size,
                                                        args.workers, args.population, args.recorders))
            process.start()
            send.close()
            try:
                if not receive.poll(480 if args.population or args.recorders else 90):
                    raise RuntimeError("The local app did not finish preparing test sessions.")
                payload = receive.recv()
                if args.mode == "steady":
                    from tools.mvw_benchmark import measure_steady
                    result = asyncio.run(measure_steady(payload, args))
                else:
                    result = asyncio.run(measure(conn, name, process, payload, args))
            finally:
                receive.close()
                process.terminate()
                process.join(10)
                if process.is_alive():
                    process.kill()
                    process.join()
    except (OSError, ValueError, RuntimeError, KeyError, psycopg.Error) as error:
        message = str(error) if type(error) is RuntimeError else "Check the local PostgreSQL login and app setup."
        print(f"Load check failed. {message}", flush=True)
        return 1
    print(json.dumps(result, indent=2))
    if args.mode == "steady":
        return int(any(item["errors"] for scenario in result.values() for item in scenario.values()))
    return int(any(item["failures"] for item in result["latencies"].values()))


if __name__ == "__main__":
    raise SystemExit(main())
