"""Check the deployed Second Shift service and optionally exercise a temporary agent."""

import argparse
import http.client
import json
import re
import secrets
import subprocess
import sys
import uuid
from urllib.parse import parse_qs, urlsplit

SCREEN = "/api/v1/external/screen"
ADMIN_AGENTS = "/api/v1/external-agents"
MAX_RESPONSE = 1024 * 1024
TIMEOUT = 10


def parse_origin(value):
    try:
        url = urlsplit(value)
        if (url.scheme == "https" and url.hostname and not url.username and "@" not in url.netloc
                and re.fullmatch(r"[a-z0-9.-]+", url.hostname) and url.port in (None, 443)
                and url.path in ("", "/") and not any(char in "?#" or char.isspace() for char in value)):
            return f"https://{url.hostname}"
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("Supply a public HTTPS origin such as https://secondshift.example.com.")


def entra_redirect(location, origin, expected_tenant):
    # https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
    try:
        url = urlsplit(location)
        path = url.path.split("/")
        if url.scheme != "https" or url.netloc != "login.microsoftonline.com" or path[2:] != ["oauth2", "v2.0", "authorize"]:
            return False
        tenant = str(uuid.UUID(path[1]))
    except (ValueError, IndexError):
        return False
    return (
        (expected_tenant is None or tenant == str(expected_tenant))
        and parse_qs(url.query).get("redirect_uri") == [f"{origin}/auth/callback"]
    )


def request_json(origin, method, path, body=None, auth=None):
    headers = {"Accept": "application/json", **(auth or {})}
    encoded = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        encoded = json.dumps(body).encode()
    connection = http.client.HTTPSConnection(urlsplit(origin).hostname, timeout=TIMEOUT)
    try:
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        payload = response.read(MAX_RESPONSE + 1)
        if len(payload) > MAX_RESPONSE:
            return 0, {}, {}
        try:
            data = json.loads(payload) if payload else {}
        except (ValueError, UnicodeError):
            data = {}
        return response.status, {"location": response.getheader("Location", "")}, data if isinstance(data, dict) else {}
    except (OSError, ValueError, http.client.HTTPException):
        return 0, {}, {}
    finally:
        connection.close()


def rejects_before_body(origin):
    """Submit one normal Expect handshake without supplying its two-byte body."""
    host = urlsplit(origin).hostname
    connection = http.client.HTTPSConnection(host, timeout=TIMEOUT)
    try:
        connection.send(
            f"POST {SCREEN} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n"
            "Content-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n".encode("ascii")
        )
        # Reading the first status avoids http.client's automatic consumption
        # of a 100 response. Only a final 401 before any continue is a pass.
        with connection.sock.makefile("rb") as stream:
            line = stream.readline(512)
        return re.match(rb"HTTP/1\.[01] 401(?:\s|$)", line) is not None
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def vault_admin(vault, name, origin, use_session):
    # https://learn.microsoft.com/en-us/cli/azure/keyvault/secret?view=azure-cli-latest#az-keyvault-secret-show
    try:
        result = subprocess.run(
            ["az", "keyvault", "secret", "show", "--vault-name", vault, "--name", name, "--query", "value",
             "--output", "tsv", "--only-show-errors"],
            stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30,
        )
        text = result.stdout.decode("ascii").strip()
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None
    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,16384}", text):
        return None
    if use_session:
        return {"Cookie": f"ss_session={text}", "Origin": origin}
    return {"Authorization": f"Bearer {text}"}


def report(message, passed):
    print(f"{'Pass' if passed else 'Fail'} — {message}", flush=True)
    return bool(passed)


def check_agent(request, admin):
    agent_id = f"deployment-check-{uuid.uuid4().hex}"
    path = f"{ADMIN_AGENTS}/{agent_id}"
    screen_body = {"tool": "deployment_check", "detail": "Check the deployment without running an action.", "risk": "low"}
    enrolled = False
    passed = False
    try:
        status, _, _ = request("POST", ADMIN_AGENTS, {
            "id": agent_id, "platform": "custom", "allow_tools": ["deployment_check:low"], "max_risk": "low",
            "max_dollars": 0.01, "expires_days": 1,
        }, admin)
        enrolled = report("temporary agent enrolled", status == 201)
        if enrolled:
            status, _, data = request("POST", f"{path}/credentials", {"surface": "rest"}, admin)
            key = data.get("token")
            minted = report(
                "temporary agent key minted" if status != 409 else "agent key requires approval under this deployment's rules",
                status == 200 and isinstance(key, str) and re.fullmatch(r"ss-rest-[A-Za-z0-9_-]+", key),
            )
            if minted:
                status, _, data = request("POST", SCREEN, screen_body, {"Authorization": f"Bearer {key}"})
                good = report("agent key screened a harmless action", status == 200 and data.get("allowed") is True)
                wrong = "ss-rest-" + secrets.token_urlsafe(32)
                status, _, _ = request("POST", SCREEN, screen_body, {"Authorization": f"Bearer {wrong}"})
                bad = report("wrong agent key was refused", status == 401)
                passed = good and bad
    finally:
        status, _, _ = request("DELETE", path, auth=admin)
        cleaned = status == 204 or (not enrolled and status == 404)
        if not report("temporary agent removed" if cleaned else f"could not remove temporary agent {agent_id}", cleaned):
            passed = False
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_origin", type=parse_origin)
    parser.add_argument("--tenant-id", type=uuid.UUID, help="Verify that sign-in points at this specific Entra tenant.")
    parser.add_argument("--teams-required", action="store_true", help="Require the Teams bot to be enabled.")
    parser.add_argument("--vault", help="Use a named administrator credential from this vault.")
    parser.add_argument("--admin-secret", help="Key Vault secret name, required with --vault.")
    parser.add_argument("--admin-session", action="store_true", help="The vault secret is a signed-in administrator's session cookie value.")
    args = parser.parse_args()
    if bool(args.vault) != bool(args.admin_secret) or (args.admin_session and not args.vault):
        parser.error("Provide --vault and --admin-secret together for the optional agent check.")
    origin = args.public_origin

    def request(method, path, body=None, auth=None):
        return request_json(origin, method, path, body, auth)

    results = []
    for path, message in [("/livez", "service is running"), ("/readyz", "service is ready")]:
        status, _, data = request("GET", path)
        results.append(report(message, status == 200 and data.get("status") == "ok"))
    status, headers, _ = request("GET", "/auth/login")
    results.append(report("sign-in redirects to the tenant's Entra login",
                          status == 302 and entra_redirect(headers["location"], origin, args.tenant_id)))
    status, _, data = request("GET", "/api/v1/external/openapi.json")
    paths = data.get("paths")
    results.append(report("public agent schema is available",
                          status == 200 and str(data.get("openapi", "")).startswith("3.")
                          and isinstance(paths, dict) and SCREEN in paths))
    results.append(report("agent gateway refused the request before accepting the body", rejects_before_body(origin)))
    status, _, data = request("POST", "/webhook/teams", {})
    if status == 404 and data.get("detail") == "Approvals in Teams are turned off." and not args.teams_required:
        results.append(report("Teams webhook is off in this deployment", True))
    else:
        results.append(report("Teams webhook refused an unsigned request", status in (401, 403)))
    if args.vault:
        admin = vault_admin(args.vault, args.admin_secret, origin, args.admin_session)
        results.append(report("administrator credential read from Key Vault", admin is not None))
        if admin:
            results.append(check_agent(request, admin))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
