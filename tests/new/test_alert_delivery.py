"""Alert delivery to Microsoft Teams and by email, proven against local
stand-ins: an HTTP server that receives the Teams request, and an SMTP server
on a socket that carries a real ``smtplib`` conversation. Nothing here reaches
a real Teams tenant or a real mail server."""
from __future__ import annotations

import base64
import contextlib
import datetime
import email
import email.policy
import hashlib
import ipaddress
import json
import logging
import os
import socket
import ssl
import threading
import time
from email.header import decode_header, make_header
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

#: The parts of a webhook address that let whoever holds them post.
WORKFLOW = "7f3c9e51d2"
SIGNATURE = "Zx9SECRETsigQ7vW"  # pragma: allowlist secret
WEBHOOK_PATH = f"/workflows/{WORKFLOW}/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sig={SIGNATURE}"
SMTP_PASSWORD = "stand-in-Pa55word"  # pragma: allowlist secret
DRIFT = "helpdesk has moved away from its approved baseline. It used a tool it had not used before: export_records."


# ------------------------------------------------------------------ stand-ins

class TeamsStandIn:
    """A local HTTP server that keeps every request it receives and answers
    each POST with ``status``."""

    def __init__(self, tls: ssl.SSLContext | None = None) -> None:
        self.requests: list[dict] = []
        self.status = 202
        self.location = ""
        self.delay = 0.0
        self._release = threading.Event()
        stand_in = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                stand_in.requests.append({"path": self.path, "headers": dict(self.headers.items()), "body": body})
                if stand_in.delay:
                    stand_in._release.wait(stand_in.delay)
                self.send_response(stand_in.status)
                if stand_in.location:
                    self.send_header("Location", stand_in.location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        if tls:
            self._server.socket = tls.wrap_socket(self._server.socket, server_side=True)
        self.port = self._server.server_port
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{self.port}{WEBHOOK_PATH}"
        threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()

    def card(self, index: int = -1) -> dict:
        return json.loads(self.requests[index]["body"])["attachments"][0]["content"]

    def close(self) -> None:
        self._release.set()
        self._server.shutdown()
        self._server.server_close()


class SmtpStandIn:
    """A minimal SMTP server on a local socket: enough of the protocol for a
    real ``smtplib`` conversation (EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT,
    DATA, QUIT). Each accepted message is kept with its envelope."""

    def __init__(self, *, tls: ssl.SSLContext | None = None, credentials: tuple[str, str] | None = None,
                 tls_from_the_start: bool = False) -> None:
        self.messages: list[dict] = []
        self.sessions: list[list[str]] = []
        self.refuse: set[str] = set()
        self.silent = False
        self.tls = tls
        self.tls_from_the_start = tls_from_the_start
        self.credentials = credentials
        self._closing = threading.Event()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                connection, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection: socket.socket) -> None:
        commands: list[str] = []
        self.sessions.append(commands)
        if self.silent:  # accept the connection and never speak
            self._closing.wait(30)
            connection.close()
        else:
            _SmtpConversation(self, connection, commands).run()

    def close(self) -> None:
        self._closing.set()
        self._listener.close()


class _SmtpConversation:
    """One client's conversation with the SMTP stand-in."""

    def __init__(self, server: SmtpStandIn, connection: socket.socket, commands: list[str]) -> None:
        self.server, self.connection, self.commands = server, connection, commands
        self.encrypted = self.signed_in = False
        self.envelope: dict = {"from": "", "to": []}
        self.stream = connection.makefile("rwb")

    def run(self) -> None:
        try:
            if self.server.tls_from_the_start:
                self._encrypt()
            self._say("220 stand-in ESMTP")
            while raw := self.stream.readline():
                text = raw.decode("utf-8", "replace").rstrip("\r\n")
                self.commands.append(text)
                verb, _, rest = text.partition(" ")
                if not self._answer(verb.upper(), rest):
                    break
        except (OSError, ssl.SSLError):
            pass  # the client broke the conversation off
        finally:
            self.connection.close()

    def _encrypt(self) -> None:
        self.connection = self.server.tls.wrap_socket(self.connection, server_side=True)
        self.stream = self.connection.makefile("rwb")
        self.encrypted = True

    def _say(self, *lines: str) -> None:
        for position, line in enumerate(lines):
            separator = " " if position == len(lines) - 1 else "-"
            self.stream.write(f"{line[:3]}{separator}{line[4:]}\r\n".encode("ascii"))
        self.stream.flush()

    def _answer(self, verb: str, rest: str) -> bool:
        """Answer one command. False ends the conversation."""
        server = self.server
        if verb in ("EHLO", "HELO"):
            offers = ["250 stand-in", "250 8BITMIME"]
            if server.tls and not self.encrypted:
                offers.append("250 STARTTLS")
            if server.credentials and (self.encrypted or not server.tls):
                offers.append("250 AUTH PLAIN")
            self._say(*offers)
        elif verb == "STARTTLS" and server.tls and not self.encrypted:
            self._say("220 go ahead")
            self._encrypt()
        elif verb == "AUTH":
            user, password = server.credentials or ("", "")
            expected = base64.b64encode(f"\0{user}\0{password}".encode()).decode()
            self.signed_in = bool(server.credentials) and rest == f"PLAIN {expected}"
            self._say("235 accepted" if self.signed_in else "535 credentials refused")
        elif verb == "MAIL":
            if server.credentials and not self.signed_in:
                self._say("530 sign in first")
            else:
                self.envelope = {"from": _angle(rest), "to": []}
                self._say("250 ok")
        elif verb == "RCPT":
            if _angle(rest) in server.refuse:
                self._say("550 no such user")
            else:
                self.envelope["to"].append(_angle(rest))
                self._say("250 ok")
        elif verb == "DATA":
            self._take_message()
        elif verb == "QUIT":
            self._say("221 bye")
            return False
        else:
            self._say("250 ok")
        return True

    def _take_message(self) -> None:
        self._say("354 end with a dot")
        rows = []
        while (row := self.stream.readline()) not in (b".\r\n", b""):
            rows.append(row[1:] if row.startswith(b"..") else row)
        data = b"".join(rows)
        self.server.messages.append({
            **self.envelope, "raw": data, "encrypted": self.encrypted, "signed_in": self.signed_in,
            "message": email.message_from_bytes(data, policy=email.policy.default)})
        self._say("250 queued")


@contextlib.contextmanager
def _nothing_listening():
    """A port on this machine that refuses connections for as long as the
    block lasts: it is bound, so nothing else can take it, and never listens."""
    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        yield held.getsockname()[1]


def _angle(text: str) -> str:
    """The address in ``FROM:<a@b>`` / ``TO:<a@b>``."""
    return text[text.index("<") + 1:text.index(">")]


def _self_signed(tmp_path, name: str):
    """A self-signed certificate for 127.0.0.1 and its key, as two files."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_file, key_file


def _tls_stand_in(tmp_path, monkeypatch, *, trusted: bool = True) -> ssl.SSLContext:
    """A server-side TLS context for a stand-in. The client verifies the
    server against ``SSL_CERT_FILE``: the stand-in's own certificate when
    ``trusted``, and only an unrelated one otherwise."""
    cert_file, key_file = _self_signed(tmp_path, "stand-in")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    if not trusted:
        cert_file, _ = _self_signed(tmp_path, "someone-else")
        monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path / "no-such-directory"))
    monkeypatch.setenv("SSL_CERT_FILE", str(cert_file))
    return context


# ------------------------------------------------------------------- fixtures

@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch, request):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_ALERTS", "TEAMS_NOTIFY_WEBHOOK_URL", "MAVERICK_SMTP_PASSWORD", "EMAIL_USER",
                 "EMAIL_APP_PASSWORD", "EMAIL_PROVIDER", "EMAIL_FROM", "MAVERICK_EMAIL_DISABLE",
                 "MAVERICK_FETCH_ALLOW_PRIVATE", "MAVERICK_NOTIFY_BATCH_WINDOW", "MAVERICK_NOTIFY_BATCH_MAX"):
        monkeypatch.delenv(name, raising=False)
    # The same switch the core tests use: MAVERICK_TEST_SECURE_DEFAULT=1 runs
    # these under the production security posture, with a throwaway audit key.
    secure = os.environ.get("MAVERICK_TEST_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", secure)
    if secure.strip().lower() in {"1", "true", "yes", "on"}:
        seed = f"alert-delivery-test:{request.node.nodeid}".encode()
        monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(seed).hexdigest())
    from maverick import config, notification_batcher, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(notification_batcher, "_shared", None)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _configure(tmp_path, body: str) -> None:
    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    from maverick import config

    config.reset_config_cache()


@pytest.fixture
def teams(monkeypatch):
    """A Teams stand-in on this machine. The outbound guard refuses addresses
    inside the network, so the documented override is switched on for it."""
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    stand_in = TeamsStandIn()
    yield stand_in
    stand_in.close()


@pytest.fixture
def smtp():
    stand_in = SmtpStandIn()
    yield stand_in
    stand_in.close()


@pytest.fixture
def alerts_on(monkeypatch):
    monkeypatch.setenv("MAVERICK_ALERTS", "1")


def _email_settings(port: int, *, to: str = '"ops@example.test"', extra: str = "") -> str:
    return (f'[notifications.email]\nhost = "127.0.0.1"\nport = {port}\ntls = "none"\n'
            f'from_address = "Second Shift <alerts@example.test>"\nto = {to}\n{extra}')


def _both(tmp_path, teams, smtp) -> None:
    _configure(tmp_path, '[alerts]\nbackends = ["teams", "email"]\n\n'
                         f'[notifications]\nteams_webhook = "{teams.url}"\n\n' + _email_settings(smtp.port))


def _receipts() -> list[dict]:
    from maverick.notification_receipts import DeliveryReceipts

    return DeliveryReceipts().recent()


def _assert_secret_free(text: str, teams: TeamsStandIn | None = None) -> None:
    assert SIGNATURE not in text and WORKFLOW not in text
    assert SMTP_PASSWORD not in text
    if teams is not None:
        assert teams.url not in text and f":{teams.port}/" not in text


# ------------------------------------------------- the Teams message, in units

def test_a_teams_address_is_judged_without_ever_being_quoted():
    from maverick.notifications import _teams_address_problem as problem

    assert problem("") == "No Teams webhook address is set."
    assert problem("https://prod-07.westus.logic.azure.com:443" + WEBHOOK_PATH) == ""
    assert problem("https://example.environment.api.powerplatform.com" + WEBHOOK_PATH) == ""
    # the address is the credential, so it only travels encrypted ...
    assert problem("http://prod-07.westus.logic.azure.com" + WEBHOOK_PATH) == "The Teams webhook address must start with https://."
    # ... except to this machine itself, which crosses no network
    assert problem("http://127.0.0.1:8123" + WEBHOOK_PATH) == ""
    assert problem("http://localhost:8123" + WEBHOOK_PATH) == ""
    for wrong in ("teams", "ftp://example.test/hook", "https://", "https://[half" + WEBHOOK_PATH, "mailto:ops@example.test",
                  "https://hooks.example.test:port" + WEBHOOK_PATH):
        assert problem(wrong) == "The Teams webhook address is not a web address."
    for address in ("http://prod-07.westus.logic.azure.com" + WEBHOOK_PATH, "https://[half" + WEBHOOK_PATH):
        _assert_secret_free(problem(address))


def test_a_port_that_only_repeats_the_default_is_left_out_of_the_request():
    from maverick.notifications import _teams_target

    # Microsoft's example addresses look like https://<name>.logic.azure.com:443/...
    assert _teams_target("https://prod-07.westus.logic.azure.com:443" + WEBHOOK_PATH) == (
        "https://prod-07.westus.logic.azure.com" + WEBHOOK_PATH)
    assert _teams_target("http://localhost:80" + WEBHOOK_PATH) == "http://localhost" + WEBHOOK_PATH
    assert _teams_target("https://[::1]:443/hook") == "https://[::1]/hook"
    for kept in ("https://prod-07.westus.logic.azure.com" + WEBHOOK_PATH, "https://hooks.example.test:8443" + WEBHOOK_PATH,
                 "http://127.0.0.1:443" + WEBHOOK_PATH):
        assert _teams_target(kept) == kept  # nothing else about the address changes


def test_the_teams_request_is_the_documented_message_holding_one_adaptive_card():
    from maverick.notifications import _teams_message

    assert json.loads(_teams_message("Second Shift ALERT: agent_drift.detected", DRIFT)) == {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": None,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.2",
                "body": [
                    {"type": "TextBlock", "text": "Second Shift ALERT: agent_drift.detected",
                     "weight": "Bolder", "size": "Medium", "wrap": True},
                    {"type": "TextBlock", "text": DRIFT, "wrap": True},
                ],
            },
        }],
    }


def test_card_text_cannot_hide_a_link_and_keeps_its_line_breaks_and_letters():
    from maverick.notifications import _teams_message

    body = "Zürich desk: [Approve now](https://evil.example/x)\r\nsecond line\n\n\nthird \ud800 line"
    card = json.loads(_teams_message("José's agent [x](y)", body))["attachments"][0]["content"]
    heading, text = (block["text"] for block in card["body"])
    assert heading == "José's agent (x)(y)"
    # Markdown needs square brackets for a link with a hidden target; a line break needs a blank line.
    assert text == "Zürich desk: (Approve now)(https://evil.example/x)\n\nsecond line\n\nthird ? line"
    assert "Zürich".encode() in _teams_message("t", body)  # sent as UTF-8, not as escapes
    assert len(json.loads(_teams_message("only a title", ""))["attachments"][0]["content"]["body"]) == 1


@pytest.mark.parametrize("body", ["x" * 200_000, "é[" * 60_000, "line one\n" * 20_000, '"\\' * 50_000])
def test_a_long_message_is_cut_to_stay_inside_the_documented_size_limit(body):
    from maverick.notifications import _TEAMS_MAX_BYTES, _teams_message

    request = _teams_message("T" * 5_000, body)
    assert _TEAMS_MAX_BYTES < 28_000 and len(request) <= _TEAMS_MAX_BYTES  # Microsoft documents 28 KB
    assert len(request) > _TEAMS_MAX_BYTES - 64  # and it is cut no shorter than it has to be
    heading, text = (block["text"] for block in json.loads(request)["attachments"][0]["content"]["body"])
    assert heading == "T" * 200
    assert text.endswith("(This message was shortened.)")


def test_backend_names_are_tidied_and_anything_that_is_not_a_name_is_dropped():
    from maverick.notifications import _requested

    assert _requested({}, None) == []  # nothing configured: the default is none
    assert _requested({"backend": "Teams"}, None) == ["teams"]
    assert _requested({"backend": "teams"}, ["  EMAIL  ", "None", "", "teams"]) == ["email", "teams"]
    assert _requested({}, "teams") == ["teams"]  # one name, not its letters
    assert _requested({"backend": ["teams"]}, None) == []
    # an address pasted where a name belongs goes no further
    assert _requested({}, ["https://example.test/hook?sig=" + SIGNATURE, "x" * 33, "tea ms", 7, "slack"]) == ["slack"]


# -------------------------------------------- Teams, through the local server

def test_an_alert_is_posted_to_teams_as_one_card(tmp_path, teams, alerts_on):
    from maverick import ops_alert

    _configure(tmp_path, f'[alerts]\nbackends = ["teams"]\n\n[notifications]\nteams_webhook = "{teams.url}"\n')
    assert ops_alert.alert("agent_drift.detected", DRIFT, severity="high") is True
    assert len(teams.requests) == 1
    request = teams.requests[0]
    assert request["path"] == WEBHOOK_PATH  # the whole address, signature included, reached the server
    assert request["headers"]["Content-Type"] == "application/json"
    assert request["headers"]["Host"] == f"127.0.0.1:{teams.port}"
    assert json.loads(request["body"]) == {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": None,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.2",
                "body": [
                    {"type": "TextBlock", "text": "Second Shift ALERT: agent_drift.detected",
                     "weight": "Bolder", "size": "Medium", "wrap": True},
                    {"type": "TextBlock", "text": DRIFT, "wrap": True},
                ],
            },
        }],
    }
    assert [(row["backend"], row["state"]) for row in _receipts()] == [("teams", "delivered")]


def test_teams_over_https_is_sent_only_to_a_server_whose_certificate_checks_out(tmp_path, alerts_on, monkeypatch):
    from maverick import ops_alert

    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    teams = TeamsStandIn(tls=_tls_stand_in(tmp_path, monkeypatch))
    try:
        assert teams.url.startswith("https://")
        _configure(tmp_path, f'[alerts]\nbackends = ["teams"]\n\n[notifications]\nteams_webhook = "{teams.url}"\n')
        assert ops_alert.alert("agent_drift.detected", DRIFT) is True
        assert teams.requests[0]["path"] == WEBHOOK_PATH and teams.card()["body"][1]["text"] == DRIFT
        # the same server, now with nothing vouching for its certificate: the request is never made
        _tls_stand_in(tmp_path, monkeypatch, trusted=False)
        assert ops_alert.alert("agent_drift.detected", DRIFT) is False
        assert ops_alert.send_test() == {"teams": "The notification service could not be reached. Nothing was sent."}
        assert len(teams.requests) == 1
        # a server that cannot even read its list of trusted authorities sends nothing either, and says so
        (tmp_path / "broken.pem").write_text("")
        monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "broken.pem"))
        assert ops_alert.send_test() == {
            "teams": "The request to Teams could not be prepared on this server, so nothing was sent."}
        assert len(teams.requests) == 1
    finally:
        teams.close()


def test_the_teams_address_can_come_from_the_environment_and_a_saved_one_wins(tmp_path, teams, alerts_on, monkeypatch):
    from maverick import ops_alert

    _configure(tmp_path, '[alerts]\nbackends = ["teams"]\n')
    assert ops_alert.alert("e", "no address anywhere") is False
    monkeypatch.setenv("TEAMS_NOTIFY_WEBHOOK_URL", teams.url)  # read when the alert is sent, not at start-up
    assert ops_alert.alert("e", "from the environment") is True
    other = TeamsStandIn()
    try:
        _configure(tmp_path, f'[alerts]\nbackends = ["teams"]\n\n[notifications]\nteams_webhook = "{other.url}"\n')
        assert ops_alert.alert("e", "from the saved setting") is True
        assert len(other.requests) == 1 and len(teams.requests) == 1
    finally:
        other.close()
    # a reference nobody resolved is not an address
    _configure(tmp_path, '[alerts]\nbackends = ["teams"]\n\n[notifications]\nteams_webhook = 7\n')
    monkeypatch.delenv("TEAMS_NOTIFY_WEBHOOK_URL")
    assert ops_alert.alert("e", "a number is not an address") is False


def test_the_outbound_guard_refuses_an_address_inside_the_network(tmp_path, teams, alerts_on, monkeypatch):
    from maverick import ops_alert

    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE")  # the fixture's override, taken away again
    _configure(tmp_path, f'[alerts]\nbackends = ["teams"]\n\n[notifications]\nteams_webhook = "{teams.url}"\n')
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False
    assert teams.requests == []
    reason = ops_alert.send_test()["teams"]
    assert reason == "The Teams webhook address could not be found on the public internet, so nothing was sent."
    assert teams.requests == []


def test_the_outbound_policy_can_block_teams_and_only_the_host_is_recorded(tmp_path, teams, alerts_on, monkeypatch):
    import maverick.enterprise as enterprise
    from maverick import ops_alert
    from maverick.audit import writer

    recorded = []
    monkeypatch.setattr(enterprise, "egress_permitted", lambda url: False)
    monkeypatch.setattr(writer, "audit_event", lambda kind, **fields: recorded.append((str(kind), fields)))
    _configure(tmp_path, f'[alerts]\nbackends = ["teams"]\n\n[notifications]\nteams_webhook = "{teams.url}"\n')
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False
    assert ops_alert.send_test() == {
        "teams": "The outbound network rules do not allow the Teams webhook address, so nothing was sent."}
    assert teams.requests == []
    hosts = [fields["host"] for _kind, fields in recorded if "host" in fields]
    assert hosts and set(hosts) == {"127.0.0.1"}  # the host, so an administrator knows what to allow
    _assert_secret_free(repr(recorded), teams)


@pytest.mark.parametrize(("status", "accepted", "state"), [
    (200, True, "delivered"), (202, True, "delivered"), (400, False, "failed"), (401, False, "failed"),
    (404, False, "failed"), (429, False, "failed"), (500, False, "unknown"), (503, False, "unknown")])
def test_only_a_success_answer_from_teams_counts_as_accepted(tmp_path, teams, alerts_on, status, accepted, state):
    from maverick import ops_alert

    teams.status = status
    _configure(tmp_path, f'[alerts]\nbackends = ["teams"]\n\n[notifications]\nteams_webhook = "{teams.url}"\n')
    assert ops_alert.alert("agent_drift.detected", DRIFT) is accepted
    assert len(teams.requests) == 1  # one attempt, never a retry
    assert [row["state"] for row in _receipts()] == [state]


def test_a_redirect_from_teams_is_not_followed(tmp_path, teams, alerts_on):
    from maverick import ops_alert

    elsewhere = TeamsStandIn()
    try:
        teams.status, teams.location = 307, elsewhere.url
        _configure(tmp_path, f'[alerts]\nbackends = ["teams"]\n\n[notifications]\nteams_webhook = "{teams.url}"\n')
        assert ops_alert.alert("agent_drift.detected", DRIFT) is False
        assert len(teams.requests) == 1 and elsewhere.requests == []
    finally:
        elsewhere.close()


def test_a_slow_teams_answer_ends_at_the_time_limit_without_raising(tmp_path, teams, alerts_on, monkeypatch):
    from maverick import notifications, ops_alert

    monkeypatch.setattr(notifications, "_TEAMS_TIMEOUT", 0.3)
    teams.delay = 20
    _configure(tmp_path, f'[alerts]\nbackends = ["teams"]\n\n[notifications]\nteams_webhook = "{teams.url}"\n')
    started = time.monotonic()
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False
    assert time.monotonic() - started < 5
    # the request was sent and nobody answered: it may have been posted, so it is not called a failure
    assert [row["state"] for row in _receipts()] == ["unknown"]
    assert ops_alert.send_test() == {"teams": "Delivery could not be confirmed. Check the destination before sending again."}


def test_teams_that_cannot_be_reached_is_a_plain_failure(tmp_path, alerts_on, monkeypatch):
    from maverick import ops_alert

    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    with _nothing_listening() as port:
        _configure(tmp_path, '[alerts]\nbackends = ["teams"]\n\n'
                             f'[notifications]\nteams_webhook = "http://127.0.0.1:{port}{WEBHOOK_PATH}"\n')
        assert ops_alert.alert("agent_drift.detected", DRIFT) is False
        assert ops_alert.send_test() == {"teams": "The notification service could not be reached. Nothing was sent."}
        assert [(row["state"], row["safe_to_retry"]) for row in _receipts() if row["kind"] == "event"] == [("failed", True)]


def test_an_address_that_is_not_https_is_refused_before_anything_is_sent(tmp_path, alerts_on, monkeypatch):
    from maverick import notifications, ops_alert

    monkeypatch.setattr(notifications, "_send_teams", lambda *a, **k: pytest.fail("must not send"))
    _configure(tmp_path, '[alerts]\nbackends = ["teams"]\n\n'
                         f'[notifications]\nteams_webhook = "http://hooks.example.test{WEBHOOK_PATH}"\n')
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False
    assert ops_alert.send_test() == {"teams": "The Teams webhook address must start with https://."}


# ----------------------------------------- email, through the SMTP stand-in

def test_an_alert_is_delivered_by_email_in_a_real_smtp_conversation(tmp_path, smtp, alerts_on):
    from maverick import ops_alert

    _configure(tmp_path, '[alerts]\nbackends = ["email"]\n\n' + _email_settings(smtp.port))
    assert ops_alert.alert("agent_drift.detected", DRIFT, severity="high") is True
    assert len(smtp.messages) == 1
    received = smtp.messages[0]
    assert (received["from"], received["to"]) == ("alerts@example.test", ["ops@example.test"])
    message = received["message"]
    assert message["From"] == "Second Shift <alerts@example.test>"
    assert message["To"] == "ops@example.test"
    assert message["Subject"] == "Second Shift ALERT: agent_drift.detected"
    assert message.get_content_type() == "text/plain" and not message.is_multipart()
    assert message.get_content().strip() == DRIFT
    assert message["Message-ID"].endswith("@example.test>")  # the sender's own domain
    assert message["Date"]
    verbs = [command.split(" ")[0].upper() for command in smtp.sessions[0]]
    assert verbs == ["EHLO", "MAIL", "RCPT", "DATA", "QUIT"]
    assert [(row["backend"], row["state"]) for row in _receipts()] == [("email", "delivered")]


def test_email_signs_in_over_an_encrypted_connection_by_default(tmp_path, alerts_on, monkeypatch):
    from maverick import ops_alert

    monkeypatch.setenv("MAVERICK_SMTP_PASSWORD", SMTP_PASSWORD)
    smtp = SmtpStandIn(tls=_tls_stand_in(tmp_path, monkeypatch), credentials=("alerts", SMTP_PASSWORD))
    try:
        # no tls setting: STARTTLS is the default
        _configure(tmp_path, '[alerts]\nbackends = ["email"]\n\n[notifications.email]\n'
                             f'host = "127.0.0.1"\nport = {smtp.port}\nuser = "alerts"\n'
                             'from_address = "alerts@example.test"\nto = "ops@example.test"\n')
        assert ops_alert.alert("killswitch_tripped", "Everything was stopped by hand.", severity="critical") is True
        received = smtp.messages[0]
        assert received["encrypted"] is True and received["signed_in"] is True
        assert received["message"]["Subject"] == "Second Shift ALERT: killswitch_tripped"
        verbs = [command.split(" ")[0].upper() for command in smtp.sessions[0]]
        assert verbs == ["EHLO", "STARTTLS", "EHLO", "AUTH", "MAIL", "RCPT", "DATA", "QUIT"]
        # a wrong password is refused by the server and said plainly, without the password
        monkeypatch.setenv("MAVERICK_SMTP_PASSWORD", "not-the-password")
        assert ops_alert.send_test() == {"email": "The mail server did not accept the user name and password."}
        assert len(smtp.messages) == 1
    finally:
        smtp.close()


def test_a_server_the_client_cannot_verify_gets_no_message_and_no_password(tmp_path, alerts_on, monkeypatch):
    from maverick import ops_alert

    monkeypatch.setenv("MAVERICK_SMTP_PASSWORD", SMTP_PASSWORD)
    smtp = SmtpStandIn(tls=_tls_stand_in(tmp_path, monkeypatch, trusted=False), credentials=("alerts", SMTP_PASSWORD))
    try:
        _configure(tmp_path, '[alerts]\nbackends = ["email"]\n\n[notifications.email]\n'
                             f'host = "127.0.0.1"\nport = {smtp.port}\nuser = "alerts"\n'
                             'from_address = "alerts@example.test"\nto = "ops@example.test"\n')
        assert ops_alert.alert("agent_drift.detected", DRIFT) is False
        assert ops_alert.send_test() == {"email": "A secure connection to the mail server could not be set up. "
                                                  "Check the tls setting and the server's certificate."}
        assert smtp.messages == []
        assert not any(command.upper().startswith("AUTH") for session in smtp.sessions for command in session)
    finally:
        smtp.close()


def test_email_also_works_when_the_connection_is_encrypted_from_the_start(tmp_path, alerts_on, monkeypatch):
    from maverick import ops_alert

    monkeypatch.setenv("MAVERICK_SMTP_PASSWORD", SMTP_PASSWORD)
    smtp = SmtpStandIn(tls=_tls_stand_in(tmp_path, monkeypatch), credentials=("alerts", SMTP_PASSWORD),
                       tls_from_the_start=True)
    try:
        _configure(tmp_path, '[alerts]\nbackends = ["email"]\n\n[notifications.email]\ntls = "ssl"\n'
                             f'host = "127.0.0.1"\nport = {smtp.port}\nuser = "alerts"\n'
                             'from_address = "alerts@example.test"\nto = "ops@example.test"\n')
        assert ops_alert.alert("agent_drift.detected", DRIFT) is True
        received = smtp.messages[0]
        assert received["encrypted"] is True and received["signed_in"] is True
        assert received["message"].get_content().strip() == DRIFT
        assert [command.split(" ")[0].upper() for command in smtp.sessions[0]] == ["EHLO", "AUTH", "MAIL", "RCPT", "DATA", "QUIT"]
    finally:
        smtp.close()


def test_several_recipients_and_a_title_with_other_alphabets_arrive_intact(tmp_path, smtp, alerts_on):
    from maverick import notifications

    _configure(tmp_path, '[notifications]\nbackend = "email"\n\n'
               + _email_settings(smtp.port, to='["ops@example.test", "security@example.test"]'))
    assert notifications.notify("Zürich: läuft nicht\nzweite Zeile", title="Fällig: José aus Zürich",
                                async_dispatch=False) == 1
    received = smtp.messages[0]
    assert received["to"] == ["ops@example.test", "security@example.test"]
    assert b"Subject: =?utf-8?" in received["raw"]  # encoded for the wire, not sent raw
    assert str(make_header(decode_header(received["message"]["Subject"]))) == "Fällig: José aus Zürich"
    assert received["message"].get_content().splitlines() == ["Zürich: läuft nicht", "zweite Zeile"]


def test_a_refused_recipient_is_a_failure_with_a_plain_reason(tmp_path, smtp, alerts_on):
    from maverick import ops_alert

    smtp.refuse.add("ops@example.test")
    _configure(tmp_path, '[alerts]\nbackends = ["email"]\n\n' + _email_settings(smtp.port))
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False
    assert ops_alert.send_test() == {"email": "The mail server refused the address set to receive alerts."}
    assert smtp.messages == []


def test_a_mail_server_that_never_answers_ends_at_the_time_limit_without_raising(tmp_path, smtp, alerts_on, monkeypatch):
    from maverick import notifications, ops_alert

    monkeypatch.setattr(notifications, "_EMAIL_TIMEOUT", 0.3)
    smtp.silent = True
    _configure(tmp_path, '[alerts]\nbackends = ["email"]\n\n' + _email_settings(smtp.port))
    started = time.monotonic()
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False
    assert time.monotonic() - started < 5
    assert ops_alert.send_test() == {"email": "The mail server could not be reached, or it closed the connection."}


@pytest.mark.parametrize(("settings", "reason"), [
    ("", "No email address is set to receive alerts."),
    ('[notifications.email]\nhost = "127.0.0.1"\nfrom_address = "alerts@example.test"\n',
     "No email address is set to receive alerts."),
    ('[notifications.email]\nhost = "127.0.0.1"\nfrom_address = "alerts@example.test"\nto = "the ops team"\n',
     "The email address set to receive alerts is not valid."),
    ('[notifications.email]\nto = "ops@example.test"\n', "No mail server is set up to send alerts."),
    ('[notifications.email]\nhost = "127.0.0.1"\nto = "ops@example.test"\n',
     "The alert mail settings are incomplete: both host and from_address are needed."),
    # settings typed as the wrong kind of value are "not set", never a crash
    ('[notifications.email]\nhost = 25\nfrom_address = ["a"]\nuser = true\nto = 7\nport = "x"\n',
     "No email address is set to receive alerts."),
])
def test_email_that_is_not_set_up_says_what_is_missing(tmp_path, alerts_on, settings, reason):
    from maverick import notifications, ops_alert

    _configure(tmp_path, '[alerts]\nbackends = ["email"]\n\n' + settings)
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False
    assert ops_alert.send_test() == {"email": reason}
    status = ops_alert.delivery_status()["channels"][0]
    assert (status["ready"], status["problem"]) == (False, reason)
    # the documented promise of the email sender itself
    assert notifications.send_email("ops@example.test", "s", "b") is False


def test_the_platform_mail_account_carries_an_alert_when_no_alert_server_is_set(tmp_path, alerts_on, monkeypatch):
    from maverick import mailer, ops_alert

    carried = []
    monkeypatch.setenv("EMAIL_USER", "platform@example.test")
    monkeypatch.setenv("EMAIL_APP_PASSWORD", SMTP_PASSWORD)
    monkeypatch.setattr(mailer, "_smtp_transport",
                        lambda host, port, user, password, message, **kw: carried.append(message))
    _configure(tmp_path, '[alerts]\nbackends = ["email"]\n\n[notifications.email]\nto = "ops@example.test"\n')
    assert ops_alert.delivery_status()["channels"] == [
        {"channel": "email", "ready": True, "problem": "", "recipient": "ops@example.test"}]
    assert ops_alert.alert("agent_drift.detected", DRIFT) is True
    assert carried[0]["To"] == "ops@example.test"
    assert carried[0]["Subject"] == "Second Shift ALERT: agent_drift.detected"
    assert carried[0].get_content().strip() == DRIFT


# -------------------------------------------------------- several channels

def test_an_alert_goes_to_every_channel(tmp_path, teams, smtp, alerts_on):
    from maverick import ops_alert

    _both(tmp_path, teams, smtp)
    assert ops_alert.alert("agent_drift.detected", DRIFT) is True
    assert teams.card()["body"][1]["text"] == DRIFT
    assert smtp.messages[0]["message"].get_content().strip() == DRIFT
    assert sorted((row["backend"], row["state"]) for row in _receipts()) == [("email", "delivered"), ("teams", "delivered")]


def test_one_channel_failing_does_not_stop_the_other(tmp_path, teams, smtp, alerts_on):
    from maverick import ops_alert

    _both(tmp_path, teams, smtp)
    teams.status = 500
    assert ops_alert.alert("agent_drift.detected", DRIFT) is True  # email accepted it
    assert len(teams.requests) == 1 and len(smtp.messages) == 1
    teams.status, smtp.refuse = 202, {"ops@example.test"}
    assert ops_alert.alert("agent_drift.detected", DRIFT) is True  # Teams accepted it
    assert len(teams.requests) == 2 and len(smtp.messages) == 1
    teams.status = 404
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False  # nobody accepted it
    assert ops_alert.send_test() == {
        "teams": "The notification service refused this request. Check the saved destination and credentials.",
        "email": "The mail server refused the address set to receive alerts."}
    teams.status, smtp.refuse = 202, set()
    assert ops_alert.send_test() == {"teams": "sent", "email": "sent"}


def test_a_test_still_reports_each_channel_when_the_delivery_history_is_turned_off(tmp_path, teams, smtp):
    from maverick import ops_alert

    _configure(tmp_path, '[alerts]\nbackends = ["teams", "email"]\n\n'
                         f'[notifications]\ndelivery_receipts = false\nteams_webhook = "{teams.url}"\n\n'
               + _email_settings(smtp.port))
    smtp.refuse.add("ops@example.test")
    assert ops_alert.send_test() == {"teams": "sent", "email": "Not sent. Check this channel's settings."}
    teams.delay, teams.status = 0, 503
    assert ops_alert.send_test()["teams"] == "Delivery could not be confirmed. Check the channel before sending again."
    assert _receipts() == []


def test_a_channel_that_raises_never_reaches_the_caller(tmp_path, teams, smtp, alerts_on, monkeypatch, caplog):
    from maverick import notifications, ops_alert
    from maverick.tools import _ssrf

    _both(tmp_path, teams, smtp)

    def explode(url, **options):
        raise RuntimeError(f"could not open {url}")  # a client error that quotes the whole address

    monkeypatch.setattr(_ssrf, "safe_client", explode)
    caplog.set_level(logging.DEBUG)
    assert ops_alert.alert("agent_drift.detected", DRIFT) is True  # email still went
    assert ops_alert.send_test() == {
        "teams": "The request to Teams could not be prepared on this server, so nothing was sent.", "email": "sent"}
    _assert_secret_free(caplog.text, teams)
    # even the dispatcher itself failing is held back
    monkeypatch.setattr(notifications, "_dispatch", lambda *a, **k: (_ for _ in ()).throw(KeyError(teams.url)))
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False
    assert set(ops_alert.send_test().values()) == {"Delivery could not be confirmed. Check the destination before sending again."}
    monkeypatch.setattr(notifications, "notify", lambda *a, **k: (_ for _ in ()).throw(OSError(teams.url)))
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False
    assert set(ops_alert.send_test().values()) == {
        "The test was not sent: the delivery history or the settings could not be read."}
    _assert_secret_free(caplog.text, teams)


def test_without_an_alert_list_the_single_notification_backend_is_used(tmp_path, teams, smtp, alerts_on):
    from maverick import ops_alert

    _configure(tmp_path, f'[notifications]\nbackend = "Teams"\nteams_webhook = "{teams.url}"\n\n' + _email_settings(smtp.port))
    assert ops_alert.alert("agent_drift.detected", DRIFT) is True
    assert len(teams.requests) == 1 and smtp.messages == []
    # one name written as text is one channel, and a list wins over the single backend
    _configure(tmp_path, f'[alerts]\nbackends = "email"\n\n[notifications]\nbackend = "teams"\n'
                         f'teams_webhook = "{teams.url}"\n\n' + _email_settings(smtp.port))
    assert ops_alert.alert("agent_drift.detected", DRIFT) is True
    assert len(teams.requests) == 1 and len(smtp.messages) == 1
    # "none" in the list means nowhere, even when ordinary notifications have a backend
    _configure(tmp_path, f'[alerts]\nbackends = ["none"]\n\n[notifications]\nbackend = "teams"\n'
                         f'teams_webhook = "{teams.url}"\n')
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False
    assert len(teams.requests) == 1
    # an empty list is the same as no list
    _configure(tmp_path, f'[alerts]\nbackends = []\n\n[notifications]\nbackend = "teams"\nteams_webhook = "{teams.url}"\n')
    assert ops_alert.alert("agent_drift.detected", DRIFT) is True
    assert len(teams.requests) == 2


def test_with_nothing_configured_nothing_is_sent_and_the_answers_say_so(tmp_path, alerts_on, caplog):
    from maverick import notifications, ops_alert

    caplog.set_level(logging.WARNING)
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False
    assert "alerts are on but no alert channel is set up" in caplog.text  # a silent nothing would hide the gap
    assert ops_alert.send_test() == {}
    assert ops_alert.delivery_status() == {"enabled": True, "channels": [], "ignored": [], "available": ["teams", "email"]}
    assert notifications.notify("anything", async_dispatch=False) == 0  # the default backend is none
    assert _receipts() == []


def test_alerts_that_are_off_send_nothing_but_a_test_can_still_prove_delivery(tmp_path, teams, smtp, monkeypatch):
    from maverick import ops_alert

    _both(tmp_path, teams, smtp)
    assert ops_alert.alerts_enabled() is False  # off unless switched on
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False
    assert teams.requests == [] and smtp.messages == []
    monkeypatch.setenv("MAVERICK_ALERTS", "0")
    _configure(tmp_path, (tmp_path / "config.toml").read_text().replace("[alerts]\n", "[alerts]\nenabled = true\n"))
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False  # the environment wins over the file
    assert teams.requests == [] and smtp.messages == []
    assert ops_alert.delivery_status()["enabled"] is False
    # a test is something an administrator asked for by hand, and it says it is a test
    assert ops_alert.send_test() == {"teams": "sent", "email": "sent"}
    assert teams.card()["body"][0]["text"] == "Second Shift test alert"
    assert smtp.messages[0]["message"]["Subject"] == "Second Shift test alert"
    assert "This is a test." in smtp.messages[0]["message"].get_content()
    assert {row["kind"] for row in _receipts()} == {"test"}
    monkeypatch.delenv("MAVERICK_ALERTS")
    assert ops_alert.alert("agent_drift.detected", DRIFT) is True  # switched on in the file


def test_removed_channel_names_are_not_channels(tmp_path, teams, alerts_on, caplog):
    from maverick import notifications, ops_alert

    _configure(tmp_path, '[alerts]\nbackends = ["slack", "ntfy", "Teams", "pushover", "discord", "pager"]\n\n'
                         f'[notifications]\nbackend = "ntfy"\nntfy_topic = "ops"\nteams_webhook = "{teams.url}"\n')
    caplog.set_level(logging.WARNING)
    assert ops_alert.alert("agent_drift.detected", DRIFT) is True  # Teams took it; the rest were ignored
    assert len(teams.requests) == 1
    assert "slack, ntfy, pushover, discord, pager is not an alert channel and is ignored" in caplog.text
    not_a_channel = "Not sent: this is not a supported alert channel. Use teams or email."
    assert ops_alert.send_test() == {"slack": not_a_channel, "ntfy": not_a_channel, "pushover": not_a_channel,
                                     "discord": not_a_channel, "pager": not_a_channel, "teams": "sent"}
    status = ops_alert.delivery_status()
    assert status["ignored"] == ["slack", "ntfy", "pushover", "discord", "pager"]
    assert [channel["channel"] for channel in status["channels"]] == ["teams"]
    assert {row["backend"] for row in _receipts()} == {"teams"}  # an ignored name leaves no record behind
    # asked for directly, a removed name is refused: nothing is sent and the record says why
    outcomes: list[str] = []
    assert notifications.notify("x", backends=["slack", "ntfy", "pushover", "discord"], async_dispatch=False,
                                outcomes=outcomes) == 0
    assert outcomes == ["failed"] * 4
    refused = [row for row in _receipts() if row["backend"] != "teams"]
    assert {row["message"] for row in refused} == {"Not sent: this is not a supported channel. Use teams or email."}
    assert not any(row["safe_to_retry"] for row in refused)
    assert notifications.notify("x", async_dispatch=False) == 0  # the old default backend, still in the file
    for name in ("_send_ntfy", "_send_pushover", "_send_discord", "_send_slack", "_pushover_credentials"):
        assert not hasattr(notifications, name)
    assert notifications.BACKENDS == ("teams", "email")


def test_only_an_alert_list_of_removed_names_sends_nowhere(tmp_path, teams, alerts_on):
    from maverick import ops_alert

    _configure(tmp_path, '[alerts]\nbackends = ["slack"]\n\n'
                         f'[notifications]\nbackend = "teams"\nteams_webhook = "{teams.url}"\n')
    assert ops_alert.alert("agent_drift.detected", DRIFT) is False  # it does not fall back behind the administrator's back
    assert teams.requests == [] and _receipts() == []


# ------------------------------------------------------- the address is a secret

def test_the_webhook_address_never_shows_in_logs_results_records_or_errors(tmp_path, teams, smtp, alerts_on, caplog, monkeypatch):
    import httpx

    from maverick import ops_alert

    caplog.set_level(logging.DEBUG)  # every logger, the HTTP client's own included
    monkeypatch.setenv("MAVERICK_SMTP_PASSWORD", SMTP_PASSWORD)
    _both(tmp_path, teams, smtp)
    shown = []
    for status in (202, 404, 500, 307):
        teams.status, teams.location = status, (teams.url if status == 307 else "")
        ops_alert.alert("agent_drift.detected", DRIFT)
        shown.append(ops_alert.send_test())
    assert len(teams.requests) == 8  # the address did work: every send above got there
    with _nothing_listening() as port:  # the same address where nothing answers at all
        dead = f"http://127.0.0.1:{port}{WEBHOOK_PATH}"
        # ... and pasted into the wrong setting as well: it is not a name, so it goes no further
        _configure(tmp_path, f'[alerts]\nbackends = ["{dead}", "teams"]\n\n[notifications]\nteams_webhook = "{dead}"\n')
        assert ops_alert.alert("agent_drift.detected", DRIFT) is False
        shown += [ops_alert.send_test(), ops_alert.delivery_status()]
    assert shown[-1] == {"enabled": True, "ignored": [], "available": ["teams", "email"], "channels": [
        {"channel": "teams", "ready": True, "problem": "", "webhook_set": True}]}

    _assert_secret_free(caplog.text, teams)
    _assert_secret_free(json.dumps(shown), teams)
    _assert_secret_free(json.dumps(_receipts()), teams)
    for path in tmp_path.rglob("*"):
        if path.is_file() and path.name != "config.toml":
            _assert_secret_free(path.read_text(errors="replace"), teams)
    # The HTTP client does log each request line by default; only a send to a secret address is kept out.
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
        client.get("https://status.example.test/ping")
    assert "https://status.example.test/ping" in caplog.text


# ------------------------------------------ what the removed channels' tests covered

def test_a_backend_name_in_any_case_reaches_its_sender(monkeypatch):
    from maverick import notifications

    fired: list[str] = []
    monkeypatch.setattr(notifications, "_load_config", lambda: {"teams_webhook": "https://hooks.example.test/x"})
    monkeypatch.setattr(notifications, "_send_teams", lambda *a, **k: fired.append("teams") or True)
    assert notifications.notify("agent done", backends=["Teams"], async_dispatch=False) == 1
    assert notifications.notify("agent done", backends=["  TEAMS  "], async_dispatch=False) == 1
    assert fired == ["teams", "teams"]
    assert notifications.notify("x", backends=["None"], async_dispatch=False) == 0  # "None" disables like "none"
    assert fired == ["teams", "teams"]


def test_notify_hands_ordinary_messages_to_the_batcher_and_keeps_their_backends(monkeypatch):
    import maverick.notification_batcher as nb
    from maverick import notifications

    sends: list = []
    batcher = nb.NotificationBatcher(
        nb.BatchPolicy(window_seconds=600.0),
        send=lambda title, body, priority, category, backends=None: sends.append((title, body, backends)) or 1)
    monkeypatch.setattr(nb, "shared", lambda: batcher)
    monkeypatch.setattr(notifications, "_load_config", lambda: {"backend": "email"})
    states: list = []
    assert notifications.notify("hi", backends=["teams"], priority="default", outcomes=states) == 0
    assert sends == [] and states == ["batched"]  # held for later, and says so
    assert notifications.notify("to the default backend") == 0
    assert batcher.flush() == 2  # one digest per set of backends
    assert sends == [("Second Shift", "hi", ["teams"]), ("Second Shift", "to the default backend", None)]


def test_an_alert_is_never_held_back_in_a_batch(tmp_path, teams, alerts_on, monkeypatch):
    import maverick.notification_batcher as nb
    from maverick import ops_alert

    monkeypatch.setattr(nb, "shared", lambda: pytest.fail("an alert must not wait in a batch"))
    _configure(tmp_path, '[alerts]\nbackends = ["teams"]\n\n[notifications]\nbatch_window_seconds = 600\n'
                         f'teams_webhook = "{teams.url}"\n')
    assert ops_alert.alert("budget_cap", "A spending cap was reached.", severity="info") is True
    assert len(teams.requests) == 1


def test_a_queued_notification_is_not_called_delivered_and_its_failure_is_kept(monkeypatch):
    from maverick import notifications

    monkeypatch.setattr(notifications, "_load_config", lambda: {"backend": "teams", "teams_webhook": "https://hooks.example.test/x"})
    jobs = []

    class Executor:
        def submit(self, fn, *args):
            jobs.append((fn, args))

    monkeypatch.setattr(notifications, "_get_executor", lambda: Executor())
    monkeypatch.setattr(notifications, "_send_teams", lambda *args: False)
    assert notifications.notify("PRIVATE", batch=False, delivery_key="event-once") == 1  # queued, not delivered
    assert _receipts()[0]["state"] == "queued"
    fn, args = jobs.pop()
    fn(*args)
    assert _receipts()[0]["state"] == "failed"
    assert notifications.notify("PRIVATE", batch=False, delivery_key="event-once") == 0  # the same event is not sent twice
    from maverick.notification_receipts import DeliveryReceipts

    assert "PRIVATE" not in DeliveryReceipts().path.read_text()


def test_a_notification_still_goes_out_when_the_history_is_full_of_definite_failures(monkeypatch):
    from maverick import notifications
    from maverick.notification_receipts import DeliveryReceipts

    now = time.time()
    monkeypatch.setattr(notifications, "_load_config", lambda: {"backend": "teams", "teams_webhook": "https://hooks.example.test/x"})
    from maverick.file_lock import ensure_private_directory

    receipts = DeliveryReceipts()
    ensure_private_directory(receipts.path.parent)
    receipts._save([{"id": f"row-{index}", "backend": "teams", "kind": "event", "state": "failed", "request_id": None,
                     "updated_at": now, "created_at": now, "attempts": 1, "safe_to_retry": True, "message": "Not sent."}
                    for index in range(1000)])
    monkeypatch.setattr(notifications, "_send_teams", lambda *args: True)
    assert notifications.notify("synthetic", batch=False, async_dispatch=False) == 1
    assert len(DeliveryReceipts()._load()) == 1000


# ------------------------------------------------------------ the two endpoints

@pytest.fixture
def client():
    from starlette.routing import NoMatchFound

    from maverick_dashboard import alerts_api
    from maverick_dashboard.app import app

    before = len(app.router.routes)
    try:
        app.url_path_for("alert_delivery")
    except NoMatchFound:
        app.include_router(alerts_api.router)  # for a tree whose app does not include the router yet
    try:
        with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
            yield c
    finally:
        del app.router.routes[before:]


def _only(allowed):
    def require(request, permission):
        if permission not in allowed:
            from fastapi import HTTPException

            raise HTTPException(status_code=403, detail="insufficient role")
    return require


def test_the_status_endpoint_shows_how_delivery_is_set_up_and_no_secret(client, tmp_path, teams, smtp, alerts_on, monkeypatch):
    monkeypatch.setenv("MAVERICK_SMTP_PASSWORD", SMTP_PASSWORD)
    _configure(tmp_path, '[alerts]\nbackends = ["teams", "email", "slack"]\n\n'
                         f'[notifications]\nteams_webhook = "{teams.url}"\n\n'
               + _email_settings(smtp.port, extra='user = "alerts"\n'))
    answer = client.get("/api/v1/alerts")
    assert answer.status_code == 200, answer.text
    assert answer.json() == {
        "enabled": True,
        "channels": [
            {"channel": "teams", "ready": True, "problem": "", "webhook_set": True},
            {"channel": "email", "ready": True, "problem": "", "recipient": "ops@example.test"},
        ],
        "ignored": ["slack"],
        "available": ["teams", "email"],
    }
    _assert_secret_free(answer.text, teams)
    assert teams.requests == [] and smtp.messages == []  # looking sends nothing


def test_the_status_endpoint_says_what_is_missing(client, tmp_path):
    _configure(tmp_path, '[alerts]\nbackends = ["teams", "email"]\n')
    assert client.get("/api/v1/alerts").json() == {
        "enabled": False,
        "channels": [
            {"channel": "teams", "ready": False, "problem": "No Teams webhook address is set.", "webhook_set": False},
            {"channel": "email", "ready": False, "problem": "No email address is set to receive alerts.", "recipient": ""},
        ],
        "ignored": [],
        "available": ["teams", "email"],
    }


def test_the_test_endpoint_sends_to_every_channel_and_reports_each(client, tmp_path, teams, smtp):
    _both(tmp_path, teams, smtp)
    answer = client.post("/api/v1/alerts/test")
    assert answer.status_code == 200, answer.text
    assert answer.json() == {
        "enabled": False, "sent": True, "results": {"teams": "sent", "email": "sent"},
        "message": "The test reached teams and email. Alerts are turned off, so nothing else is sent until they are turned on."}
    assert teams.card()["body"][0]["text"] == "Second Shift test alert"
    assert smtp.messages[0]["message"]["Subject"] == "Second Shift test alert"

    teams.status = 404
    answer = client.post("/api/v1/alerts/test")
    assert answer.json()["sent"] is True
    assert answer.json()["results"]["teams"] == (
        "The notification service refused this request. Check the saved destination and credentials.")
    assert answer.json()["message"].startswith("The test reached email but not teams.")
    smtp.refuse.add("ops@example.test")
    answer = client.post("/api/v1/alerts/test")
    assert (answer.json()["sent"], answer.json()["message"]) == (False, "The test did not reach any alert channel.")
    _assert_secret_free(answer.text, teams)


def test_the_test_endpoint_with_no_channel_says_how_to_set_one_up(client, alerts_on):
    answer = client.post("/api/v1/alerts/test")
    assert answer.status_code == 200
    assert answer.json() == {
        "enabled": True, "sent": False, "results": {},
        "message": "No alert channel is set up. Name teams or email under [alerts] backends, then add that channel's settings."}


def test_reading_needs_view_and_sending_a_test_needs_admin(client, tmp_path, teams, smtp, monkeypatch):
    from maverick_dashboard import alerts_api

    _both(tmp_path, teams, smtp)
    monkeypatch.setattr(alerts_api, "require_permission", _only({"view", "operate", "audit"}))
    assert client.get("/api/v1/alerts").status_code == 200
    refused = client.post("/api/v1/alerts/test")
    assert refused.status_code == 403
    assert teams.requests == [] and smtp.messages == []  # refused before anything was sent
    monkeypatch.setattr(alerts_api, "require_permission", _only(set()))
    assert client.get("/api/v1/alerts").status_code == 403
    monkeypatch.setattr(alerts_api, "require_permission", _only({"admin"}))
    assert client.post("/api/v1/alerts/test").status_code == 200
    assert len(teams.requests) == 1 and len(smtp.messages) == 1


def test_a_test_sent_from_another_site_is_refused(client, tmp_path, teams, smtp):
    _both(tmp_path, teams, smtp)
    refused = client.post("/api/v1/alerts/test", headers={"Origin": "https://elsewhere.example"})
    assert refused.status_code == 403
    assert teams.requests == [] and smtp.messages == []


def test_settings_that_cannot_be_read_are_an_answer_not_a_crash(client, monkeypatch):
    from maverick import ops_alert

    monkeypatch.setattr(ops_alert, "delivery_status", lambda: (_ for _ in ()).throw(OSError("/etc/secret/path")))
    answer = client.get("/api/v1/alerts")
    assert answer.status_code == 503
    assert answer.json()["detail"] == "The alert settings could not be read."
