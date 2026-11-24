"""The email notification backend: SMTP through a fake server, the secret
provider for the password, the platform-mailer fallback, and notify()."""
from __future__ import annotations

import pytest


class FakeSMTP:
    """Records what a real smtplib.SMTP would have been told."""

    instances: list = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.started_tls = False
        self.login_args = None
        self.sent = []
        self.refuse = False
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        self.started_tls = True

    def login(self, user, password):
        self.login_args = (user, password)

    def send_message(self, message):
        self.sent.append(message)
        return {"x@example.com": (550, b"no")} if self.refuse else {}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    import smtplib

    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_SMTP_PASSWORD", raising=False)
    monkeypatch.delenv("EMAIL_USER", raising=False)
    monkeypatch.delenv("EMAIL_APP_PASSWORD", raising=False)
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    FakeSMTP.instances = []
    config.reset_config_cache()
    yield
    config.reset_config_cache()


CFG = {"email": {"host": "smtp.example.test", "port": 2525, "user": "alerts",
                 "password": "saved-pw",  # pragma: allowlist secret
                 "from_address": "Second Shift <alerts@example.test>", "tls": "starttls",
                 "to": "ops@example.test"}}


def test_password_from_secret_provider_wins_and_ssl_mode(monkeypatch):
    from maverick.notifications import send_email

    monkeypatch.setenv("MAVERICK_SMTP_PASSWORD", "env-pw")
    cfg = {"email": {**CFG["email"], "tls": "ssl", "port": 465}}
    assert send_email("bob@example.test", "s", "b", cfg=cfg) is True
    smtp = FakeSMTP.instances[-1]
    assert smtp.login_args == ("alerts", "env-pw") and smtp.started_tls is False


def test_refusals_bad_recipients_and_failures_never_raise(monkeypatch):
    import smtplib

    from maverick.notifications import send_email

    assert send_email("not-an-address", "s", "b", cfg=CFG) is False
    assert send_email("", "s", "b", cfg=CFG) is False

    class Refusing(FakeSMTP):
        def send_message(self, message):
            return {"bob@example.test": (550, b"no")}

    monkeypatch.setattr(smtplib, "SMTP", Refusing)
    assert send_email("bob@example.test", "s", "b", cfg=CFG) is False

    class Broken(FakeSMTP):
        def __init__(self, *a, **kw):
            raise OSError("connection refused")

    monkeypatch.setattr(smtplib, "SMTP", Broken)
    assert send_email("bob@example.test", "s", "b", cfg=CFG) is False


def test_notify_email_backend_uses_the_default_recipient(monkeypatch):
    from maverick import notifications

    monkeypatch.setattr(notifications, "_load_config", lambda: {"backend": "email", **CFG})
    assert notifications.notify("Run 42 finished", title="Second Shift", async_dispatch=False) == 1
    message = FakeSMTP.instances[-1].sent[0]
    assert message["To"] == "ops@example.test" and message["Subject"] == "Second Shift"
    monkeypatch.setattr(notifications, "_load_config",
                        lambda: {"backend": "email", "email": {**CFG["email"], "to": ""}})
    assert notifications.notify("Run 43 finished", async_dispatch=False) == 0


def test_a_non_ascii_ntfy_title_is_sent_as_an_rfc2047_word_not_a_local_encoding_error(monkeypatch):
    """httpx writes header text as ASCII, so a raw "Zürich" title would fail
    before any request existed and be recorded as an unknown outcome."""
    from email.header import decode_header, make_header

    import httpx

    from maverick import notifications as n

    sent = []

    def post(url, content=None, headers=None, timeout=None):
        httpx.Request("POST", url, content=content, headers=headers)        # what httpx itself would build
        sent.append(headers)
        return httpx.Response(200)

    monkeypatch.setattr(httpx, "post", post)
    assert n._send_ntfy("Due soon: José from Zürich", "body", "default", "https://ntfy.example", "topic") is True
    title = sent[0]["Title"]
    assert title.isascii()
    assert str(make_header(decode_header(title))) == "Due soon: José from Zürich"
    assert n._send_ntfy("Plain title", "body", "default", "https://ntfy.example", "topic") is True
    assert sent[1]["Title"] == "Plain title"


def test_a_delivered_notification_whose_receipt_cannot_be_updated_is_still_delivered(monkeypatch):
    from maverick import notifications as n

    class Receipts:
        def update(self, ident, state, message, **kwargs):
            if state in ("delivered", "failed", "unknown"):
                raise OSError("receipt file locked")

    monkeypatch.setattr(n, "_dispatch", lambda backend, **kwargs: True)
    monkeypatch.setattr(n, "_load_config", dict)
    states = []
    result = n._tracked("ntfy", "id", cfg={}, title="t", body="b", priority="default",
                        receipts=Receipts(), authorize=None, states=states)
    assert result is True and states == ["delivered"]


def test_a_send_that_needs_an_authority_check_is_never_batched(monkeypatch):
    import maverick.notification_batcher as nb
    from maverick import notifications as n

    class Batcher:
        def submit(self, *args, **kwargs):
            raise AssertionError("an authorized send must not wait in a batch that skips its check")

    checked = []
    monkeypatch.setattr(nb, "shared", lambda: Batcher())
    monkeypatch.setattr(n, "_load_config", lambda: {"backends": ["ntfy"], "delivery_receipts": False})
    monkeypatch.setattr(n, "_requested", lambda cfg, backends: ["none"])
    n.notify("hi", async_dispatch=True, authorize=lambda: checked.append(True))
