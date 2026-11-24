"""Notifications for run events and operator alerts.

Sends through two channels and nothing else:
  - Microsoft Teams, through a Workflows webhook (the saved
    [notifications] teams_webhook, else TEAMS_NOTIFY_WEBHOOK_URL)
  - Email over SMTP (the platform mail backend; also carries the daily
    summary from maverick.daily_digest)

Config (in ~/.maverick/config.toml):

    [notifications]
    backend = "teams"            # teams | email | none (the default)
    teams_webhook = "${TEAMS_NOTIFY_WEBHOOK_URL}"   # a secret: whoever holds it can post

    [notifications.email]
    host = "smtp.example.com"
    port = 587
    user = "alerts@example.com"
    password = "${MAVERICK_SMTP_PASSWORD}"   # or the sealed All settings value
    from_address = "Second Shift <alerts@example.com>"
    tls = "starttls"             # starttls | ssl | none
    to = "ops@example.com"       # where run alerts go (the digest picks its own recipient)

Use:

    from maverick.notifications import notify
    notify("Run #42 finished", priority="default", category="run")

Failures are logged but never block the caller. Multiple backends can
be configured; each fires its own notification.

It does not retry a failed send, and it does not send to ntfy, Pushover,
Discord or Slack: those names are no longer channels, and a message
addressed to one is recorded as not sent. A webhook address is a secret and
never appears in a log line, a delivery record or a returned message.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import threading
import uuid
from contextvars import ContextVar, copy_context

log = logging.getLogger(__name__)


_outcome = ContextVar("notification_outcome", default=None)


def _response_accepted(status: int) -> bool:
    if 200 <= status < 300:
        _outcome.set(("delivered", "Accepted by the notification service. This does not mean the person saw it.", False))
        return True
    if 400 <= status < 500 and status != 408:
        _outcome.set(("failed", "The notification service refused this request. Check the saved destination and credentials.", True))
    else:
        _outcome.set(("unknown", "The service did not confirm delivery. Check the destination before sending again.", False))
    return False


def _network_unknown() -> None:
    _outcome.set(("unknown", "Delivery could not be confirmed. Check the destination before sending again.", False))


def never_sent(exc: BaseException) -> bool:
    """Whether an HTTP send that raised ``exc`` provably never reached the service:
    it never connected (the host could not be reached or the address is unusable)."""
    try:
        import httpx

        return isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout,
                                httpx.UnsupportedProtocol, httpx.InvalidURL))
    except Exception:  # noqa: BLE001 -- no httpx: treat the result as unknown
        return False


def mark_transport_failure(exc: BaseException) -> None:
    """Record why an HTTP send raised. A request that never connected was never
    sent, so it is a definite failure that may be retried after a wait; any other
    failure may have reached the service and stays unconfirmed."""
    if never_sent(exc):
        _outcome.set(("failed", "The notification service could not be reached. Nothing was sent.", True))
    else:
        _network_unknown()


_executor = None  # type: ignore[var-annotated]
_executor_lock = threading.Lock()


def _get_executor():
    global _executor
    with _executor_lock:
        if _executor is None:
            from concurrent.futures import ThreadPoolExecutor
            _executor = ThreadPoolExecutor(
                max_workers=2, thread_name_prefix="mvk-notify",
            )
    return _executor


def _resolve_env_ref(value: str | None) -> str | None:
    """Reject unresolved references; trusted layers were expanded by config."""
    if not value:
        return value
    if value.startswith("${") and value.endswith("}"):
        return None
    return value


def _load_config() -> dict:
    try:
        from .config import load_config
        return (load_config() or {}).get("notifications") or {}
    except Exception:
        return {}


#: The backends a notification can go to. Every other name is refused.
BACKENDS = ("teams", "email")

_NOT_A_BACKEND = "Not sent: this is not a supported channel. Use teams or email."


def _not_sent(reason: str, *, retry: bool = True) -> bool:
    """Record a definite "not sent" and its plain reason. Always False."""
    _outcome.set(("failed", reason, retry))
    log.debug("notify: %s", reason)
    return False


# The HTTP client writes every request line, address included, to its own log
# at INFO, and at DEBUG the reply's headers, which can repeat the address (a
# redirect does). A webhook address is a secret (whoever holds it can post), so
# the client's own log lines are dropped while one is in use.
_secret_address = ContextVar("notification_secret_address", default=False)


class _HideSecretRequest(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not _secret_address.get()


for _client_log in ("httpx", "httpcore.connection", "httpcore.http11", "httpcore.http2", "httpcore.proxy",
                    "httpcore.socks"):
    logging.getLogger(_client_log).addFilter(_HideSecretRequest())

_TEAMS_TIMEOUT = 10.0
# Microsoft gives 28 KB as the most a webhook message may hold. What counts
# toward it is not spelled out, so the whole request stays well inside it.
_TEAMS_MAX_BYTES = 24_000
_TEAMS_SHORTENED = "\n\n(This message was shortened.)"


def _teams_address_problem(url: str) -> str:
    """Why ``url`` cannot be used as a Teams webhook address, in words for an
    administrator, or "" when it can. The address itself is never quoted."""
    if not url:
        return "No Teams webhook address is set."
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
        scheme, host, _port = parts.scheme.lower(), (parts.hostname or "").lower(), parts.port
    except ValueError:
        scheme = host = ""
    if scheme not in ("http", "https") or not host:
        return "The Teams webhook address is not a web address."
    # The address is the credential, so it only travels encrypted. Plain HTTP
    # is left for an address on this machine, which never crosses a network.
    if scheme == "http" and host not in ("localhost", "127.0.0.1", "::1"):
        return "The Teams webhook address must start with https://."
    return ""


def _teams_target(url: str) -> str:
    """``url`` without a port that only repeats the default. Microsoft's own
    example addresses end the host in ``:443``; other HTTP clients leave that
    out of the host they name in the request, and so does this one."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    if parts.port != {"https": 443, "http": 80}.get(parts.scheme.lower()):
        return url
    return urlunsplit(parts._replace(netloc=parts.netloc.rsplit(":", 1)[0]))


def _teams_text(value: str) -> str:
    """``value`` as card text. Teams reads card text as Markdown, so square
    brackets become round ones: text an agent chose can then never show as a
    link with a hidden target. A line break only shows after a blank line."""
    plain = str(value or "").encode("utf-8", "replace").decode("utf-8")
    plain = plain.replace("[", "(").replace("]", ")")
    return "\n\n".join(line.strip() for line in plain.splitlines() if line.strip())


def _teams_message(title: str, body: str) -> bytes:
    """The request Microsoft documents for a Workflows webhook ("When a Teams
    webhook request is received"): a ``message`` carrying one Adaptive Card.
    A long body is cut so the request stays inside the size limit."""
    import json

    heading = _teams_text(title)[:200]

    def encode(text: str) -> bytes:
        blocks = [{"type": "TextBlock", "text": heading, "weight": "Bolder", "size": "Medium", "wrap": True}]
        if text:
            blocks.append({"type": "TextBlock", "text": text, "wrap": True})
        card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                "version": "1.2", "body": blocks}
        message = {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}
        return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    text = _teams_text(body)
    whole = encode(text)
    if len(whole) <= _TEAMS_MAX_BYTES:
        return whole
    low, high = 0, len(text)
    while low < high:  # the longest start of the text that still fits
        middle = (low + high + 1) // 2
        if len(encode(text[:middle] + _TEAMS_SHORTENED)) <= _TEAMS_MAX_BYTES:
            low = middle
        else:
            high = middle - 1
    return encode(text[:low] + _TEAMS_SHORTENED)


def _teams_failure(exc: BaseException, *, requested: bool) -> None:
    """Record why a Teams send raised, in words that hold no address.
    ``requested`` says whether the request had been handed to the HTTP client."""
    from .enterprise import EgressBlocked
    from .tools._ssrf import BlockedHost

    if isinstance(exc, BlockedHost):
        _not_sent("The Teams webhook address could not be found on the public internet, so nothing was sent.",
                  retry=False)
    elif isinstance(exc, EgressBlocked):
        _not_sent("The outbound network rules do not allow the Teams webhook address, so nothing was sent.",
                  retry=False)
    elif not requested:
        _not_sent("The request to Teams could not be prepared on this server, so nothing was sent.")
    else:
        mark_transport_failure(exc)


def _send_teams(title: str, body: str, url: str) -> bool:
    """Post one card to a Teams channel through its Workflows webhook. The
    address passes the outbound guards first (a public address, a connection
    pinned to it, the outbound policy) and no redirect is followed. Never
    raises."""
    hide = _secret_address.set(True)
    requested = False
    try:
        from .governed_http import guarded_sender
        from .tools._ssrf import safe_client

        url = _teams_target(url)
        message = _teams_message(title, body)
        with safe_client(url, timeout=_TEAMS_TIMEOUT) as client:
            def post(target: str, **request) -> int:
                # Only the status is needed, and the receiver chooses how long
                # its reply is: stop reading once the status has arrived.
                with client.stream("POST", target, **request) as reply:
                    return reply.status_code

            requested = True
            status = guarded_sender(post)(url, content=message, headers={"Content-Type": "application/json"})
        return _response_accepted(status)
    except Exception as e:  # noqa: BLE001 -- a send never raises into its caller
        # The address IS the secret, and both the HTTP client and the outbound
        # guards put it (or its host) in str(e): log the exception TYPE only.
        _teams_failure(e, requested=requested)
        log.warning("notify teams failed: %s", type(e).__name__)
        return False
    finally:
        _secret_address.reset(hide)


_EMAIL_TLS_MODES = ("starttls", "ssl", "none")
_EMAIL_TIMEOUT = 15.0


def _setting_text(value: object) -> str:
    """A saved text setting, or "" for anything else: an unresolved reference,
    a number, a table. A setting typed wrongly must not raise into a send."""
    return (_resolve_env_ref(value) or "").strip() if isinstance(value, str) else ""


def _recipients(value: object) -> str:
    """The ``to`` setting as one address line; several recipients may be
    written as a list."""
    values = value if isinstance(value, (list, tuple)) else [value]
    return ", ".join(filter(None, (_setting_text(item) for item in values)))


def _sender_domain(address: str) -> str:
    """The domain of a ``Name <user@domain>`` sending address, or "" when it
    has none that is safe to put in a message header."""
    from email.utils import parseaddr

    domain = parseaddr(address)[1].rpartition("@")[2]
    return domain if domain.isascii() and domain.replace("-", "").replace(".", "").isalnum() else ""


def _smtp_failure(exc: BaseException) -> str:
    """Why the mail server did not take a message, in words that hold no
    address, user name or password (an SMTP error can echo all three)."""
    import smtplib
    import ssl

    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "The mail server did not accept the user name and password."
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "The mail server refused the address set to receive alerts."
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "The mail server refused the sending address."
    if isinstance(exc, ssl.SSLError):
        return ("A secure connection to the mail server could not be set up. "
                "Check the tls setting and the server's certificate.")
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return ("The mail server does not offer the sign-in or encryption these settings ask for. "
                "Check the tls, user and password settings.")
    if isinstance(exc, smtplib.SMTPResponseException):
        return "The mail server answered but did not take the message."
    return "The mail server could not be reached, or it closed the connection."


def _email_config(cfg: dict | None = None) -> dict:
    """The ``[notifications.email]`` table with defaults and the password
    resolved through the secret provider (``MAVERICK_SMTP_PASSWORD`` wins over
    the sealed value saved on the All settings page)."""
    from .secret_provider import get_secret_or_saved

    section = _load_config() if cfg is None else cfg
    raw = section.get("email") if isinstance(section.get("email"), dict) else {}
    port = raw.get("port", 587)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        port = 587
    tls = str(raw.get("tls") or "starttls").strip().lower()
    if tls not in _EMAIL_TLS_MODES:
        tls = "starttls"
    saved_password = _resolve_env_ref(raw.get("password")) if isinstance(raw.get("password"), str) else None
    return {
        "host": _setting_text(raw.get("host")),
        "port": port,
        "user": _setting_text(raw.get("user")),
        "password": get_secret_or_saved("MAVERICK_SMTP_PASSWORD", saved_password) or "",
        "from_address": _setting_text(raw.get("from_address")),
        "tls": tls,
        "to": _recipients(raw.get("to")),
    }


def _smtp_tls_problem(mail: dict) -> str:
    if mail["tls"] != "none":
        return ""
    host = mail["host"].lower()
    try:
        local = ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = host == "localhost"
    if local and not mail["user"]:
        return ""
    return ("Alerts require a mail server with verified TLS. "
            "A relay on this machine may use a plain connection without a username.")


def _smtp_session(mail: dict):
    import smtplib
    import ssl

    if mail["tls"] == "ssl":
        return smtplib.SMTP_SSL(mail["host"], mail["port"], timeout=_EMAIL_TIMEOUT,
                                context=ssl.create_default_context())
    host = mail["host"]
    if mail["tls"] == "none" and host.lower() == "localhost":
        host = "127.0.0.1"
    return smtplib.SMTP(host, mail["port"], timeout=_EMAIL_TIMEOUT)


def send_email(to: str, subject: str, text_body: str, *, html_body: str | None = None,
               cfg: dict | None = None, headers: dict[str, str] | None = None) -> bool:
    """Send one message through ``[notifications.email]``. False when mail is
    not set up or the server refuses; never raises. Logs the failure type only
    (an SMTP error can echo credentials)."""
    import smtplib
    import ssl
    from email.message import EmailMessage
    from email.utils import formatdate, make_msgid

    from . import practice

    if practice.active():  # practice mode: recorded, never sent
        practice.record("email", "Email", {"to": to, "subject": subject})
        return False
    mail = _email_config(cfg)
    recipient = " ".join(str(to or "").split())
    if not recipient or "@" not in recipient:
        return False
    if not mail["host"] or not mail["from_address"]:
        # No dedicated alert server: the platform mailer's [email] account
        # (invitations use it) carries the plain-text version.
        try:
            from .mailer import MailerError, MailerNotSent, configured, send

            if not configured():
                return False
            send(recipient, str(subject or "Second Shift"), str(text_body or ""))
            return True
        except MailerNotSent as e:
            # The mailer's own "definitely not sent": it could not connect or
            # log in, the recipient was refused, or sending is off. Stays a
            # plain failure (safe to retry), never "unknown".
            log.warning("notify email failed: %s", type(e).__name__)
            return False
        except MailerError as e:
            _network_unknown()  # the message may already be on the wire
            log.warning("notify email failed: %s", type(e).__name__)
            return False
    problem = _smtp_tls_problem(mail)
    if problem:
        return _not_sent(problem, retry=False)
    message = EmailMessage()
    message["From"] = mail["from_address"]
    message["To"] = recipient
    message["Subject"] = " ".join(str(subject or "Second Shift").split())[:200]
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain=_sender_domain(mail["from_address"]) or "second-shift.local")
    # One-click unsubscribe (RFC 8058) and similar list headers; values are
    # links Second Shift made, never message content.
    for name, value in (headers or {}).items():
        if name in {"List-Unsubscribe", "List-Unsubscribe-Post"} and "\n" not in value and "\r" not in value:
            message[name] = value
    message.set_content(str(text_body or ""))
    if html_body:
        message.add_alternative(str(html_body), subtype="html")
    on_the_wire = False
    try:
        with _smtp_session(mail) as smtp:
            if mail["tls"] == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if mail["user"]:
                smtp.login(mail["user"], mail["password"])
            on_the_wire = True  # from here (MAIL FROM, RCPT TO, DATA) it may be delivered
            refused = smtp.send_message(message)
        return not refused
    except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
        # A failure before the message is handed over (connection refused, TLS,
        # login) or an explicit refusal by the server sent nothing: a plain,
        # retryable failure. Only a lost or unanswered hand-over is unknown.
        refused_by_server = isinstance(e, (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused,
                                           smtplib.SMTPDataError))
        if on_the_wire and not refused_by_server:
            _network_unknown()
        else:
            _not_sent(_smtp_failure(e))
        log.warning("notify email failed: %s", type(e).__name__)
        return False

def _email_problem(cfg: dict | None = None) -> str:
    """Why a notification cannot be emailed with the current settings, in
    words for an administrator, or "" when it can."""
    mail = _email_config(cfg)
    if not mail["to"]:
        return "No email address is set to receive alerts."
    if "@" not in mail["to"]:
        return "The email address set to receive alerts is not valid."
    if mail["host"] and mail["from_address"]:
        return _smtp_tls_problem(mail)
    from .mailer import unavailable_reason

    # No complete alert server: the platform mail account carries the message.
    reason = unavailable_reason()
    if not reason:
        return ""
    if reason != "no sending account configured":
        return "Email sending is turned off, or its settings could not be read."
    if mail["host"] or mail["from_address"]:
        return "The alert mail settings are incomplete: both host and from_address are needed."
    return "No mail server is set up to send alerts."

def backend_status(backend: str, cfg: dict | None = None) -> dict:
    """Whether ``backend`` has what it needs to send, for a settings or status
    page: ``ready``, and the plain ``problem`` when it is not. It holds no
    secret: a webhook address is reported only as set or not set, while an
    email recipient is shown."""
    section = _load_config() if cfg is None else cfg
    if backend == "teams":
        url = _webhook_url(section, "teams")
        problem = _teams_address_problem(url)
        return {"channel": "teams", "ready": not problem, "problem": problem, "webhook_set": bool(url)}
    if backend == "email":
        problem = _email_problem(section)
        return {"channel": "email", "ready": not problem, "problem": problem,
                "recipient": _email_config(section)["to"]}
    return {"channel": backend, "ready": False, "problem": _NOT_A_BACKEND}


# The configuration key and environment variable of each webhook backend. The
# key names are spelled out so the settings catalog can prove they are read here.
_WEBHOOKS = {
    "teams": ("teams_webhook", "TEAMS_NOTIFY_WEBHOOK_URL"),
}


def _webhook_url(cfg: dict, backend: str) -> str:
    """The saved or environment webhook address of the ``teams`` backend. It is
    a secret: callers send to it and never log, store or return it."""
    key, env_name = _WEBHOOKS[backend]
    return _setting_text(cfg.get(key)) or os.environ.get(env_name, "").strip()


def _dispatch(backend: str, *, cfg: dict, title: str, body: str, priority: str) -> bool:
    if backend == "teams":
        url = _webhook_url(cfg, "teams")
        problem = _teams_address_problem(url)
        return _not_sent(problem) if problem else _send_teams(title, body, url)
    if backend == "email":
        problem = _email_problem(cfg)
        return _not_sent(problem) if problem else send_email(_email_config(cfg)["to"], title, body, cfg=cfg)
    log.warning("notify: unknown backend %r", backend)
    return _not_sent(_NOT_A_BACKEND, retry=False)

def _is_backend_name(text: str) -> bool:
    """Whether ``text`` looks like a backend name at all. Names are typed by
    hand, and anything else found in their place (an address pasted into the
    wrong setting, say) must not travel on into a log line or a delivery
    record."""
    return 0 < len(text) <= 32 and text.isascii() and text.replace("-", "").replace("_", "").isalnum()


def _requested(cfg: dict, backends: list[str] | None) -> list[str]:
    # Normalize: backend names are user-typed (config/TOML or the `backends`
    # arg) and matched case-sensitively in _dispatch ("teams"/"email"), so
    # "Teams" / "Email" / "None" would otherwise dispatch to no handler or
    # skip the "none" filter -- a user who configured notifications silently
    # gets none. Lowercase + strip; drop the "none" sentinel and anything that
    # is not a name. With nothing configured the backend is "none".
    if isinstance(backends, str):  # one name, not its letters
        backends = [backends]
    names = [b.strip().lower() for b in (backends or [cfg.get("backend", "none")]) if isinstance(b, str)]
    return [b for b in names if b != "none" and _is_backend_name(b)]


def _admit(cfg, requested, event, delivery_kind, retry):
    from .notification_receipts import DeliveryReceipts
    receipts = DeliveryReceipts() if cfg.get("delivery_receipts", True) is not False else None
    if len(event) > 200:
        raise ValueError("Delivery reference is too long")
    if retry and (receipts is None or delivery_kind != "test"):
        return receipts, []
    admitted = []
    for backend in dict.fromkeys(requested):
        if receipts is None:
            admitted.append((backend, None))
        else:
            try:
                ident, acquired = receipts.claim(event, backend, kind=delivery_kind, retry=retry)
            except Exception as exc:
                log.warning("notify receipt admission unavailable: %s", type(exc).__name__)
                if delivery_kind == "test":
                    raise RuntimeError("Delivery history is unavailable; the test was not sent.") from None
                continue
            if acquired:
                admitted.append((backend, ident))

    return receipts, admitted


def _tracked(backend, ident, *, cfg, title, body, priority, receipts, authorize, states=None):
    from .authority_effects import authority_effect_fence
    token = _outcome.set(("failed", "Not sent. Check the channel configuration and installed backend dependencies.", True))
    started = False
    final = "failed"
    try:
        with authority_effect_fence():
            if authorize is not None:
                authorize()
            if cfg != _load_config():
                raise ValueError("Notification configuration changed")
            if receipts is not None:
                receipts.update(ident, "sending", "Contacting the notification service.")
            started = True
            result = _dispatch(backend, cfg=cfg, title=title, body=body, priority=priority)
            outcome = _outcome.get()
            if result and outcome[0] != "delivered":
                outcome = ("delivered", "Accepted by the notification service. This does not mean the person saw it.", False)
            final = outcome[0] if outcome[0] in ("delivered", "failed", "unknown") else ("delivered" if result else "unknown")
            if receipts is not None:
                receipts.update(ident, outcome[0], outcome[1], safe_to_retry=outcome[2])
            return result
    except Exception as exc:
        log.warning("notify dispatch unavailable: %s", type(exc).__name__)
        if final == "delivered":
            # The service accepted it; only recording that failed. It is not
            # unsent, and the receipt keeps its conservative "sending" state so
            # nothing replays it.
            return True
        final = "unknown" if started else "failed"
        if receipts is not None:
            try:
                message = ("Delivery could not be confirmed. Check the destination before sending again." if started
                           else "Not sent. Current access, configuration or delivery storage could not be verified.")
                receipts.update(ident, "unknown" if started else "failed", message)
            except Exception:
                log.warning("notify receipt could not be saved")
        return False
    finally:
        _outcome.reset(token)
        if states is not None:
            states.append(final)


def notify(
    body: str,
    *,
    title: str = "Second Shift",
    priority: str = "default",
    category: str | None = None,
    backends: list[str] | None = None,
    async_dispatch: bool = True,
    batch: bool = True,
    delivery_key: str | None = None,
    delivery_kind: str = "event",
    retry: bool = False,
    authorize=None,
    outcomes: list[str] | None = None,
) -> int:
    """Queue a notification. Async returns accepted queue count, never proof of delivery.

    ``priority`` is one of: low / default / high / max.
    ``backends`` overrides config (e.g. ['teams']). None = use config.
    ``async_dispatch=False`` runs synchronously (mainly for tests).
    ``batch`` lets opt-in **notification batching** coalesce low/normal-priority
    pushes (``[notifications] batch_window_seconds``); high/urgent always go
    straight through, and with batching unconfigured this is a no-op. When an
    item is queued for a later batch, the call returns 0 (fired *now*).

    ``outcomes`` receives, on a synchronous send, one final state per
    dispatched backend: ``delivered`` (accepted), ``failed`` (definitely not
    sent) or ``unknown`` (it may have been sent; never replay it blindly). An
    item held for a later batch adds the single state ``batched``, which
    tells that 0 apart from "nothing was sent".
    """
    from . import practice

    if practice.active():  # practice mode: recorded, never sent
        practice.record("alert", title, {"body": body, "priority": priority})
        return 0
    cfg = _load_config()
    requested = _requested(cfg, backends)
    if not requested:
        return 0

    # Opt-in batching: coalesce low/normal-priority pushes into a windowed
    # digest. High/urgent bypass; sync sends (tests, and the batcher's own
    # delivery) bypass so there's no recursion. No-op unless configured.
    # A send that must pass an authority check cannot wait in a batch: the
    # batcher's own delivery does not carry the check, so it would skip it.
    if (batch and async_dispatch and delivery_key is None and authorize is None
            and priority not in ("high", "max", "urgent")):
        from .notification_batcher import shared as _shared_batcher
        batcher = _shared_batcher()
        if batcher is not None:
            fired = batcher.submit(body, title=title, priority=priority,
                                   category=category, backends=backends)
            if not fired and outcomes is not None:
                outcomes.append("batched")
            return fired

    event = delivery_key or uuid.uuid4().hex
    receipts, admitted = _admit(cfg, requested, event, delivery_kind, retry)

    def tracked(backend, ident, states=None):
        return _tracked(backend, ident, cfg=cfg, title=title, body=body,
                        priority=priority, receipts=receipts, authorize=authorize, states=states)

    if async_dispatch:
        exec_ = _get_executor()
        for backend, ident in admitted:
            context = copy_context()
            exec_.submit(context.run, tracked, backend, ident)
        return len(admitted)
    # Sync (for tests).
    fired = 0
    for backend, ident in admitted:
        if tracked(backend, ident, outcomes):
            fired += 1
    return fired


__all__ = [
    "notify",
    "send_email",
]
