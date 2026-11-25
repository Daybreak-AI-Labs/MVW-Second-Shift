"""Approve in Microsoft Teams: an Azure Bot that posts approval cards and takes the click.

When a request waits for a person, the people who may decide it get an Adaptive
Card in Teams with Approve and Reject. A click reaches ``POST /webhook/teams``
as a signed Bot Connector request and decides the request through
:func:`approval_decisions.decide_from_channel`, by the same rules as the
Approvals page. The card then shows who decided and when.

What this module does:

* verifies every request against Microsoft's Bot Connector signing keys
  (issuer ``https://api.botframework.com``, audience = the bot's app id,
  RS256, expiry with 5 minutes of skew, the ``msteams`` endorsement, and the
  token's ``serviceurl`` equal to the activity's), and refuses anything it
  cannot verify
  (https://learn.microsoft.com/azure/bot-service/rest-api/bot-framework-rest-connector-authentication);
* accepts only the organisation's tenant, and optionally only listed people;
* claims every activity id once in the world model, so a redelivered click
  never decides twice;
* sends proactive cards to the linked approvers' personal chats and to one
  optional channel, remembers each card it posted, and updates every copy when
  the request is decided;
* gives an administrator a status answer and a test card, and a person a way
  to link their Teams account.

What it does not do: run tasks from chat, answer questions, or decide anything
itself. The bot is single-tenant (Microsoft stopped creating multi-tenant Azure
Bots in 2025). The app secret is read from the environment variable the
settings name and is never logged, stored or returned. Every outbound call goes
through the guarded client (``maverick.tools._ssrf.safe_client``) with a
timeout and a size bound.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import teams_cards
from .auth import caller_principal, require_permission

log = logging.getLogger(__name__)
router = APIRouter()

BOT_OPENID_METADATA = "https://login.botframework.com/v1/.well-known/openidconfiguration"
BOT_ISSUER = "https://api.botframework.com"
TOKEN_SCOPE = "https://api.botframework.com/.default"
LOGIN_HOST = "https://login.microsoftonline.com"
DEFAULT_SERVICE_URL = "https://smba.trafficmanager.net/teams/"
WEBHOOK_PATH = "/webhook/teams"
ALGORITHMS = ("RS256",)
CLOCK_SKEW_SECONDS = 300
KEYS_TTL_SECONDS = 24 * 3600
KEYS_REFRESH_COOLDOWN = 60.0
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
HTTP_TIMEOUT = 15.0
DEDUP_CHANNEL = "teams"
_LINK_CODE = re.compile(r"[0-9A-Fa-f]{6,16}")
_GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


class TeamsAuthError(PermissionError):
    """The incoming request is not a verified Bot Connector call."""


class TeamsSendError(Exception):
    """A message Teams did not take, with a plain sentence for the administrator."""

    def __init__(self, message: str, *, unknown: bool = False) -> None:
        super().__init__(message)
        self.message = message
        self.unknown = unknown  # the message may still have been delivered


# ------------------------------------------------------------ outbound HTTP


def _bounded_json(response) -> object:
    body = bytearray()
    for chunk in response.iter_bytes(chunk_size=65536):
        if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
            raise TeamsSendError("Microsoft's answer was larger than expected and was ignored.")
        body.extend(chunk)
    try:
        return json.loads(bytes(body)) if body else {}
    except ValueError:
        return {}


def default_transport(method: str, url: str, *, headers: dict | None = None, json_body: object = None,
                      data: dict | None = None, timeout: float = HTTP_TIMEOUT) -> tuple[int, object]:
    """One HTTPS request through the guarded client; ``(status, JSON body)``."""
    from maverick.tools._ssrf import safe_client

    if urlsplit(url).scheme != "https":
        raise TeamsSendError("Teams addresses must be https.")
    with safe_client(url, timeout=timeout) as client:
        with client.stream(method, url, headers=headers or {}, json=json_body, data=data) as response:
            return response.status_code, _bounded_json(response)


# ----------------------------------------------------------------- tokens


def token_endpoint(tenant_id: str) -> str:
    """A single-tenant bot asks its own tenant for a token."""
    return f"{LOGIN_HOST}/{quote(tenant_id.strip(), safe='')}/oauth2/v2.0/token"


def explain_token_failure(status: int, body: object) -> str:
    """Microsoft's token error as a plain sentence (nothing secret is echoed)."""
    error = str(body.get("error") or "") if isinstance(body, dict) else ""
    description = str(body.get("error_description") or "") if isinstance(body, dict) else ""
    if error == "invalid_client" or "AADSTS7000215" in description:
        return ("Microsoft did not accept the bot's secret. Check the secret value (not its id) "
                "and that it has not expired.")
    if error == "unauthorized_client" or "AADSTS700016" in description:
        return "Microsoft does not know this app id in that tenant. Check the app id and the tenant id."
    if "AADSTS90002" in description:
        return "Microsoft could not find that tenant. Check the tenant id."
    if error == "invalid_scope":
        return "Microsoft refused the Bot Framework scope. Make sure the app is an Azure Bot's app registration."
    if status >= 500:
        return "Microsoft's sign-in service returned an error. Try again in a minute."
    return f"Microsoft refused the sign-in ({error or status})."


class TokenProvider:
    """The bot's client-credentials token, cached until a minute before it expires."""

    def __init__(self, app_id: str, secret: str, tenant_id: str, transport=None) -> None:
        self.app_id, self._secret, self.tenant_id = app_id, secret, tenant_id
        self._transport = transport or default_transport
        self._token, self._expires = "", 0.0
        self._lock = threading.Lock()

    def token(self) -> str:
        with self._lock:
            if self._token and time.monotonic() < self._expires - 60:
                return self._token
            status, body = self._transport(
                "POST", token_endpoint(self.tenant_id),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"grant_type": "client_credentials", "client_id": self.app_id,
                      "client_secret": self._secret, "scope": TOKEN_SCOPE})
            if status != 200 or not isinstance(body, dict) or not body.get("access_token"):
                raise TeamsSendError(explain_token_failure(status, body))
            self._token = str(body["access_token"])
            self._expires = time.monotonic() + float(body.get("expires_in") or 3600)
            return self._token


# ------------------------------------------------------ inbound token check


class SigningKeys:
    """The Bot Connector's signing keys from its OpenID metadata. Refreshed on an
    unknown ``kid`` (at most once a minute) and at least once a day, as
    Microsoft asks."""

    def __init__(self, fetch_json=None, *, metadata_url: str = BOT_OPENID_METADATA,
                 jwks: dict | None = None) -> None:
        self._fetch = fetch_json or self._default_fetch
        self._metadata_url = metadata_url
        self._keys: dict[str, dict] = {}
        self._fetched = float("-inf")
        self._last_attempt = float("-inf")
        self._lock = threading.Lock()
        if jwks:
            self._store(jwks)

    @staticmethod
    def _default_fetch(url: str) -> dict:
        status, body = default_transport("GET", url, timeout=5.0)
        if status != 200 or not isinstance(body, dict):
            raise TeamsAuthError("the signing key document could not be fetched")
        return body

    def _store(self, jwks: dict) -> None:
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(keys, list) or not 1 <= len(keys) <= 128:
            raise TeamsAuthError("Bot Framework signing key set is invalid")
        self._keys = {str(k.get("kid")): k for k in keys if isinstance(k, dict) and k.get("kid")}
        self._fetched = time.monotonic()

    def _refresh(self) -> None:
        now = time.monotonic()
        if now < self._last_attempt + KEYS_REFRESH_COOLDOWN:
            raise TeamsAuthError("signing key refresh is temporarily unavailable")
        self._last_attempt = now
        try:
            metadata = self._fetch(self._metadata_url)
            uri = str((metadata or {}).get("jwks_uri") or "")
            if urlsplit(uri).scheme != "https":
                raise TeamsAuthError("Bot Framework OpenID metadata has no https jwks_uri")
            self._store(self._fetch(uri))
        except TeamsAuthError:
            raise
        except Exception as exc:  # a network failure or a malformed document: refuse
            raise TeamsAuthError(f"signing keys could not be fetched ({type(exc).__name__})") from exc

    def key_for(self, kid: str, *, required_endorsement: str | None = None):
        import jwt

        with self._lock:
            if time.monotonic() - self._fetched > KEYS_TTL_SECONDS or kid not in self._keys:
                self._refresh()
            jwk = self._keys.get(kid)
            if jwk is None:
                raise TeamsAuthError("signing key is unknown")
            if required_endorsement:
                endorsements = jwk.get("endorsements")
                if not isinstance(endorsements, list) or required_endorsement not in endorsements:
                    raise TeamsAuthError("signing key is not endorsed for this channel")
            try:
                return jwt.PyJWK(jwk).key
            except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
                raise TeamsAuthError("signing key is unusable") from exc


def verify_bot_token(token: str, *, app_id: str, keys: SigningKeys,
                     required_endorsement: str | None = None) -> dict:
    """The verified claims of a Bot Connector JWT, or :class:`TeamsAuthError`.

    From Microsoft's list: a Bearer JWT, issuer ``https://api.botframework.com``,
    audience = the app id, inside its validity period (5 minutes of skew), and
    signed by a key in the published set with the algorithm the metadata names."""
    try:
        import jwt
    except ImportError as exc:
        raise TeamsAuthError("pyjwt[crypto] is required to verify Teams requests") from exc
    if not isinstance(token, str) or not token or len(token) > 16384:
        raise TeamsAuthError("missing token")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TeamsAuthError("malformed token") from exc
    if header.get("alg") not in ALGORITHMS:
        raise TeamsAuthError("unaccepted signing algorithm")
    kid = header.get("kid")
    if not isinstance(kid, str) or not 1 <= len(kid) <= 256:
        raise TeamsAuthError("invalid signing key identifier")
    key = keys.key_for(kid, required_endorsement=required_endorsement)
    try:
        claims = jwt.decode(token, key, algorithms=list(ALGORITHMS), audience=app_id,
                            leeway=CLOCK_SKEW_SECONDS,
                            options={"require": ["exp", "iss", "aud"], "verify_iss": False})
    except jwt.ExpiredSignatureError as exc:
        raise TeamsAuthError("token expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise TeamsAuthError("token audience is not this app") from exc
    except jwt.PyJWTError as exc:
        raise TeamsAuthError("token signature or claims invalid") from exc
    if claims.get("iss") != BOT_ISSUER:
        raise TeamsAuthError("token issuer is not the Bot Connector")
    return claims


# -------------------------------------------------------------- activities


@dataclass
class ParsedActivity:
    kind: str
    text: str = ""
    sender_id: str = ""
    sender_aad: str = ""
    sender_name: str = ""
    conversation_id: str = ""
    conversation_type: str = "personal"
    service_url: str = ""
    tenant_id: str = ""
    activity_id: str = ""
    reply_to_id: str = ""
    bot_added: bool = False
    raw: dict = field(default_factory=dict)


def _dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def parse_activity(activity: object, *, bot_id: str) -> ParsedActivity | None:
    """One Bot Framework activity, or ``None`` for a shape this bot ignores."""
    if not isinstance(activity, dict):
        return None
    kind = str(activity.get("type") or "")
    if kind not in {"message", "conversationUpdate", "installationUpdate", "invoke"}:
        return None
    sender, conversation = _dict(activity.get("from")), _dict(activity.get("conversation"))
    tenant = _dict(_dict(activity.get("channelData")).get("tenant"))
    recipient = _dict(activity.get("recipient"))
    parsed = ParsedActivity(
        kind=kind,
        sender_id=str(sender.get("id") or ""),
        sender_aad=str(sender.get("aadObjectId") or "").lower(),
        sender_name=str(sender.get("name") or "")[:200],
        conversation_id=str(conversation.get("id") or ""),
        conversation_type=str(conversation.get("conversationType") or "personal"),
        service_url=str(activity.get("serviceUrl") or ""),
        tenant_id=str(tenant.get("id") or conversation.get("tenantId") or "").lower(),
        activity_id=str(activity.get("id") or ""),
        reply_to_id=str(activity.get("replyToId") or ""),
        raw=activity,
    )
    if kind == "message":
        text = str(activity.get("text") or "")
        for entity in activity.get("entities") if isinstance(activity.get("entities"), list) else []:
            mentioned = _dict(_dict(entity).get("mentioned"))
            if str(mentioned.get("id") or "").lower() == str(recipient.get("id") or bot_id).lower():
                text = text.replace(str(_dict(entity).get("text") or "\0"), "")
        parsed.text = " ".join(text.split())
    elif kind == "conversationUpdate":
        added = activity.get("membersAdded") if isinstance(activity.get("membersAdded"), list) else []
        me = str(recipient.get("id") or bot_id)
        parsed.bot_added = any(isinstance(m, dict) and str(m.get("id") or "") == me for m in added)
    elif kind == "installationUpdate":
        parsed.bot_added = str(activity.get("action") or "") == "add"
    return parsed


# --------------------------------------------------------------- connector


class TeamsConnector:
    """Bot Connector REST calls with the bot's cached token."""

    def __init__(self, app_id: str, secret: str, tenant_id: str, transport=None) -> None:
        self.app_id = app_id
        self.bot_id = f"28:{app_id}"
        self._transport = transport or default_transport
        self.tokens = TokenProvider(app_id, secret, tenant_id, transport=self._transport)

    @staticmethod
    def _base(service_url: str) -> str:
        parts = urlsplit(service_url or "")
        if parts.scheme != "https" or not parts.netloc:
            raise TeamsSendError("The Teams service address is not https.")
        return service_url.rstrip("/")

    def _call(self, method: str, url: str, payload: dict | None = None) -> dict:
        headers = {"Authorization": f"Bearer {self.tokens.token()}", "Content-Type": "application/json"}
        status, body = self._transport(method, url, headers=headers, json_body=payload)
        if status == 429:
            raise TeamsSendError("Teams is limiting this bot right now. Nothing was sent; try again shortly.")
        if status >= 500:
            raise TeamsSendError("Teams did not confirm the message, so it may or may not have arrived.",
                                 unknown=True)
        if status in (401, 403):
            raise TeamsSendError("Teams refused the message. Check that the Second Shift app is installed "
                                 "for that person or team, and that the app id, secret and tenant are right.")
        if status == 404:
            raise TeamsSendError("Teams could not find that chat or channel.")
        if status >= 400:
            raise TeamsSendError(f"Teams refused the message ({status}).")
        return body if isinstance(body, dict) else {}

    def send_activity(self, service_url: str, conversation_id: str, activity: dict) -> str:
        url = f"{self._base(service_url)}/v3/conversations/{quote(conversation_id, safe='')}/activities"
        return str(self._call("POST", url, {"type": "message", **activity}).get("id") or "")[:512]

    def update_activity(self, service_url: str, conversation_id: str, activity_id: str, activity: dict) -> None:
        url = (f"{self._base(service_url)}/v3/conversations/{quote(conversation_id, safe='')}"
               f"/activities/{quote(activity_id, safe='')}")
        self._call("PUT", url, {"type": "message", "id": activity_id, **activity})

    def create_personal_conversation(self, service_url: str, *, member_id: str, tenant_id: str) -> str:
        """A one-to-one chat with a person, by their Entra object id (a user
        principal name is not accepted). The app must be installed for them."""
        body = self._call("POST", f"{self._base(service_url)}/v3/conversations", {
            "bot": {"id": self.bot_id}, "isGroup": False, "members": [{"id": member_id}],
            "tenantId": tenant_id, "channelData": {"tenant": {"id": tenant_id}}})
        return str(body.get("id") or "")

    def post_to_channel(self, service_url: str, *, channel_id: str, tenant_id: str, activity: dict) -> dict:
        """A new conversation in a Teams channel, started with ``activity``. The
        app must be installed in that channel's team."""
        body = self._call("POST", f"{self._base(service_url)}/v3/conversations", {
            "isGroup": True, "bot": {"id": self.bot_id}, "tenantId": tenant_id,
            "activity": {"type": "message", **activity},
            "channelData": {"channel": {"id": channel_id}, "tenant": {"id": tenant_id}}})
        return {"conversation_id": str(body.get("id") or ""), "activity_id": str(body.get("activityId") or "")}

    def member_upn(self, service_url: str, conversation_id: str, user_id: str) -> str:
        """The person's user principal name, as Teams reports it for a member of a chat."""
        url = (f"{self._base(service_url)}/v3/conversations/{quote(conversation_id, safe='')}"
               f"/members/{quote(user_id, safe='')}")
        return str(self._call("GET", url).get("userPrincipalName") or "").strip().lower()


# ----------------------------------------------------------------- the bot


@dataclass
class TeamsBot:
    settings: dict
    secret: str
    connector: TeamsConnector
    keys: SigningKeys
    world: object = None

    @property
    def app_id(self) -> str:
        return self.settings["app_id"]

    @property
    def allowed_tenants(self) -> set[str]:
        return {self.settings["tenant_id"], *self.settings["allowed_tenants"]} - {""}

    def _world(self):
        if self.world is not None:
            return self.world
        from ._shared import _world

        return _world()

    # -- who may talk to the bot ------------------------------------------

    def tenant_allowed(self, parsed: ParsedActivity) -> bool:
        return bool(parsed.tenant_id) and parsed.tenant_id in self.allowed_tenants

    def sender_allowed(self, parsed: ParsedActivity) -> bool:
        """The organisation's tenant, an Entra object id Teams vouched for, and
        (when the settings list people) one of the listed people."""
        allowed = self.settings["allowed_users"]
        return (self.tenant_allowed(parsed) and bool(_GUID.fullmatch(parsed.sender_aad))
                and (not allowed or parsed.sender_aad in allowed))

    def verify(self, authorization: str) -> dict:
        if not authorization.startswith("Bearer "):
            raise TeamsAuthError("missing bearer token")
        return verify_bot_token(authorization[7:], app_id=self.app_id, keys=self.keys,
                                required_endorsement="msteams")

    # -- one request -------------------------------------------------------

    def handle(self, activity: dict, claims: dict) -> tuple[int, dict]:
        """Answer one verified activity: ``(HTTP status, JSON body)``."""
        if activity.get("channelId") != "msteams":
            return 403, {"error": "not a verified Microsoft Teams activity"}
        parsed = parse_activity(activity, bot_id=self.connector.bot_id)
        if parsed is None:
            return 200, {}
        claimed = str(claims.get("serviceurl") or claims.get("serviceUrl") or "")
        if not claimed or claimed != parsed.service_url:
            return 403, {"error": "service URL does not match the token"}
        if not self.tenant_allowed(parsed):
            log.warning("teams: an activity from a tenant that is not allowed was ignored")
            if parsed.kind == "invoke":
                return 200, teams_cards.message_response("This organisation can't use this bot.")
            return 200, {}
        if parsed.kind == "invoke":
            return 200, self.handle_invoke(parsed)
        if parsed.kind in ("conversationUpdate", "installationUpdate"):
            self._on_install(parsed)
            return 200, {}
        self._on_message(parsed)
        return 200, {}

    # -- people and chats --------------------------------------------------

    def _remember(self, parsed: ParsedActivity) -> None:
        if (parsed.conversation_type != "personal" or not self.sender_allowed(parsed)
                or not parsed.conversation_id):
            return
        from maverick import teams_identity

        try:
            teams_identity.remember_conversation(parsed.sender_aad, {
                "service_url": parsed.service_url, "conversation_id": parsed.conversation_id,
                "tenant_id": parsed.tenant_id, "user_id": parsed.sender_id})
            if parsed.sender_id and parsed.conversation_id:
                self._pin_upn(parsed)
        except Exception:  # noqa: BLE001 -- remembering a chat never blocks the bot
            log.warning("teams: could not remember a chat", exc_info=True)

    def _pin_upn(self, parsed: ParsedActivity) -> None:
        """If an administrator linked this person by user principal name, tie the
        link to the object id Teams just vouched for."""
        from maverick import teams_identity

        if not teams_identity.has_upn_links():
            return
        upn = self.connector.member_upn(parsed.service_url, parsed.conversation_id, parsed.sender_id)
        if upn:
            teams_identity.pin_upn(upn, parsed.sender_aad)

    def _on_install(self, parsed: ParsedActivity) -> None:
        if not parsed.bot_added or parsed.conversation_type != "personal":
            return
        self._remember(parsed)
        if self.sender_allowed(parsed):
            try:
                self.connector.send_activity(parsed.service_url, parsed.conversation_id,
                                             {"text": teams_cards.welcome_text()})
            except Exception as exc:  # noqa: BLE001 -- a welcome is a courtesy
                log.warning("teams: the welcome message failed (%s)", type(exc).__name__)

    def _on_message(self, parsed: ParsedActivity) -> None:
        if not self.sender_allowed(parsed) or not parsed.conversation_id:
            return
        self._remember(parsed)
        words = parsed.text.split()
        if len(words) == 2 and words[0].lower() == "link" and _LINK_CODE.fullmatch(words[1]):
            from maverick import teams_identity

            conversation = ({"service_url": parsed.service_url, "conversation_id": parsed.conversation_id,
                             "tenant_id": parsed.tenant_id, "user_id": parsed.sender_id}
                            if parsed.conversation_type == "personal" else None)
            principal = teams_identity.redeem_link_code(words[1], parsed.sender_aad, conversation=conversation)
            reply = ("Done. This Teams account is now linked to your Second Shift user." if principal
                     else "That code isn't valid, has expired, or can't be used while your company "
                          "sign-in is on. Ask an administrator for help.")
        else:
            reply = ("I only send approval requests and take your decision on them. "
                     "There is nothing to ask me here.")
        try:
            self.connector.send_activity(parsed.service_url, parsed.conversation_id, {"text": reply})
        except Exception as exc:  # noqa: BLE001 -- a reply is a courtesy
            log.warning("teams: a reply failed (%s)", type(exc).__name__)

    def principal_for(self, parsed: ParsedActivity) -> str | None:
        """The Second Shift user behind the account that pressed a button."""
        from maverick import teams_identity

        principal = teams_identity.resolve_principal(parsed.sender_aad)
        if principal or not parsed.sender_id or not parsed.conversation_id:
            return principal
        try:
            upn = self.connector.member_upn(parsed.service_url, parsed.conversation_id, parsed.sender_id)
        except Exception:  # noqa: BLE001 -- without a name the account stays unlinked
            return None
        principal = teams_identity.resolve_principal(parsed.sender_aad, upn) if upn else None
        if principal and upn:
            teams_identity.pin_upn(upn, parsed.sender_aad)
        return principal

    # -- the click ---------------------------------------------------------

    def handle_invoke(self, parsed: ParsedActivity) -> dict:
        """Decide an approval from a card button, or say plainly why not."""
        from . import approval_decisions as decisions

        activity = parsed.raw
        if activity.get("name") != "adaptiveCard/action":
            return teams_cards.message_response("That action isn't supported.")
        if not self.sender_allowed(parsed):
            return teams_cards.message_response("You're not allowed to use this bot.")
        value = _dict(activity.get("value"))
        action = _dict(value.get("action"))
        data = _dict(action.get("data"))
        verb = str(action.get("verb") or "")
        if not parsed.activity_id:
            return {"statusCode": 400, "type": "application/vnd.microsoft.error",
                    "value": {"code": "BadRequest", "message": "The request has no id."}}
        try:
            approval_id = int(data.get("approval_id"))
        except (TypeError, ValueError):
            return teams_cards.message_response("This card is missing its request number.")
        world = self._world()
        first = world.mark_message_processed(DEDUP_CHANNEL, parsed.activity_id)
        if not first:
            # Teams delivered this click again: show where the request stands.
            return self._current_card(parsed, approval_id, decisions)
        try:
            return self._decide(parsed, verb, approval_id, data, decisions)
        except Exception:
            # Nothing was answered: let Teams's retry of this click be processed.
            world.release_processed_message(DEDUP_CHANNEL, parsed.activity_id)
            log.exception("teams: a card action failed")
            return {"statusCode": 500, "type": "application/vnd.microsoft.error",
                    "value": {"code": "InternalError",
                              "message": "Second Shift could not record that. Try again."}}

    def _current_card(self, parsed, approval_id: int, decisions) -> dict:
        principal = self.principal_for(parsed)
        world = self._world()
        if principal and self._visible_approval(world, decisions, approval_id, principal) is not None:
            view = decisions.approval_view(approval_id, world=world)
            if view is not None:
                return teams_cards.card_response(self._render(view))
        return teams_cards.message_response("This was already received.")

    @staticmethod
    def _visible_approval(world, decisions, approval_id: int, principal: str):
        try:
            approval = world.get_approval(int(approval_id))
            if approval is not None and principal in decisions.channel_approvers(world, approval, among={principal}):
                return approval
        except Exception:  # noqa: BLE001 -- what cannot be checked is not shown
            log.warning("teams: could not check who may see approval #%s", approval_id, exc_info=True)
        return None

    def _render(self, view: dict, **options) -> dict:
        return teams_cards.approval_card(view, show_request_detail=show_request_detail(),
                                         dashboard_url=dashboard_url(), **options)

    def _decide(self, parsed, verb: str, approval_id: int, data: dict, decisions) -> dict:
        if verb not in ("approve", "reject"):
            return teams_cards.message_response("That button isn't recognised.")
        principal = self.principal_for(parsed)
        if not principal:
            return teams_cards.message_response(
                "Your Teams account isn't linked to a Second Shift user. Ask an administrator to link it, "
                "or sign in to Second Shift once so it can be recognised.")
        world = self._world()
        approval = self._visible_approval(world, decisions, approval_id, principal)
        if approval is None:
            return teams_cards.message_response(
                "Your Second Shift account can't open this request. Ask an administrator for the "
                "approver role or for access to it.")
        if approval.status != "pending":
            view = decisions.approval_view(approval_id, world=world)
            if view is None:
                return teams_cards.message_response("This request no longer exists.")
            return teams_cards.card_response(self._render(
                view, note="This request was already decided, so no decision was recorded from this click."))
        ack = data.get("acknowledged")
        acknowledgement = {"acknowledged": ack is True or str(ack).lower() == "true",
                           "confirmation": str(data.get("confirmation") or "")}
        try:
            result = decisions.decide_from_channel(
                approval_id=approval_id, status="approved" if verb == "approve" else "denied",
                principal=principal, binding=str(data.get("binding") or ""), channel="teams",
                channel_user=parsed.sender_aad, acknowledgement=acknowledgement, world=world)
        except decisions.ApprovalDecisionRefused as exc:
            fresh = decisions.approval_view(approval_id, world=world)
            if fresh is not None and fresh["approval"]["status"] == "pending":
                return teams_cards.card_response(self._render(fresh, note=exc.detail))
            return teams_cards.message_response(exc.detail)
        fresh = decisions.approval_view(approval_id, world=world)
        if fresh is None:
            return teams_cards.message_response("This request no longer exists.")
        return teams_cards.card_response(self._render(fresh, decided=result))


def show_request_detail() -> bool:
    """``[external_agents] show_request_detail``: whether the agent's own
    description of an action is shown. Unreadable settings hide it."""
    try:
        from maverick.config import get_external_agents

        return bool(get_external_agents()["show_request_detail"])
    except Exception:  # noqa: BLE001 -- unreadable settings keep the card content-free
        return False


def dashboard_url() -> str:
    try:
        from maverick.webhook_events import record_link

        link = record_link("/")
        return link if link.startswith("https://") or link.startswith("http://") else ""
    except Exception:  # noqa: BLE001 -- the link is a convenience
        return ""


# --------------------------------------------------------- card references


_CARDS_LOCK = threading.Lock()
_MAX_CARD_APPROVALS = 2000


def _cards_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "teams-cards.json"


def _cards_update(change) -> object:
    """Read, change and write the record of cards the bot posted, under a lock."""
    from maverick.record_documents import at, using_postgres

    path = _cards_path()
    record = at(path)
    with _CARDS_LOCK, record.locked():
        data: dict = {}
        if not using_postgres() and path.exists():
            from maverick.file_lock import ensure_private_file

            ensure_private_file(path)
        try:
            text = record.read_text()
            if text is not None:
                loaded = json.loads(text)
                data = loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            data = {}
        approvals = data.setdefault("approvals", {})
        result = change(approvals)
        while len(approvals) > _MAX_CARD_APPROVALS:
            approvals.pop(next(iter(approvals)))
        record.write_text(json.dumps(data, sort_keys=True))
        return result


def _remember_cards(approval_id: int, refs: list[dict]) -> None:
    if refs:
        _cards_update(lambda approvals: approvals.setdefault(str(approval_id), []).extend(refs))


def _forget_cards(approval_id: int) -> list[dict]:
    return _cards_update(lambda approvals: approvals.pop(str(approval_id), [])) or []


def _peek_cards(approval_id: int) -> list[dict]:
    return _cards_update(lambda approvals: list(approvals.get(str(approval_id), []))) or []


# -------------------------------------------------- building the bot, posting


def build_bot(*, transport=None, keys: SigningKeys | None = None, world=None) -> TeamsBot | None:
    """The bot for the saved settings, or ``None`` when Teams is off or not
    completely set up (an app id, the tenant and the secret are all needed)."""
    from maverick.approval_notify import teams_approvals_enabled, teams_secret, teams_settings

    if not teams_approvals_enabled():
        return None
    settings = teams_settings()
    secret = teams_secret(settings)
    return TeamsBot(settings=settings, secret=secret,
                    connector=TeamsConnector(settings["app_id"], secret, settings["tenant_id"],
                                             transport=transport),
                    keys=keys or _shared_keys(), world=world)


_KEYS: SigningKeys | None = None


def _shared_keys() -> SigningKeys:
    global _KEYS
    if _KEYS is None:
        _KEYS = SigningKeys()
    return _KEYS


def _service_url(settings: dict) -> str:
    return settings.get("service_url") or DEFAULT_SERVICE_URL


def _plain_error(exc: Exception) -> str:
    if isinstance(exc, TeamsSendError):
        return exc.message
    return "Second Shift could not reach Teams."


def post_approval(approval_id: int, *, world=None, bot: TeamsBot | None = None) -> list[dict]:
    """Post a waiting approval's card to the people who may decide it, and to the
    channel when one is set. Returns one ``{to, ok, detail}`` per attempt."""
    from maverick import teams_identity
    from maverick.channel_approvals import SETTINGS_PROVENANCE, separate_approver_refusal

    from . import approval_decisions as decisions

    bot = bot or build_bot(world=world)
    if bot is None:
        return []
    world = world if world is not None else bot._world()
    approval = world.get_approval(int(approval_id))
    if approval is None or approval.status != "pending" or approval.provenance == SETTINGS_PROVENANCE:
        return []
    view = decisions.approval_view(int(approval_id), world=world)
    if view is None or view["card"] is None:
        return []
    card = teams_cards.approval_card(view, show_request_detail=show_request_detail(),
                                     dashboard_url=dashboard_url())
    message = {"attachments": [teams_cards.attachment(card)]}
    settings = bot.settings
    results: list[dict] = []
    refs: list[dict] = []
    allowed = decisions.channel_approvers(world, approval)
    for person in teams_identity.reachable_people():
        principal = person["principal"]
        if principal not in allowed or separate_approver_refusal(world, approval, principal):
            continue
        if settings["allowed_users"] and person["teams_id"] not in settings["allowed_users"]:
            continue
        outcome = {"to": principal, "ok": False, "detail": ""}
        try:
            conversation = person.get("conversation") or {}
            service_url = conversation.get("service_url") or _service_url(settings)
            conversation_id = conversation.get("conversation_id")
            if not conversation_id:
                conversation_id = bot.connector.create_personal_conversation(
                    service_url, member_id=person["teams_id"], tenant_id=settings["tenant_id"])
                teams_identity.remember_conversation(person["teams_id"], {
                    "service_url": service_url, "conversation_id": conversation_id,
                    "tenant_id": settings["tenant_id"]})
            activity_id = bot.connector.send_activity(service_url, conversation_id, message)
            refs.append({"kind": "person", "to": principal, "service_url": service_url,
                         "conversation_id": conversation_id, "activity_id": activity_id})
            outcome.update(ok=True, detail="Card sent.")
        except Exception as exc:  # noqa: BLE001 -- one unreachable person never blocks the others
            outcome["detail"] = _plain_error(exc)
            log.warning("teams: could not post approval #%s (%s)", approval_id, type(exc).__name__)
        results.append(outcome)
    if settings["channel_id"] and getattr(approval, "provenance", None) == "external_agents":
        # Only a request about an outside agent goes to a shared channel: another
        # request's content belongs to the people who can open it.
        outcome = {"to": "channel", "ok": False, "detail": ""}
        try:
            service_url = _service_url(settings)
            posted = bot.connector.post_to_channel(
                service_url, channel_id=settings["channel_id"], tenant_id=settings["tenant_id"],
                activity=message)
            refs.append({"kind": "channel", "to": "channel", "service_url": service_url, **posted})
            outcome.update(ok=True, detail="Card sent.")
        except Exception as exc:  # noqa: BLE001
            outcome["detail"] = _plain_error(exc)
            log.warning("teams: could not post approval #%s to the channel (%s)", approval_id, type(exc).__name__)
        results.append(outcome)
    _remember_cards(int(approval_id), refs)
    return results


def refresh_approval_cards(approval_id: int, *, world=None, bot: TeamsBot | None = None) -> int:
    """Show the request's current state on every card the bot posted for it.
    Returns how many cards were updated."""
    from . import approval_decisions as decisions

    bot = bot or build_bot(world=world)
    if bot is None:
        return 0
    refs = _peek_cards(int(approval_id))
    if not refs:
        return 0
    view = decisions.approval_view(int(approval_id), world=world if world is not None else bot._world())
    if view is None:
        return 0
    final = view["approval"]["status"] != "pending"
    message = {"attachments": [teams_cards.attachment(bot._render(view))]}
    updated = 0
    for ref in refs:
        try:
            bot.connector.update_activity(ref["service_url"], ref["conversation_id"],
                                          ref["activity_id"], message)
            updated += 1
        except Exception as exc:  # noqa: BLE001 -- the card then says "already decided" when pressed
            log.warning("teams: could not update a card for approval #%s (%s)", approval_id, type(exc).__name__)
    if final:
        _forget_cards(int(approval_id))
    return updated


# -------------------------------------------------------------- web routes


@router.post(WEBHOOK_PATH)
async def teams_webhook(request: Request) -> JSONResponse:
    """The bot's messaging endpoint. Teams sends a Bot Connector JWT with every call."""
    bot = await run_in_threadpool(build_bot)
    if bot is None:
        raise HTTPException(status_code=404, detail="Approvals in Teams are turned off.")
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_REQUEST_BYTES:
        raise HTTPException(status_code=413, detail="too large")
    body = await request.body()
    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(status_code=413, detail="too large")
    try:
        claims = await run_in_threadpool(bot.verify, request.headers.get("Authorization", ""))
    except TeamsAuthError as exc:
        log.warning("teams: a request was refused: %s", exc)
        raise HTTPException(status_code=403, detail="not a verified Bot Connector request") from None
    try:
        activity = json.loads(body or b"{}")
    except ValueError:
        raise HTTPException(status_code=400, detail="bad JSON") from None
    if not isinstance(activity, dict):
        raise HTTPException(status_code=400, detail="bad JSON")
    status, answer = await run_in_threadpool(bot.handle, activity, claims)
    if status != 200:
        raise HTTPException(status_code=status, detail=str(answer.get("error") or "refused"))
    return JSONResponse(answer)


def _setup_problems(settings: dict) -> list[str]:
    from maverick.approval_notify import teams_secret

    problems = []
    if not settings["app_id"]:
        problems.append("Set [teams] app_id to the Azure Bot's Microsoft App ID.")
    if not settings["tenant_id"]:
        problems.append("Set [teams] tenant_id to your organisation's Microsoft Entra tenant id.")
    if not teams_secret(settings):
        problems.append(f"Set the environment variable {settings['app_secret_env']} to the bot's client "
                        "secret, or change [teams] app_secret_env to the name of the variable that holds it.")
    return problems


def status(*, check_credentials: bool = False, transport=None) -> dict:
    """Whether Teams is set up, in words for an administrator. Holds no secret."""
    from maverick import teams_identity
    from maverick.approval_notify import teams_secret, teams_settings
    from maverick.oidc import oidc_enabled

    settings = teams_settings()
    problems = _setup_problems(settings)
    secret = teams_secret(settings)
    out = {
        "enabled": settings["enabled"], "ready": settings["enabled"] and not problems,
        "problems": problems, "app_id_set": bool(settings["app_id"]), "tenant_id_set": bool(settings["tenant_id"]),
        "secret_set": bool(secret), "secret_environment_variable": settings["app_secret_env"],
        "allowed_tenants": sorted({settings["tenant_id"], *settings["allowed_tenants"]} - {""}),
        "people_limited_to_list": bool(settings["allowed_users"]),
        "channel_set": bool(settings["channel_id"]),
        "messaging_endpoint_path": WEBHOOK_PATH, "messaging_endpoint": _endpoint_url(),
        "sign_in_is_entra": bool(oidc_enabled()),
    }
    try:
        people = teams_identity.reachable_people()
        out["people_who_can_get_cards"] = len({p["principal"] for p in people})
        out["linked_accounts"] = len(teams_identity.list_links())
    except Exception:  # noqa: BLE001 -- the counts are a convenience
        out["people_who_can_get_cards"] = None
        out["linked_accounts"] = None
    if not settings["enabled"]:
        out["summary"] = "Approvals in Teams are turned off. Set [teams] enabled = true to turn them on."
    elif problems:
        out["summary"] = "Approvals in Teams are on but not set up: " + " ".join(problems)
    else:
        out["summary"] = "Approvals in Teams are on."
    if check_credentials and out["ready"]:
        try:
            TokenProvider(settings["app_id"], secret, settings["tenant_id"], transport=transport).token()
            out["credentials"] = "Microsoft accepted the bot's app id, secret and tenant."
        except Exception as exc:  # noqa: BLE001
            out["credentials"] = _plain_error(exc)
            out["ready"] = False
    return out


def _endpoint_url() -> str:
    base = dashboard_url()
    return base.rstrip("/") + WEBHOOK_PATH if base else ""


def send_test(principal: str, *, transport=None, world=None) -> dict:
    """Send the test card to the administrator's own Teams chat and to the channel."""
    from maverick import teams_identity

    info = status(check_credentials=True, transport=transport)
    if not info["ready"]:
        return {**info, "results": [], "message": info.get("credentials") or info["summary"]}
    bot = build_bot(transport=transport, world=world)
    if bot is None:
        return {**info, "results": [], "message": info["summary"]}
    message = {"attachments": [teams_cards.attachment(teams_cards.check_card())]}
    results: list[dict] = []
    mine = [p for p in teams_identity.reachable_people() if p["principal"] == principal]
    for person in mine:
        outcome = {"to": "you", "ok": False, "detail": ""}
        try:
            conversation = person.get("conversation") or {}
            service_url = conversation.get("service_url") or _service_url(bot.settings)
            conversation_id = conversation.get("conversation_id") or bot.connector.create_personal_conversation(
                service_url, member_id=person["teams_id"], tenant_id=bot.settings["tenant_id"])
            bot.connector.send_activity(service_url, conversation_id, message)
            outcome.update(ok=True, detail="The test card was sent to your Teams chat.")
        except Exception as exc:  # noqa: BLE001
            outcome["detail"] = _plain_error(exc)
        results.append(outcome)
    if not mine:
        results.append({"to": "you", "ok": False, "detail": (
            "Your Teams account isn't known yet. Install the Second Shift app in Teams and send the "
            "bot any message, or ask an administrator to link your account.")})
    if bot.settings["channel_id"]:
        outcome = {"to": "channel", "ok": False, "detail": ""}
        try:
            bot.connector.post_to_channel(_service_url(bot.settings), channel_id=bot.settings["channel_id"],
                                          tenant_id=bot.settings["tenant_id"], activity=message)
            outcome.update(ok=True, detail="The test card was sent to the channel.")
        except Exception as exc:  # noqa: BLE001
            outcome["detail"] = _plain_error(exc)
        results.append(outcome)
    sent = [r for r in results if r["ok"]]
    return {**info, "results": results,
            "message": ("The test card was sent. " if sent else "The test card did not reach anyone. ")
            + " ".join(r["detail"] for r in results if not r["ok"])}


@router.get("/api/v1/teams")
async def teams_status(request: Request) -> dict:
    """Whether approvals in Teams are set up (administrators)."""
    require_permission(request, "admin")
    return await run_in_threadpool(status)


@router.post("/api/v1/teams/test")
async def teams_test(request: Request) -> dict:
    """Check the bot's credentials and send a test card (administrators)."""
    require_permission(request, "admin")
    return await run_in_threadpool(send_test, caller_principal(request) or "")


@router.get("/api/v1/teams/links")
async def teams_links(request: Request) -> dict:
    require_permission(request, "admin")
    from maverick import teams_identity

    try:
        return {"links": await run_in_threadpool(teams_identity.list_links)}
    except teams_identity.TeamsIdentityError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/api/v1/teams/links")
async def teams_link(request: Request) -> dict:
    """Link a person's Teams account, by their Entra object id or user principal name (administrators)."""
    require_permission(request, "admin")
    from maverick import teams_identity

    body = await _json_object(request)
    try:
        row = await run_in_threadpool(teams_identity.link, body.get("teams_id"), body.get("principal"),
                                      actor=caller_principal(request) or "operator")
    except teams_identity.TeamsIdentityError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"linked": True, "principal": row["principal"]}


@router.delete("/api/v1/teams/links/{teams_id}")
async def teams_unlink(request: Request, teams_id: str) -> dict:
    require_permission(request, "admin")
    from maverick import teams_identity

    try:
        removed = await run_in_threadpool(teams_identity.unlink, teams_id,
                                          actor=caller_principal(request) or "operator")
    except teams_identity.TeamsIdentityError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not removed:
        raise HTTPException(status_code=404, detail="That Teams account isn't linked.")
    return {"unlinked": True}


@router.post("/api/v1/teams/link-codes")
async def teams_link_code(request: Request) -> JSONResponse:
    """An administrator issues a one-time code for a person (no Entra sign-in only).

    The person sends ``link <code>`` to the bot in a personal chat. The code is
    shown once and never accepted while Entra sign-in is on."""
    require_permission(request, "admin")
    from maverick import teams_identity
    from maverick.oidc import oidc_enabled

    if oidc_enabled():
        raise HTTPException(status_code=409, detail=(
            "With Entra sign-in on, people are recognised from their sign-in. Link an account by hand "
            "with their Entra object id instead."))
    body = await _json_object(request)
    try:
        code = await run_in_threadpool(teams_identity.issue_link_code, body.get("principal"),
                                       actor=caller_principal(request) or "operator")
    except teams_identity.TeamsIdentityError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    response = JSONResponse({"code": code, "valid_for_minutes": teams_identity.CODE_TTL_SECONDS // 60,
                             "instructions": "Ask the person to send the bot: link " + code})
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/api/v1/teams/me")
async def teams_me(request: Request) -> dict:
    """Whether the caller's own Teams account is known, and how to link it."""
    require_permission(request, "approve")
    from maverick import teams_identity
    from maverick.oidc import oidc_enabled

    who = caller_principal(request)
    if not who:
        raise HTTPException(status_code=403, detail="Sign in to Second Shift to link your Teams account.")
    people = await run_in_threadpool(teams_identity.reachable_people)
    known = [p["teams_id"] for p in people if p["principal"] == who]
    entra = bool(oidc_enabled())
    return {
        "linked": bool(known), "entra_sign_in": entra,
        "how": ("Install the Second Shift app in Teams and send the bot any message. Your Teams account is "
                "recognised from your Second Shift sign-in." if entra else
                "Ask an administrator for a link code, then send the bot: link <code>."),
    }


async def _json_object(request: Request) -> dict:
    try:
        body = await request.json()
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Send the details as JSON.") from None
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="Send the details as a JSON object.")
    return body


__all__ = [
    "BOT_ISSUER", "BOT_OPENID_METADATA", "SigningKeys", "TeamsAuthError", "TeamsBot", "TeamsConnector",
    "TeamsSendError", "TokenProvider", "WEBHOOK_PATH", "build_bot", "explain_token_failure",
    "parse_activity", "post_approval", "refresh_approval_cards", "router", "send_test", "status",
    "token_endpoint", "verify_bot_token",
]
