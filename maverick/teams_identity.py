"""Which Second Shift person is behind a Microsoft Teams account.

A click on an approval card arrives with the Microsoft Entra object id of the
person who pressed it (the ``aadObjectId`` of the signed Bot Connector request).
This module answers who that is, and who can be reached in Teams.

Three ways a Teams account is tied to a person:

* With Entra sign-in on, the Entra object id (or user principal name) the
  person signed in with is recorded at sign-in (``subject_directory``), so a
  person who has signed in is recognised in Teams with nothing to set up.
* An administrator links an account by hand, typing the person's Entra object
  id or user principal name. A user principal name is pinned to the object id
  the first time that person talks to the bot.
* Without Entra sign-in, an administrator issues a one-time code and the
  person sends ``link <code>`` to the bot. The code is never accepted while
  Entra sign-in is on.

The record ``teams-identities.json`` (private to the server, kept with the
other records, ``maverick.record_documents``) holds
links, hashed one-time codes and the last personal chat the bot saw for each
person, which is how a card is posted to someone proactively. It holds no
secret. This module does not decide who may approve; the dashboard's roles do.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)

CODE_TTL_SECONDS = 15 * 60
MAX_LINKS = 5000
MAX_CONVERSATIONS = 20000
_LOCK = threading.Lock()
_ID_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-@._'+")
_CONVERSATION_KEYS = ("service_url", "conversation_id", "tenant_id", "user_id")
_EMPTY = {"links": {}, "codes": {}, "conversations": {}}


class TeamsIdentityError(ValueError):
    """A link request the store refuses, with a plain sentence."""


def store_path() -> Path:
    from .paths import maverick_home

    return maverick_home() / "teams-identities.json"


def normalize_teams_id(value: object) -> str:
    """Lower-case and trim an Entra object id or user principal name."""
    text = str(value or "").strip().lower()
    if not text or len(text) > 320 or any(ch not in _ID_CHARS for ch in text):
        raise TeamsIdentityError(
            "Enter the person's Microsoft Entra object ID or their sign-in address "
            "(user principal name), such as alice@example.com."
        )
    return text


def normalize_principal(value: object) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 300 or any(ch.isspace() for ch in text):
        raise TeamsIdentityError("Choose the Second Shift user to link.")
    return text if ":" in text else f"user:{text}"


def _is_upn(key: str) -> bool:
    return "@" in key


def _load() -> dict:
    from .record_documents import at, using_postgres

    path = store_path()
    if not using_postgres():
        from .file_lock import ensure_private_directory, ensure_private_file

        ensure_private_directory(path.parent)
        if not path.exists():
            return {name: {} for name in _EMPTY}
        ensure_private_file(path)
    try:
        text = at(path).read_text()
        if text is None:
            return {name: {} for name in _EMPTY}
        data = json.loads(text)
    except (OSError, ValueError) as exc:
        raise TeamsIdentityError("The Teams account links could not be read.") from exc
    if not isinstance(data, dict):
        raise TeamsIdentityError("The Teams account links are damaged.")
    return {name: data[name] if isinstance(data.get(name), dict) else {} for name in _EMPTY}


def _write(data: dict) -> None:
    from .record_documents import at

    at(store_path()).write_text(json.dumps(data, indent=2, sort_keys=True))


class _locked:
    """Read-modify-write under one in-process and one cross-process lock."""

    def __enter__(self) -> dict:
        from contextlib import ExitStack

        from .record_documents import at

        self._stack = ExitStack()
        self._stack.enter_context(_LOCK)
        try:
            self._stack.enter_context(at(store_path()).locked())
            self.data = _load()
        except BaseException:
            self._stack.close()
            raise
        return self.data

    def __exit__(self, *exc) -> None:
        self._stack.close()


def _prune_codes(data: dict, now: float) -> None:
    data["codes"] = {
        digest: row for digest, row in data["codes"].items()
        if isinstance(row, dict) and float(row.get("expires_at") or 0) > now
    }


def _code_digest(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()


def _audit(action: str, actor: str, **fields) -> None:
    try:
        from . import audit

        audit.audit_event(audit.EventKind.CONSENT_RESULT, agent=actor or "system",
                          action=action, channel="teams", **fields)
    except Exception:  # noqa: BLE001 -- a link never fails because the log is down
        log.warning("teams identity audit failed", exc_info=True)


def _conversation_ref(conversation: dict) -> dict:
    return {k: str(conversation.get(k) or "")[:2048] for k in _CONVERSATION_KEYS}


# ----------------------------------------------------------------- links


def link(teams_id: object, principal: object, *, actor: str = "", upn: str = "") -> dict:
    """Tie a Teams account (Entra object id or user principal name) to a user.

    Linking again replaces the record. The change is written to the audit log."""
    key = normalize_teams_id(teams_id)
    who = normalize_principal(principal)
    with _locked() as data:
        if key not in data["links"] and len(data["links"]) >= MAX_LINKS:
            raise TeamsIdentityError("Too many Teams links. Remove some first.")
        previous = data["links"].get(key) if isinstance(data["links"].get(key), dict) else {}
        row = {"principal": who, "upn": str(upn or previous.get("upn") or "").strip().lower(),
               "linked_by": str(actor or ""), "linked_at": time.time()}
        data["links"][key] = row
        _write(data)
    _audit("teams_identity_linked", actor, teams_id=key, principal=who)
    return dict(row)


def unlink(teams_id: object, *, actor: str = "") -> bool:
    key = normalize_teams_id(teams_id)
    with _locked() as data:
        removed = data["links"].pop(key, None) is not None
        if removed:
            _write(data)
    if removed:
        _audit("teams_identity_unlinked", actor, teams_id=key)
    return removed


def list_links() -> list[dict]:
    """Every link made by hand or by code, oldest first."""
    with _LOCK:
        data = _load()
    out = []
    for key, row in data["links"].items():
        if not isinstance(row, dict):
            continue
        out.append({"teams_id": key, "kind": "user principal name" if _is_upn(key) else "object id",
                    "principal": str(row.get("principal") or ""),
                    "linked_by": str(row.get("linked_by") or ""),
                    "linked_at": float(row.get("linked_at") or 0),
                    "can_be_reached": key in data["conversations"]})
    out.sort(key=lambda item: item["linked_at"])
    return out


def links_for_principal(principal: object) -> list[dict]:
    who = normalize_principal(principal)
    return [item for item in list_links() if item["principal"] == who]


def principal_for(*ids: object) -> str | None:
    """The user a link ties any of ``ids`` to, or ``None``. Links only."""
    candidates = _candidates(*ids)
    if not candidates:
        return None
    with _LOCK:
        links = _load()["links"]
    for key in candidates:
        row = links.get(key)
        if isinstance(row, dict) and row.get("principal"):
            return str(row["principal"])
    return None


def _candidates(*ids: object) -> list[str]:
    out = []
    for value in ids:
        try:
            out.append(normalize_teams_id(value))
        except TeamsIdentityError:
            continue
    return out


def pin_upn(upn: object, object_id: object) -> bool:
    """A link made with a user principal name becomes a link to the Entra object
    id the bot saw for that person, which does not change when a name does."""
    keys = _candidates(upn, object_id)
    if len(keys) != 2 or not _is_upn(keys[0]) or _is_upn(keys[1]):
        return False
    with _locked() as data:
        row = data["links"].get(keys[0])
        if not isinstance(row, dict) or keys[1] in data["links"]:
            return False
        data["links"][keys[1]] = {**row, "upn": keys[0]}
        del data["links"][keys[0]]
        _write(data)
    _audit("teams_identity_pinned", str(row.get("linked_by") or ""), teams_id=keys[1],
           principal=str(row.get("principal") or ""))
    return True


# --------------------------------------------------------- Entra sign-in


def directory_principal(*ids: object) -> str | None:
    """With Entra sign-in on: the person who signed in with this Entra object id
    or user principal name, as recorded at their sign-in. ``None`` when sign-in
    is off, when nobody signed in with it, or when the record cannot be read."""
    try:
        from .oidc import oidc_enabled

        if not oidc_enabled():
            return None
        from maverick_dashboard import subject_directory
    except Exception:  # noqa: BLE001 -- unreadable sign-in settings recognise nobody
        return None
    for value in ids:
        text = str(value or "").strip()
        if not text:
            continue
        try:
            subject = subject_directory.subject_for(text)
        except Exception:  # noqa: BLE001 -- a damaged record recognises nobody
            log.warning("teams: the sign-in directory could not be read", exc_info=True)
            return None
        if subject:
            return f"user:{subject}"
    return None


def resolve_principal(object_id: object, upn: object = "") -> str | None:
    """The Second Shift user for a Teams account, or ``None``: a link first,
    then (with Entra sign-in on) the sign-in directory."""
    return principal_for(object_id, upn) or directory_principal(object_id, upn)


# ----------------------------------------------------- reachable people


def remember_conversation(teams_id: object, conversation: dict) -> None:
    """Keep the personal chat the bot last saw for this Entra object id, so a
    card can be posted into it later. Needs no link: who the person is gets
    decided when a card is posted."""
    keys = _candidates(teams_id)
    if not keys or _is_upn(keys[0]) or not isinstance(conversation, dict):
        return
    ref = _conversation_ref(conversation)
    if not ref["service_url"] or not ref["conversation_id"]:
        return
    with _locked() as data:
        if data["conversations"].get(keys[0]) == ref:
            return
        if keys[0] not in data["conversations"] and len(data["conversations"]) >= MAX_CONVERSATIONS:
            return
        data["conversations"][keys[0]] = ref
        _write(data)


def conversation_for(teams_id: object) -> dict | None:
    keys = _candidates(teams_id)
    if not keys:
        return None
    with _LOCK:
        ref = _load()["conversations"].get(keys[0])
    return dict(ref) if isinstance(ref, dict) else None


def reachable_people() -> list[dict]:
    """Every Teams account the bot could post to, with the user it belongs to:
    those linked by hand to an Entra object id, and those the bot has talked
    to that Entra sign-in recognises. Several accounts can belong to one user."""
    with _LOCK:
        data = _load()
    people: dict[str, dict] = {}
    for key, row in data["links"].items():
        if isinstance(row, dict) and row.get("principal") and not _is_upn(key):
            people[key] = {"teams_id": key, "principal": str(row["principal"]),
                           "conversation": data["conversations"].get(key)}
    for key, ref in data["conversations"].items():
        if key in people or not isinstance(ref, dict):
            continue
        principal = directory_principal(key)
        if principal:
            people[key] = {"teams_id": key, "principal": principal, "conversation": ref}
    return list(people.values())


# ------------------------------------------------------ one-time codes


def issue_link_code(principal: object, *, actor: str = "") -> str:
    """A one-time code the person sends the bot as ``link <code>``. Shown once."""
    who = normalize_principal(principal)
    code = secrets.token_hex(4).upper()
    now = time.time()
    with _locked() as data:
        _prune_codes(data, now)
        if len(data["codes"]) >= 200:
            raise TeamsIdentityError("Too many unused link codes. Wait for some to expire.")
        data["codes"][_code_digest(code)] = {"principal": who, "expires_at": now + CODE_TTL_SECONDS,
                                             "issued_by": str(actor or "")}
        _write(data)
    _audit("teams_link_code_issued", actor, principal=who)
    return code


def redeem_link_code(code: object, teams_id: object, *, conversation: dict | None = None) -> str | None:
    """Link the Teams account that sent ``code``. Returns the user, or ``None``
    for a wrong, used or expired code. Never accepted while Entra sign-in is on."""
    text = str(code or "").strip()
    if not 6 <= len(text) <= 16:
        return None
    try:
        from .oidc import oidc_enabled

        if oidc_enabled():
            return None
    except Exception:  # noqa: BLE001 -- unreadable sign-in settings accept no code
        return None
    key = normalize_teams_id(teams_id)
    if _is_upn(key):
        return None
    now = time.time()
    with _locked() as data:
        codes_before = len(data["codes"])
        _prune_codes(data, now)
        digest = _code_digest(text)
        row = data["codes"].get(digest)
        if (not isinstance(row, dict)
                or (key not in data["links"] and len(data["links"]) >= MAX_LINKS)):
            if len(data["codes"]) != codes_before:
                _write(data)
            return None
        del data["codes"][digest]
        data["links"][key] = {"principal": row["principal"], "upn": "",
                              "linked_by": str(row.get("issued_by") or ""), "linked_at": now}
        if isinstance(conversation, dict):
            ref = _conversation_ref(conversation)
            if ref["service_url"] and ref["conversation_id"]:
                data["conversations"][key] = ref
        _write(data)
    _audit("teams_identity_linked", str(row.get("issued_by") or ""), teams_id=key,
           principal=row["principal"], via="link_code")
    return str(row["principal"])


__all__ = ["TeamsIdentityError", "conversation_for", "directory_principal", "issue_link_code",
           "link", "links_for_principal", "list_links", "normalize_principal",
           "normalize_teams_id", "pin_upn", "principal_for", "reachable_people",
           "redeem_link_code", "remember_conversation", "resolve_principal", "store_path",
           "unlink"]
