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
from collections.abc import MutableMapping
from contextlib import contextmanager
from pathlib import Path

from . import keyed_records, record_documents

log = logging.getLogger(__name__)

CODE_TTL_SECONDS = 15 * 60
MAX_LINKS = 50_000
MAX_CONVERSATIONS = 50_000
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


def _load_legacy() -> dict:
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


def _keyed() -> keyed_records.KeyedRecords:
    return keyed_records.KeyedRecords(store_path())


def _migrate(collection: keyed_records.Collection) -> None:
    for name, entries in _load_legacy().items():
        collection.rows(name).seed((entry, json.dumps(value), str(value.get("principal") or "") if isinstance(value, dict)
                                    else "", 0.0) for entry, value in entries.items())
        if name == "links":
            collection.rows("upns").seed((entry, "true", "", 0.0) for entry in entries if _is_upn(entry))


class _SavedRows(MutableMapping):
    """The existing Teams actions read and change only their addressed rows."""

    def __init__(self, collection: keyed_records.Collection, name: str):
        self.values_store = collection.rows(name)
        self.upns = collection.rows("upns") if name == "links" else None

    def __getitem__(self, key: str):
        saved = self.values_store.get(key)
        if saved is None:
            raise KeyError(key)
        return json.loads(saved)

    def __setitem__(self, key: str, value: dict) -> None:
        self.values_store.put(key, json.dumps(value), tag=str(value.get("principal") or ""))
        if self.upns is not None and _is_upn(key):
            self.upns.put(key, "true")

    def __delitem__(self, key: str) -> None:
        if not self.values_store.discard(key):
            raise KeyError(key)
        if self.upns is not None and _is_upn(key):
            self.upns.discard(key)

    def __iter__(self):
        return iter(self.values_store.select())

    def __len__(self) -> int:
        return self.values_store.count()

    def items(self):
        return self.values_store.json_items().items()


def _load() -> dict:
    if record_documents.using_postgres():
        with _keyed().transaction(_migrate) as store:
            return {name: store.rows(name).json_items() for name in ("links", "codes", "conversations")}
    return _load_legacy()


def _write(data: dict) -> None:
    if not isinstance(data["links"], _SavedRows):
        record_documents.at(store_path()).write_text(json.dumps(data, indent=2, sort_keys=True))


@contextmanager
def _locked():
    """Serialize a Teams identity mutation and its one-time code consumption."""
    if record_documents.using_postgres():
        with _keyed().transaction(_migrate, write=True) as store:
            yield {name: _SavedRows(store, name) for name in ("links", "codes", "conversations")}
    else:
        with _LOCK, record_documents.at(store_path()).locked():
            yield _load_legacy()


def _prune_codes(data: dict, now: float) -> None:
    codes = data["codes"]
    for digest, row in list(codes.items()):
        if not isinstance(row, dict) or float(row.get("expires_at") or 0) <= now:
            codes.pop(digest)


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


def _describe_link(key: str, row: dict, reachable: bool) -> dict:
    return {"teams_id": key, "kind": "user principal name" if _is_upn(key) else "object id",
            "principal": str(row.get("principal") or ""), "linked_by": str(row.get("linked_by") or ""),
            "linked_at": float(row.get("linked_at") or 0), "can_be_reached": reachable}


def list_links() -> list[dict]:
    """Every link made by hand or by code, oldest first."""
    with _LOCK:
        data = _load()
    out = [_describe_link(key, row, key in data["conversations"])
           for key, row in data["links"].items() if isinstance(row, dict)]
    return sorted(out, key=lambda item: item["linked_at"])


def links_for_principal(principal: object) -> list[dict]:
    who = normalize_principal(principal)
    if record_documents.using_postgres():
        with _keyed().transaction(_migrate) as store:
            links = store.rows("links").json_items(tag=who)
            conversations = store.rows("conversations")
            out = [_describe_link(key, row, conversations.get(key) is not None)
                   for key, row in links.items() if isinstance(row, dict) and row.get("principal") == who]
        return sorted(out, key=lambda item: item["linked_at"])
    return [item for item in list_links() if item["principal"] == who]


def has_upn_links() -> bool:
    if record_documents.using_postgres():
        with _keyed().transaction(_migrate) as store:
            return store.rows("upns").count() != 0
    return any(item["kind"] == "user principal name" for item in list_links())


def _principal_in(links, candidates: list[str]) -> str | None:
    for key in candidates:
        row = links.get(key)
        if isinstance(row, dict) and row.get("principal"):
            return str(row["principal"])
    return None


def principal_for(*ids: object) -> str | None:
    """The user a link ties any of ``ids`` to, or ``None``. Links only."""
    candidates = _candidates(*ids)
    if not candidates:
        return None
    if record_documents.using_postgres():
        with _keyed().transaction(_migrate) as store:
            return _principal_in(_SavedRows(store, "links"), candidates)
    with _LOCK:
        return _principal_in(_load_legacy()["links"], candidates)


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


def _directory_principals(ids: list[str]) -> dict[str, str]:
    if not ids:
        return {}
    try:
        from maverick_dashboard import subject_directory

        from .oidc import oidc_enabled

        if not oidc_enabled():
            return {}
        return {key: f"user:{sub}" for key, sub in subject_directory.subjects_for(ids).items()}
    except Exception:  # an unreadable sign-in setting or record recognises nobody
        log.warning("teams: the sign-in directory could not be read", exc_info=True)
        return {}


def directory_principal(*ids: object) -> str | None:
    """Resolve the first identifier recognised by the Entra sign-in directory."""
    names = [name for value in ids if (name := str(value or "").strip())]
    if not names:
        return None
    matches = _directory_principals(names)
    return next((matches[name] for name in names if name in matches), None)


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
    if record_documents.using_postgres():
        with _keyed().transaction(_migrate) as store:
            ref = _SavedRows(store, "conversations").get(keys[0])
    else:
        with _LOCK:
            ref = _load_legacy()["conversations"].get(keys[0])
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
    candidates = {key: ref for key, ref in data["conversations"].items() if key not in people and isinstance(ref, dict)}
    for key, principal in _directory_principals(list(candidates)).items():
        people[key] = {"teams_id": key, "principal": principal, "conversation": candidates[key]}
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
