"""The name and verified email a person's sign-in reports, by sign-in.

People read as people in approvals, settings history and the Activity log
(:mod:`person_names`), not as "Google account". Company sign-in (OIDC) keeps
here, at every sign-in, only two facts the identity provider sent in the
verified ID token: the email when the provider marks it verified, and the
display name. Nothing else from the token is kept, and a sign-in that sends
neither removes the record.

Store: ``<maverick_home>/account-profiles.json`` (0600), one installation-wide
file keyed by sign-in, written atomically under a cross-process lock and
sealed with the deployment key when at-rest encryption is on. With Postgres as the
main database it is kept as one row per sign-in, sealed with the same key. Bounded to
``_MAX_ENTRIES`` by last sign-in. It grants nothing: it only names people
where they are already shown. My data exports it and its reviewed deletion
erases it; deleting the account in the company directory (SCIM) erases it too.

``[auth] remember_account_names`` (``MAVERICK_REMEMBER_ACCOUNT_NAMES``),
default on: off stops recording and naming; kept records stay exportable and
erasable.
"""
from __future__ import annotations

import json
import os
import threading
import time
import unicodedata
from contextlib import contextmanager
from pathlib import Path

from maverick import keyed_records, record_documents
from maverick.paths import maverick_home

_MAX_ENTRIES = 50_000
_MAX_TEXT = 200
_LOCK = threading.Lock()
_FALSE = {"0", "false", "no", "off"}


def _path() -> Path:
    return maverick_home() / "account-profiles.json"


def enabled() -> bool:
    raw = os.environ.get("MAVERICK_REMEMBER_ACCOUNT_NAMES", "").strip().lower()
    if raw:
        return raw not in _FALSE
    try:
        from maverick.config import config_source_errors, load_global_config

        if config_source_errors(include_tenant=False):
            return False  # unreadable settings: collect nothing
        value = (load_global_config().get("auth") or {}).get("remember_account_names", True)
    except Exception:  # noqa: BLE001 -- unreadable settings: collect nothing
        return False
    return value is not False


@contextmanager
def _locked():
    with _LOCK, record_documents.at(_path()).locked():
        yield


def _read_legacy() -> dict[str, dict]:
    from maverick import crypto_at_rest

    if record_documents.using_postgres():
        text = record_documents.at(_path()).read_text()
        if text is None:
            return {}
        if crypto_at_rest.is_sealed_str(text):
            with crypto_at_rest.deployment_key_scope():
                text = crypto_at_rest.unseal_from_str(text)
        raw = text.encode("utf-8")
    else:
        try:
            raw = _path().read_bytes()
        except FileNotFoundError:
            return {}
    if crypto_at_rest.is_sealed(raw):
        with crypto_at_rest.deployment_key_scope():
            raw = crypto_at_rest.unseal(raw)
    data = json.loads(raw.decode("utf-8"))
    profiles = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(profiles, dict):
        raise ValueError("The account name record is not readable.")
    return profiles


def _keyed() -> keyed_records.KeyedRecords:
    return keyed_records.KeyedRecords(_path())


def _encode(profile: dict) -> str:
    from maverick import crypto_at_rest

    text = json.dumps(profile, sort_keys=True)
    if crypto_at_rest.deployment_at_rest_enabled():
        with crypto_at_rest.deployment_key_scope():
            return crypto_at_rest.seal_to_str(text)
    return text


def _decode(text: str) -> dict:
    from maverick import crypto_at_rest

    if crypto_at_rest.is_sealed_str(text):
        with crypto_at_rest.deployment_key_scope():
            text = crypto_at_rest.unseal_from_str(text)
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("The account name record is not readable.")
    return data


def _migrate(collection: keyed_records.Collection) -> None:
    collection.rows("people").seed((principal, _encode(value), "", float(value.get("at", 0)))
                                   for principal, value in _read_legacy().items())


def _read() -> dict[str, dict]:
    if record_documents.using_postgres():
        with _keyed().transaction(_migrate) as store:
            return {key: _decode(body) for key, body in store.rows("people").select().items()}
    return _read_legacy()


def _record_keyed(principal: str, current: dict) -> None:
    with _keyed().transaction(_migrate, write=True) as store:
        people = store.rows("people")
        before = people.get(principal)
        if not (current["email"] or current["name"]):
            people.discard(principal)
            return
        now = time.time()
        if before is not None:
            previous = _decode(before)
            if all(previous.get(key) == value for key, value in current.items()) and now - float(previous.get("at", 0)) < 86_400:
                return
        people.put(principal, _encode({**current, "at": now}), stamp=now)
        people.trim(_MAX_ENTRIES)


def _write(profiles: dict[str, dict]) -> None:
    from maverick import crypto_at_rest

    if len(profiles) > _MAX_ENTRIES:
        newest = sorted(profiles, key=lambda key: profiles[key].get("at", 0), reverse=True)[:_MAX_ENTRIES]
        profiles = {key: profiles[key] for key in newest}
    payload = json.dumps({"schema": 1, "profiles": profiles}, sort_keys=True).encode("utf-8")
    from maverick.file_lock import atomic_write_bytes, ensure_private_directory

    if crypto_at_rest.deployment_at_rest_enabled():
        with crypto_at_rest.deployment_key_scope():
            payload = crypto_at_rest.seal(payload)
    ensure_private_directory(maverick_home())
    atomic_write_bytes(_path(), payload, mode=0o600)


def _text(value: object) -> str:
    """One readable line: no control or format characters, bounded."""
    if not isinstance(value, str):
        return ""
    kept = "".join(" " if unicodedata.category(char).startswith(("C", "Z")) else char for char in value)
    return " ".join(kept.split())[:_MAX_TEXT]


def from_claims(claims: dict) -> dict[str, str]:
    """The verified email and display name in verified ID-token claims."""
    from .oidc_login import _oidc_permission_email

    name = _text(claims.get("name")) or _text(" ".join(
        _text(claims.get(key)) for key in ("given_name", "family_name")))
    return {"email": _oidc_permission_email(claims), "name": name}


def record_sign_in(principal: str, claims: dict) -> None:
    """Keep what this sign-in reported; a sign-in with neither removes it."""
    if not isinstance(principal, str) or not principal.startswith("user:") or not enabled():
        return
    current = from_claims(claims or {})
    if record_documents.using_postgres():
        _record_keyed(principal, current)
        return
    with _locked():
        profiles = _read_legacy()
        before = profiles.get(principal)
        if not (current["email"] or current["name"]):
            if before is None:
                return
            profiles.pop(principal)
        else:
            if before and {key: before.get(key) for key in current} == current \
                    and time.time() - float(before.get("at", 0)) < 86_400:
                return  # unchanged and recent: no write on every sign-in
            profiles[principal] = {**current, "at": time.time()}
        _write(profiles)
