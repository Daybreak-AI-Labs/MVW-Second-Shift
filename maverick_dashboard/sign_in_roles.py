"""Roles from the sign-in token: an identity provider's app roles, mapped to roles here.

A person's role can come from the identity provider instead of being assigned
by hand. Microsoft Entra ID puts the app roles a person holds in the ``roles``
claim of the token it issues for this application; ``[auth.oidc.role_map]``
says which role each of those values stands for::

    [auth.oidc]
    role_claim = "roles"            # the default

    [auth.oidc.role_map]
    "SecondShift.Admin" = "admin"
    "SecondShift.GovernanceLead" = "governance_lead"

What this module does:

* reads those two settings (:func:`load_settings`). Only values named in the
  map count. An entry naming a role that does not exist is left out and logged
  once. A map that is not a table of text to text, or a claim name that is not
  text, turns the feature off entirely and is logged once. No map: nothing here
  has any effect and sign-in behaves as it did before;
* turns the claim of a VERIFIED token into one role (:func:`role_from_claims`),
  looking at no more than :data:`MAX_CLAIM_VALUES` values of at most
  :data:`MAX_VALUE_LENGTH` characters. Several mapped values: the role with the
  most permissions wins (:func:`strongest` documents the tie rule);
* attaches that role at the two places that verified the token: the browser
  sign-in callback keeps it in the signed session (:func:`session_extra`,
  :func:`from_session`), and the bearer check keeps it on that request's
  identity (:func:`with_token_role`);
* gives it back only for the caller of the request in hand (:func:`carried`,
  :func:`for_request`), and only while the settings still grant that role.

What it does not do:

* verify anything: callers pass claims that ``maverick.oidc.verify_oidc_token``
  already verified, or a session payload whose signature already checked;
* keep a record per person. The role lives in that person's own session or
  token and nowhere else, so a lookup with no request (background work) or
  about someone other than the caller finds none, and removing the app role at
  the identity provider takes effect at the person's next sign-in;
* outrank an administrator named in settings or a role stored for the person:
  ``auth.global_role_for_principal`` asks here only after both, and before the
  default role;
* log a token, a session or a claim value.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from maverick.oidc import VerifiedPrincipal

log = logging.getLogger(__name__)

# The claim Microsoft Entra ID uses for the app roles assigned to a person.
DEFAULT_ROLE_CLAIM = "roles"
# How much of the claim is looked at: values past the first MAX_CLAIM_VALUES
# and values longer than MAX_VALUE_LENGTH characters are not read.
MAX_CLAIM_VALUES = 64
MAX_VALUE_LENGTH = 256
_MAX_CLAIM_NAME_LENGTH = 128

# Where the role travels: a field of the signed session payload, and an entry
# in the claims of the request's verified identity.
CLAIM_KEY = "claim_role"

# One warning per distinct problem, however often the settings are read.
_WARNED: set[tuple] = set()
_MAX_WARNED = 256


class ClaimRole(str):
    """A role this module attached to a verified identity.

    A token's own claims are decoded from JSON and so are never of this type:
    a token that carries a claim named :data:`CLAIM_KEY` cannot name its own
    role. :func:`carried` accepts nothing else."""

    __slots__ = ()


@dataclass(frozen=True)
class Settings:
    """``[auth.oidc] role_claim`` and the usable entries of ``[auth.oidc.role_map]``.

    An empty ``role_map`` means no role is ever taken from a sign-in claim."""

    claim: str = DEFAULT_ROLE_CLAIM
    role_map: Mapping[str, str] = field(default_factory=dict)


def _warn_once(key: tuple, message: str, *args: object) -> None:
    if key in _WARNED or len(_WARNED) >= _MAX_WARNED:
        return
    _WARNED.add(key)
    log.warning(message, *args)


def _valid_claim_name(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value) <= _MAX_CLAIM_NAME_LENGTH and value == value.strip()


def _text_to_text(value: object) -> bool:
    return isinstance(value, dict) and all(
        isinstance(key, str) and key and isinstance(role, str) for key, role in value.items())


def load_settings() -> Settings:
    """The current sign-in role settings, installation-wide.

    Read from the deployment's own configuration, never a workspace's file.
    Settings that cannot be read, no map, or a malformed setting all give
    ``Settings()`` with an empty map: nothing is granted."""
    from maverick.config import config_source_errors, load_global_config

    tree = load_global_config()
    if config_source_errors(include_tenant=False):
        return Settings()  # the map may have been lost with the file
    auth = tree.get("auth") if isinstance(tree, dict) else None
    section = auth.get("oidc") if isinstance(auth, dict) else None
    if not isinstance(section, dict) or "role_map" not in section:
        return Settings()
    claim = section.get("role_claim", DEFAULT_ROLE_CLAIM)
    if not _valid_claim_name(claim):
        _warn_once(("claim",), "Sign-in roles are ignored: [auth.oidc] role_claim must be the name of one "
                               "claim, as text. No role is taken from sign-in until this is corrected.")
        return Settings()
    raw = section["role_map"]
    if not _text_to_text(raw):
        _warn_once(("map",), "Sign-in roles are ignored: [auth.oidc.role_map] must be a table that gives one "
                             "role name, as text, for each app role value. No role is taken from sign-in "
                             "until this is corrected.")
        return Settings(claim=claim)
    return Settings(claim=claim, role_map=_known_entries(raw))


def _known_entries(raw: dict[str, str]) -> dict[str, str]:
    """The entries whose role exists; each other entry is logged once and dropped."""
    from . import rbac

    known = {role: rbac.is_known_role(role) for role in set(raw.values())}
    for value, role in raw.items():
        if not known[role]:
            _warn_once(("role", value, role),
                       "Sign-in roles: the entry %r in [auth.oidc.role_map] is ignored because there is no "
                       "role named %r. Use a built-in role (%s) or a custom role by its exact name.",
                       value, role, ", ".join(rbac.ROLES))
    return {value: role for value, role in raw.items() if known[role]}


def strongest(roles: Iterable[str]) -> str | None:
    """The one role a person gets when several of their app roles are mapped.

    The role with the most permissions wins. A permission that only comes
    with another one the role holds is not counted (``approve`` and ``respond``
    come with ``operate``: ``rbac.IMPLIED_PERMISSIONS``), so roles compare as
    they did before those two existed. Roles with equally many are ordered
    built-in roles first, in the order of ``rbac.ROLES`` (so operator comes
    before approver, responder and auditor), then by name; the order of the
    values in the token never matters."""
    from . import rbac

    def rank(role: str) -> tuple[int, int, str]:
        built_in = rbac.ROLES.index(role) if role in rbac.ROLES else len(rbac.ROLES)
        held = rbac.permissions_for(role)
        came_with = frozenset().union(*(rbac.IMPLIED_PERMISSIONS.get(permission, ()) for permission in held))
        return -len(held - came_with), built_in, role

    return min(set(roles), key=rank, default=None)


def _claim_values(raw: object) -> list[str]:
    """The claim's values worth looking at: text, bounded in number and length."""
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return []
    return [value for value in raw[:MAX_CLAIM_VALUES]
            if isinstance(value, str) and 0 < len(value) <= MAX_VALUE_LENGTH]


def role_from_claims(claims: object) -> str | None:
    """The role a VERIFIED token's claim maps to, or ``None``.

    The claim may be a list or one string. Values match the map exactly. Never
    raises: when the role cannot be worked out, none is given."""
    if not isinstance(claims, Mapping):
        return None
    try:
        settings = load_settings()
        if not settings.role_map:
            return None
        values = _claim_values(claims.get(settings.claim))
        return strongest(settings.role_map[value] for value in values if value in settings.role_map)
    except Exception:  # noqa: BLE001 -- a role that cannot be worked out is no role
        _warn_once(("unavailable",), "Sign-in roles could not be worked out, so none was given. "
                                     "Check that the settings and the role list can be read.")
        return None


def session_extra(claims: object) -> dict[str, str]:
    """What the sign-in callback adds to the signed session: the mapped role,
    or nothing at all when the verified ID token maps to none."""
    role = role_from_claims(claims)
    return {CLAIM_KEY: role} if role else {}


def from_session(payload: Mapping[str, object]) -> ClaimRole | None:
    """The role the sign-in callback kept in this signed session, if any."""
    role = payload.get(CLAIM_KEY)
    return ClaimRole(role) if isinstance(role, str) and role else None


def with_token_role(principal: VerifiedPrincipal) -> VerifiedPrincipal:
    """The identity a bearer token just verified as, carrying the role that
    token's own claim maps to. Unchanged (the same object) when it maps to none."""
    role = role_from_claims(getattr(principal, "claims", None))
    if role is None:
        return principal
    return replace(principal, claims={**principal.claims, CLAIM_KEY: ClaimRole(role)})


def carried(request: object, principal: str | None) -> ClaimRole | None:
    """The claim role ``request``'s own caller carries, when ``principal`` is
    that caller. Reads no settings.

    ``None`` with no request (background work), when ``principal`` is anyone
    else, and when the caller's session or token carried no role. Only a role
    this module attached counts (:class:`ClaimRole`)."""
    if request is None or not principal:
        return None
    caller = getattr(getattr(request, "state", None), "principal", None)
    if getattr(caller, "principal", None) != principal:
        return None
    claims = getattr(caller, "claims", None)
    role = claims.get(CLAIM_KEY) if isinstance(claims, dict) else None
    return role if type(role) is ClaimRole else None


def for_request(request: object, principal: str | None) -> str | None:
    """The sign-in claim role that applies to ``request``'s own caller, when
    ``principal`` is that caller.

    What :func:`carried` finds, and only while the settings still give that
    role: ``None`` once its entry was removed, the map is malformed, or the
    role was deleted."""
    role = carried(request, principal)
    if role is None:
        return None
    return str(role) if role in load_settings().role_map.values() else None


__all__ = [
    "CLAIM_KEY",
    "DEFAULT_ROLE_CLAIM",
    "MAX_CLAIM_VALUES",
    "MAX_VALUE_LENGTH",
    "ClaimRole",
    "Settings",
    "carried",
    "for_request",
    "from_session",
    "load_settings",
    "role_from_claims",
    "session_extra",
    "strongest",
    "with_token_role",
]
