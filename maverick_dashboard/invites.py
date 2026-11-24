"""Invitation-based local accounts are not part of this product; sign-in is OpenID Connect."""
from __future__ import annotations


def invites_enabled() -> bool:
    return False


def local_login_mode() -> bool:
    return False


def local_session_secret() -> str:
    return ""


def local_session_principal(request):
    return None
