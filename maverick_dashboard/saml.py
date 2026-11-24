"""SAML sign-in is not part of this product; sign-in is OpenID Connect."""
from __future__ import annotations


def saml_enabled() -> bool:
    return False


def _session_secret() -> str:
    return ""
