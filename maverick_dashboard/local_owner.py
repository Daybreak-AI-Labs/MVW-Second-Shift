"""A locally claimed owner account is not part of this product; sign-in is OpenID Connect."""
from __future__ import annotations


def claimed() -> bool:
    return False
