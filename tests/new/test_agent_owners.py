"""Matching a signed-in person to the agents they own."""
from __future__ import annotations

import pytest

from maverick.agent_owners import Identity, clean_email, identity_from_claims, owns

OID = "11111111-2222-3333-4444-555555555555"
OTHER = "99999999-2222-3333-4444-555555555555"


def _row(owner="jo@example.com", oid=""):
    return {"id": "a", "owner": owner, "owner_object_id": oid}


@pytest.mark.parametrize("claims, expected", [
    ({"email": "Jo@Example.com", "email_verified": True}, Identity("jo@example.com")),
    ({"email": "jo@example.com"}, Identity()),
    ({"email": "jo@example.com", "email_verified": False}, Identity()),
    ({"email": "jo@example.com", "email_verified": "true"}, Identity()),
    ({"upn": "jo@example.com", "preferred_username": "jo@example.com"}, Identity()),
    ({"oid": OID.upper()}, Identity("", OID)),
    ({"oid": "not-a-guid"}, Identity()),
    ({"via": "session", "verified_email": "Jo@Example.com"}, Identity("jo@example.com")),
    ({"via": "invite", "verified_email": "jo@example.com"}, Identity()),
    ({"verified_email": "jo@example.com"}, Identity()),
])
def test_what_a_sign_in_proves(claims, expected):
    assert identity_from_claims(claims) == expected


def test_a_trusted_proxy_identity_counts_only_as_an_email():
    assert identity_from_claims({"via": "proxy"}, issuer="proxy", subject="Jo@Example.com") == Identity("jo@example.com")
    assert identity_from_claims({"via": "proxy"}, issuer="proxy", subject="jo") == Identity()


@pytest.mark.parametrize("text", ["Jo Smith", "a@b", "a@example.com, b@example.com", "Jo <jo@example.com>", "", None, 5])
def test_only_a_plain_email_address_is_an_address(text):
    assert clean_email(text) == ""


def test_email_matches_without_regard_to_case():
    assert owns(_row("JO@Example.com"), Identity("jo@EXAMPLE.com".casefold()))
    assert not owns(_row("jo@example.com"), Identity("kim@example.com"))


def test_an_empty_identity_owns_nothing():
    assert not owns(_row(""), Identity())
    assert not owns(_row("jo@example.com"), Identity())


def test_object_id_decides_when_both_sides_have_one():
    assert owns(_row("jo@example.com", OID), Identity("", OID))
    assert owns(_row("old@example.com", OID), Identity("new@example.com", OID))
    assert not owns(_row("jo@example.com", OID), Identity("jo@example.com", OTHER))


def test_a_name_never_matches():
    assert not owns(_row("Jo Smith", OID), Identity("jo@example.com"))
