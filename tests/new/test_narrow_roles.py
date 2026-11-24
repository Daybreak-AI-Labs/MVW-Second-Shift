"""The two narrow roles: an approver only decides approvals, a responder only stops agents.

Two permissions sit beside ``operate``: ``approve`` (decide a request waiting
for a person) and ``respond`` (suspend, resume and limit agents, the emergency
stop where an operator may use it, and acknowledging or re-checking drift).
``operate`` carries both, so everyone who could do these things before still
can; ``approver`` and ``responder`` hold one each and nothing else but view.

Hermetic. Each person signs in with a token minted here and checked by the
real ``maverick.oidc.verify_oidc_token`` against a stand-in key endpoint, and
every answer comes from the real routes of the web app. A person's role is
stored in the role list, as an administrator would assign it, or comes from
their own sign-in token where a test says so.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

jwt = pytest.importorskip("jwt", reason="sign-in needs PyJWT")
rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")

ISSUER = "https://login.example.test/contoso/v2.0"
AUDIENCE = "app-client-id"
SESSION_SECRET = "unit-test-session-secret"  # pragma: allowlist secret
ACP = "/api/v1/agent-control-plane"
AGENT = "helpdesk"

#: Custom roles, as an administrator stored them. ``legacy-ops`` is a role
#: stored before ``approve`` and ``respond`` existed: it names ``operate`` only.
CUSTOM_ROLES = {
    "approvals-desk": ["approve", "view"],
    "response-desk": ["respond", "view"],
    "legacy-ops": ["operate", "view"],
}
#: Who signs in, and the role stored for each of them.
PEOPLE = {
    "approver": "approver",
    "responder": "responder",
    "operator": "operator",
    "lead": "governance_lead",
    "auditor": "auditor",
    "viewer": "viewer",
    "desk-approve": "approvals-desk",
    "desk-respond": "response-desk",
    "legacy": "legacy-ops",
    "boss": "admin",
}
MAY_APPROVE = {"approver", "operator", "lead", "desk-approve", "legacy", "boss"}
MAY_RESPOND = {"responder", "operator", "lead", "desk-respond", "legacy", "boss"}
MAY_AUDIT = {"lead", "auditor", "boss"}
EVERYONE = sorted(PEOPLE)
NOT_ADMIN = sorted(set(PEOPLE) - {"boss"})

SUSPENDED = "user:paused-earlier"
SELECTION = {"schema": "second-shift.agent-control-plane-selection.v1", "tenant": "tenant-a", "platform": None,
             "principals": ["user:fleet-one"], "snapshot_sha256": "a" * 64, "captured_at": 123.0}


def _respond_actions() -> dict[str, tuple[str, dict]]:
    """Every agent control action a responder may take: name -> (path, body)."""
    return {
        "suspend": (f"{ACP}/principals/suspend", {"principal": "user:someone", "reason": "incident"}),
        "resume": (f"{ACP}/principals/resume", {"principal": "user:someone"}),
        "limit": (f"{ACP}/principals/attenuate", {"principal": "user:someone", "max_risk": "low"}),
        "suspend, by address": (f"{ACP}/agents/user:someone/suspend", {"reason": "incident"}),
        "resume, by address": (f"{ACP}/agents/user:someone/resume", {}),
        "limit, by address": (f"{ACP}/agents/user:someone/attenuate", {"max_risk": "low"}),
        "choose a group": (f"{ACP}/bulk/select", {"tenant": "tenant-a"}),
        "suspend a group": (f"{ACP}/bulk/actions", {"selection": SELECTION, "verb": "suspend", "reason": "incident"}),
        "resume a group": (f"{ACP}/bulk/actions", {"selection": SELECTION, "verb": "resume"}),
    }


def _administrator_actions() -> dict[str, tuple[str, dict]]:
    """What stays with an administrator, as before: name -> (path, body)."""
    return {
        "isolate": (f"{ACP}/principals/contain", {"principal": "user:someone", "reason": "incident"}),
        "isolate for a set time": (f"{ACP}/principals/contain-timeboxed", {
            "principal": "user:someone", "reason": "incident", "release_after_seconds": 60, "idempotency_key": "k-1"}),
        "end isolation": (f"{ACP}/principals/release", {"principal": "user:someone"}),
        "isolate, by address": (f"{ACP}/agents/user:someone/contain", {"reason": "incident"}),
        "end isolation, by address": (f"{ACP}/agents/user:someone/release", {}),
        "isolate a group": (f"{ACP}/bulk/actions", {"selection": SELECTION, "verb": "contain", "reason": "incident"}),
        "end a group's isolation": (f"{ACP}/bulk/actions", {"selection": SELECTION, "verb": "release"}),
        "run due releases": (f"{ACP}/timeboxes/sweep", {}),
        "enroll an agent": ("/api/v1/external-agents", {"id": "second", "platform": "copilot", "owner": "ops@example.com"}),
        "create an access key": (f"/api/v1/external-agents/{AGENT}/credentials", {"surface": "rest"}),
        "approve a drift baseline": (f"/api/v1/external-agents/{AGENT}/drift/baseline", {"force": True}),
        "let a blocked agent work again": (f"/api/v1/external-agents/{AGENT}/release", {}),
        "reset an agent's spending": (f"/api/v1/external-agents/{AGENT}/reset-budget", {}),
        "block an agent": (f"/api/v1/trust/agents/{AGENT}/revoke", {"revoked": True}),
        "check the platforms now": ("/api/v1/agent-watch/sync", {}),
        "send a test alert": ("/api/v1/alerts/test", {}),
    }


# ----------------------------------------------------------------- the installation

@pytest.fixture(scope="module")
def signing_key():
    """The identity provider's key pair."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def installation(tmp_path, monkeypatch, request, signing_key):
    """One installation with sign-in on, agent controls on and its own files."""
    from maverick import _oidc_jwks, config, killswitch, revocation, world_model
    from maverick.audit import signing
    from maverick_dashboard import oidc_login, sign_in_roles

    # The posture CI asks for (tests/new/test_sign_in_roles.py does the same):
    # under the production posture the activity record is signed, with a key
    # that is read once per process, so it is set and forgotten per test.
    secure = os.environ.get("MAVERICK_TEST_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", secure)
    if secure.strip().lower() in {"1", "true", "yes", "on"}:
        seed = f"narrow-roles-test:{request.node.nodeid}".encode()
        monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(seed).hexdigest())
    signing._reset_injected_keypair_cache()

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    for name, value in {
        "MAVERICK_OIDC_ENABLED": "1", "MAVERICK_OIDC_ISSUER": ISSUER, "MAVERICK_OIDC_AUDIENCE": AUDIENCE,
        "MAVERICK_OIDC_JWKS_URI": "https://login.example.test/contoso/keys",
        "MAVERICK_OIDC_CLIENT_ID": AUDIENCE, "MAVERICK_OIDC_CLIENT_SECRET": "test-client-secret",  # pragma: allowlist secret
        "MAVERICK_OIDC_REDIRECT_URI": "http://127.0.0.1/auth/callback",
        "MAVERICK_OIDC_SESSION_SECRET": SESSION_SECRET,
        "MAVERICK_OIDC_AUTHORIZATION_ENDPOINT": "https://login.example.test/contoso/authorize",
        "MAVERICK_OIDC_TOKEN_ENDPOINT": "https://login.example.test/contoso/token",
        "MAVERICK_CONTROL_PLANE": "1", "MAVERICK_EXTERNAL_AGENTS": "1",
        "MAVERICK_HALT_FILE": str(tmp_path / "HALT"),
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_ADMINS", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT", "MAVERICK_TENANT_BY_USER", "MAVERICK_MFA_REQUIRE",
                 "MAVERICK_SEPARATE_APPROVER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")

    class KeyEndpoint:
        """The provider's published signing key, without the network."""

        def __init__(self, uri, **kwargs):
            pass

        def get_signing_keys(self, *, refresh):
            return [SimpleNamespace(key_id="k1", key=signing_key.public_key())]

    monkeypatch.setattr(jwt, "PyJWKClient", KeyEndpoint)

    def forget():
        _oidc_jwks._resolvers.clear()
        oidc_login._CONSUMED_TX_IDS.clear()
        sign_in_roles._WARNED.clear()
        config.reset_config_cache()
        revocation.reset_shared()
        killswitch._last_file_check_ts = 0.0
        killswitch._last_file_present = False

    forget()
    _write_roles()
    yield tmp_path
    try:
        killswitch.clear()
    except Exception:  # noqa: BLE001 -- the emergency stop file lives in this test's own folder
        pass
    signing._reset_injected_keypair_cache()
    forget()


def _write_private(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def _write_roles(people: dict[str, str] | None = None, custom: dict[str, list[str]] | None = None) -> None:
    """Store the custom roles and each person's role, as the Users page would."""
    from maverick_dashboard import rbac

    custom = CUSTOM_ROLES if custom is None else custom
    people = PEOPLE if people is None else people
    _write_private(rbac.custom_roles_path(), json.dumps(
        {name: {"permissions": permissions, "description": ""} for name, permissions in custom.items()}))
    _write_private(rbac.store_path(), json.dumps({f"user:{person}": role for person, role in people.items()}))


def _configure(tmp_path, body: str) -> None:
    from maverick import config

    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    config.reset_config_cache()


@pytest.fixture
def token(signing_key):
    """Mint a token as the identity provider would."""
    def mint(sub, **claims):
        now = int(time.time())
        body = {"sub": sub, "iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 600, **claims}
        return jwt.encode(body, signing_key, algorithm="RS256", headers={"kid": "k1"})
    return mint


@pytest.fixture
def app():
    from maverick_dashboard.app import app

    return app


@pytest.fixture
def signed_in(app, token):
    """A client for one signed-in person; their role is whatever is stored for them."""
    def client(person: str, **claims) -> TestClient:
        return TestClient(app, base_url="http://127.0.0.1", headers={
            "Origin": "http://127.0.0.1", "Authorization": "Bearer " + token(person, **claims)})
    return client


@pytest.fixture
def world(app):
    from maverick_dashboard._shared import _world

    return _world()


@pytest.fixture
def agent(app, signed_in):
    """An enrolled outside agent's own view: a client that carries only its access key."""
    boss = signed_in("boss")
    enrolled = boss.post("/api/v1/external-agents", json={
        "id": AGENT, "platform": "copilot", "owner": "ops@example.com", "max_risk": "high"})
    assert enrolled.status_code == 201, enrolled.text
    minted = boss.post(f"/api/v1/external-agents/{AGENT}/credentials", json={"surface": "rest"})
    assert minted.status_code == 200, minted.text
    return TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {minted.json()['token']}"})


def _park(agent, tool="send_contract") -> dict:
    """The agent asks to do something risky; the request waits for a person."""
    parked = agent.post("/api/v1/external/screen", json={"tool": tool, "risk": "high"}).json()
    assert parked["requires_approval"] is True, parked
    return parked


def _status(agent, parked) -> str:
    """What the agent is told about its request."""
    return agent.get(f"/api/v1/external/approvals/{parked['approval_id']}",
                     params={"binding_sha256": parked["approval_binding_sha256"]}).json()["status"]


def _approve(client, parked):
    return client.post(f"/api/v1/approvals/{parked['approval_id']}/approve", json={"acknowledged": True},
                       headers={"X-Second-Shift-Approval-Binding": parked["approval_binding_sha256"]})


def _reject(client, parked):
    return client.post(f"/api/v1/approvals/{parked['approval_id']}/deny", json={"reason": "Not now"})


def _suspended(principal: str) -> bool:
    from maverick.revocation import is_revoked

    return is_revoked(principal)


def _stopped(client) -> bool:
    return client.get("/api/v1/halt").json()["active"]


# ----------------------------------------------------------------- the permissions

def test_each_built_in_role_holds_exactly_these_permissions():
    from maverick_dashboard import rbac

    assert rbac.ROLES == ("admin", "governance_lead", "operator", "approver", "responder", "auditor", "viewer")
    assert rbac.PERMISSION_ATOMS == ("admin", "audit", "operate", "approve", "respond", "view")
    assert {role: rbac.permissions_for(role) for role in rbac.ROLES} == {
        "admin": frozenset({"admin", "audit", "operate", "approve", "respond", "view"}),
        "governance_lead": frozenset({"audit", "operate", "approve", "respond", "view"}),
        "operator": frozenset({"operate", "approve", "respond", "view"}),
        "approver": frozenset({"approve", "view"}),
        "responder": frozenset({"respond", "view"}),
        "auditor": frozenset({"audit", "view"}),
        "viewer": frozenset({"view"}),
    }
    assert all(rbac.is_known_role(role) for role in rbac.ROLES)


def test_the_two_roles_and_permissions_read_in_plain_words():
    from maverick_dashboard.identity_format import permission_label, role_label

    assert role_label("approver") == "Approver" and role_label("responder") == "Responder"
    assert role_label("governance_lead") == "Governance lead" and role_label("operator") == "Operator"  # as before
    assert permission_label("approve") == "Decide approvals"
    assert permission_label("respond") == "Stop and resume agents"
    assert permission_label("operate") == "Run work"  # as before


def test_operate_always_carries_approve_and_respond():
    """One rule, applied where a role's permissions are produced: no role, built
    in or custom, holds ``operate`` without the two."""
    from maverick_dashboard import rbac

    assert rbac.IMPLIED_PERMISSIONS == {"operate": frozenset({"approve", "respond"})}
    holders = [role for role in (*rbac.ROLES, *CUSTOM_ROLES) if "operate" in rbac.permissions_for(role)]
    assert holders == ["admin", "governance_lead", "operator", "legacy-ops"]
    for role in holders:
        assert {"approve", "respond"} <= rbac.permissions_for(role), role
    assert rbac.permissions_for("legacy-ops") == frozenset({"operate", "approve", "respond", "view"})
    # The narrow permissions carry nothing: not each other, and never operate.
    assert rbac.permissions_for("approvals-desk") == frozenset({"approve", "view"})
    assert rbac.permissions_for("response-desk") == frozenset({"respond", "view"})
    assert rbac.permissions_for("approver").isdisjoint({"operate", "respond", "audit", "admin"})
    assert rbac.permissions_for("responder").isdisjoint({"operate", "approve", "audit", "admin"})


@pytest.mark.parametrize("role", ["", None, "nobody", "Approver", "approver ", "APPROVER", "approve", "respond"])
def test_a_role_that_does_not_exist_holds_nothing(role):
    from maverick_dashboard import rbac

    assert rbac.permissions_for(role) == frozenset()


@pytest.mark.parametrize("name", ["approver", "responder"])
def test_a_custom_role_cannot_take_either_new_name(name):
    from maverick_dashboard import rbac

    with pytest.raises(rbac.RbacStoreError, match="built-in"):
        rbac._validate_custom_role(name, {"permissions": ["admin", "view"]})


def test_a_custom_role_may_be_built_from_the_two_new_permissions():
    from maverick_dashboard import rbac

    name, record = rbac._validate_custom_role("night-desk", {"permissions": ["view", "respond", "approve"]})
    assert name == "night-desk" and record["permissions"] == ["approve", "respond", "view"]
    for bad in (["approve"], ["approve", "approve", "view"], ["approves", "view"], ["respond", "stop", "view"]):
        with pytest.raises(rbac.RbacStoreError):
            rbac._validate_custom_role("night-desk", {"permissions": bad})


# ----------------------------------------------------------------- approvals

@pytest.mark.parametrize("person", EVERYONE)
def test_who_may_see_and_count_the_requests_that_wait(person, signed_in, agent):
    parked = _park(agent)
    client = signed_in(person)
    listed = client.get("/api/v1/approvals")
    counted = client.get("/api/v1/approvals/waiting-count")
    state = client.get(f"/api/v1/approvals/{parked['approval_id']}/state")
    if person in MAY_APPROVE:
        assert listed.status_code == 200, listed.text
        assert [row["id"] for row in listed.json()["approvals"]] == [parked["approval_id"]]
        assert listed.json()["private_count"] == 0
        assert counted.json() == {"waiting": 1}
        assert state.status_code == 200 and state.json()["status"] == "pending"
    else:
        assert (listed.status_code, counted.status_code, state.status_code) == (403, 403, 403)
        assert "approvals" not in listed.text and "waiting" not in counted.text


@pytest.mark.parametrize("person", EVERYONE)
def test_who_may_approve(person, signed_in, agent):
    parked = _park(agent)
    answer = _approve(signed_in(person), parked)
    if person in MAY_APPROVE:
        assert answer.status_code == 204, answer.text
        assert answer.headers["X-Second-Shift-Approval-State"] == "approved"
        assert _status(agent, parked) == "approved"
    else:
        assert answer.status_code == 403, answer.text
        assert _status(agent, parked) == "pending"


@pytest.mark.parametrize("person", EVERYONE)
def test_who_may_reject(person, signed_in, agent):
    parked = _park(agent)
    answer = _reject(signed_in(person), parked)
    if person in MAY_APPROVE:
        assert answer.status_code == 204, answer.text
        assert _status(agent, parked) == "denied"
    else:
        assert answer.status_code == 403, answer.text
        assert _status(agent, parked) == "pending"


def test_an_approver_still_meets_every_rule_of_a_decision(signed_in, agent):
    """The narrow role changes who may decide, not how: the acknowledgement and
    the exact request the person saw are still required."""
    parked = _park(agent)
    approver = signed_in("approver")
    address = f"/api/v1/approvals/{parked['approval_id']}/approve"
    binding = {"X-Second-Shift-Approval-Binding": parked["approval_binding_sha256"]}
    assert approver.post(address, json={}, headers=binding).status_code in (400, 409, 422)
    assert approver.post(address, json={"acknowledged": True}).status_code == 409
    assert approver.post(address, json={"acknowledged": True},
                         headers={"X-Second-Shift-Approval-Binding": "b" * 64}).status_code == 409
    assert _status(agent, parked) == "pending"
    assert approver.post(address, json={"acknowledged": True}, headers=binding).status_code == 204
    assert _status(agent, parked) == "approved"


def test_the_people_who_could_decide_are_the_people_who_may_approve(world, agent):
    from maverick_dashboard import approval_decisions

    parked = _park(agent)
    approval = world.get_approval(parked["approval_id"])
    assert approval_decisions.eligible_approvers(world, approval) == {f"user:{person}" for person in MAY_APPROVE}
    assert approval_decisions.other_eligible_approvers(world, approval, "user:approver") == sorted(
        f"user:{person}" for person in MAY_APPROVE - {"approver"})


def _request_of(bearer: str) -> Request:
    """A real request, signed in by the real request check."""
    from maverick_dashboard import auth

    scope = {"type": "http", "method": "GET", "path": "/api/v1/approvals", "scheme": "http",
             "headers": [(b"host", b"127.0.0.1"), (b"authorization", f"Bearer {bearer}".encode())],
             "query_string": b"", "server": ("127.0.0.1", 80), "client": ("127.0.0.1", 1234)}
    request = Request(scope)
    asyncio.run(auth.require_principal_in_request_context(request=request))
    return request


def test_an_outside_agents_request_opens_only_to_people_who_may_decide(world, agent, token):
    """The rule that opens an outside agent's request, asked on its own: the
    routes check the permission first, and this check agrees with them."""
    from maverick_dashboard import auth, content_access

    approval = world.get_approval(_park(agent)["approval_id"])
    for person in EVERYONE:
        request = _request_of(token(person))
        assert auth.caller_role(request) == PEOPLE[person]
        assert auth.has_permission(request, "approve") is (person in MAY_APPROVE), person
        assert auth.has_permission(request, "respond") is (person in MAY_RESPOND), person
        assert auth.has_global_permission(request, "respond") is (person in MAY_RESPOND), person
        assert content_access.can_read_approval(request, approval, world) is (person in MAY_APPROVE), person
    assert content_access.approval_readers(approval, world) == {f"user:{person}" for person in PEOPLE}


def test_a_reviewed_read_of_private_work_still_needs_the_right_to_decide(installation, world, token, monkeypatch):
    """A request that is one employee's own work opens to someone else only
    through a reviewed, unexpired read of exactly that request, and only if
    that person may decide approvals: a responder's identical read opens nothing."""
    from maverick_dashboard import content_access

    _configure(installation, "[features]\nemployee_content_access_requests = true\n")
    approval_id = world.create_approval("records.update", risk="low", scope="#save", detail="Save the setting",
                                        requested_by="user:operator")
    approval = world.get_approval(approval_id)
    resource = content_access.approval_resource(approval, world)

    def read_for(person: str) -> dict:
        return {"id": f"ECA-{person}", "tenant": content_access.tenant(), "owner": resource["owner"],
                "requester": f"user:{person}", "resource_kind": "approval", "resource_id": resource["resource_id"],
                "resource_revision": resource["resource_revision"], "status": "approved", "purpose": "review",
                "expires_at": time.time() + 600, "reviewed_by": "user:boss"}

    monkeypatch.setattr(content_access.STORE, "list", lambda: [read_for("approver"), read_for("responder")])
    assert content_access.can_read_approval(_request_of(token("operator")), approval, world) is True   # their own
    assert content_access.can_read_approval(_request_of(token("approver")), approval, world) is True
    assert content_access.can_read_approval(_request_of(token("responder")), approval, world) is False
    assert content_access.can_read_approval(_request_of(token("desk-approve")), approval, world) is False  # no read
    assert content_access.can_read_approval(_request_of(token("lead")), approval, world) is False          # no read


def _own_high_risk_request(world, person: str) -> tuple[int, dict]:
    """A high-risk request about an outside agent that ``person`` asked for: its id and the binding header."""
    from maverick.approval_cards import build_approval_card, encode_approval_detail

    card = build_approval_card(
        action="external:helpdesk:send_contract", summary="Send the signed contract",
        target_label="Contract 81234", target={"contract": "81234"}, parameters={}, parameter_summary=["Send it once"],
        actor=f"user:{person}", workspace="local", role="approver",
        authority_versions={"role_revision": "role-v1"}, input_versions={"contract_revision": "v1"},
        credential_versions={"session_sha256": "a" * 64}, budget={"currency": "USD", "maximum": 0.25},
        expires_at=time.time() + 300, known_effects=["Sends the contract."], unresolved_assumptions=[],
        before="Not sent.", after="Sent.", irreversible=True)
    approval_id = world.create_approval("external:helpdesk:send_contract", risk="high", scope="send_contract",
                                        detail=encode_approval_detail(card), provenance="external_agents",
                                        requested_by=f"user:{person}")
    return approval_id, {"X-Second-Shift-Approval-Binding": card["binding_sha256"]}


def test_a_responder_is_not_someone_else_who_could_approve(world, signed_in):
    """The person who asked for a high-risk action leaves it to someone else
    whenever someone else could decide it. A responder cannot, so they do not
    count; another approver does."""
    _write_roles({"approver": "approver", "responder": "responder", "viewer": "viewer", "auditor": "auditor"})
    alone, binding = _own_high_risk_request(world, "approver")
    approver = signed_in("approver")
    state = approver.get(f"/api/v1/approvals/{alone}/state").json()
    assert state["requested_by_you"] is True and state["self_approval_counts"] is True
    approved = approver.post(f"/api/v1/approvals/{alone}/approve", json={"acknowledged": True}, headers=binding)
    assert approved.status_code == 204, approved.text

    _write_roles({"approver": "approver", "responder": "responder", "desk-approve": "approvals-desk"})
    shared, binding = _own_high_risk_request(world, "approver")
    state = approver.get(f"/api/v1/approvals/{shared}/state").json()
    assert state["self_approval_counts"] is False and state["own_request_note"]
    page = approver.get("/approvals").text
    assert state["own_request_note"] in page  # the page says why its Approve button is off
    refused = approver.post(f"/api/v1/approvals/{shared}/approve", json={"acknowledged": True}, headers=binding)
    assert refused.status_code == 403 and world.get_approval(shared).status == "pending"
    other = signed_in("desk-approve").post(
        f"/api/v1/approvals/{shared}/approve", json={"acknowledged": True}, headers=binding)
    assert other.status_code == 204, other.text
    assert world.get_approval(shared).status == "approved"


def test_a_refused_decision_is_written_to_the_activity_record(signed_in, agent, monkeypatch):
    from maverick import audit

    seen = []
    real = audit.audit_event

    def remember(kind, **fields):
        seen.append((kind, fields))
        return real(kind, **fields)

    monkeypatch.setattr(audit, "audit_event", remember)
    parked = _park(agent)
    assert _approve(signed_in("responder"), parked).status_code == 403
    denied = [fields for kind, fields in seen if kind == audit.EventKind.CAPABILITY_DENIED]
    assert [(row["principal"], row["action"], row["reason"]) for row in denied] == [
        ("user:responder", "approval.approve", "approval_authority_missing")]


# ----------------------------------------------------------------- agent controls

@pytest.mark.parametrize("person", EVERYONE)
def test_who_may_use_the_agent_controls(person, signed_in):
    client = signed_in(person)
    for name, (path, body) in _respond_actions().items():
        answer = client.post(path, json=body)
        if person in MAY_RESPOND:
            assert answer.status_code != 403, (name, answer.text)
            assert answer.status_code < 500, (name, answer.status_code, answer.text)
        else:
            assert answer.status_code == 403, (name, answer.status_code, answer.text)
    assert _suspended("user:someone") is False  # everyone allowed to suspend also resumed


@pytest.mark.parametrize("person", EVERYONE)
def test_suspending_and_resuming_take_effect_only_for_people_who_may_respond(person, signed_in):
    client = signed_in(person)
    suspended = client.post(f"{ACP}/principals/suspend", json={"principal": "user:target", "reason": "incident"})
    if person in MAY_RESPOND:
        assert suspended.status_code == 200, suspended.text
        assert _suspended("user:target") is True
        assert client.post(f"{ACP}/principals/resume", json={"principal": "user:target"}).status_code == 200
        assert _suspended("user:target") is False
    else:
        assert suspended.status_code == 403
        assert _suspended("user:target") is False
        # Nor can they undo what someone else did.
        assert signed_in("responder").post(
            f"{ACP}/principals/suspend", json={"principal": SUSPENDED, "reason": "incident"}).status_code == 200
        assert client.post(f"{ACP}/principals/resume", json={"principal": SUSPENDED}).status_code == 403
        assert client.post(f"{ACP}/agents/{SUSPENDED}/resume").status_code == 403
        assert _suspended(SUSPENDED) is True


@pytest.mark.parametrize("person", NOT_ADMIN)
def test_what_stays_with_an_administrator(person, signed_in, agent):
    """Isolating an agent and ending its isolation, enrolling agents, access
    keys and the drift baseline needed an administrator before and still do:
    neither new permission, nor ``operate``, reaches them."""
    client = signed_in(person)
    for name, (path, body) in _administrator_actions().items():
        answer = client.post(path, json=body)
        assert answer.status_code == 403, (name, answer.status_code, answer.text)
    assert client.delete(f"/api/v1/external-agents/{AGENT}").status_code == 403
    assert signed_in("boss").get(f"/api/v1/external-agents/{AGENT}").status_code == 200  # still enrolled


def test_an_administrator_can_still_do_all_of_it(signed_in, agent):
    boss = signed_in("boss")
    for name, (path, body) in _administrator_actions().items():
        answer = boss.post(path, json=body)
        assert answer.status_code != 403, (name, answer.text)


@pytest.mark.parametrize("person", EVERYONE)
def test_reading_the_agent_controls_is_as_it_was(person, signed_in):
    client = signed_in(person)
    assert client.get(f"{ACP}/status").status_code == 200
    assert client.get(f"{ACP}/agents").status_code == 200
    expected = 200 if person in MAY_AUDIT else 403
    assert client.get(f"{ACP}/timeboxes").status_code == expected
    assert client.get(f"{ACP}/principals/ledger", params={"principal": "user:someone"}).status_code == expected


# ----------------------------------------------------------------- the emergency stop

@pytest.mark.parametrize("person", EVERYONE)
def test_who_may_raise_and_lift_the_emergency_stop(person, signed_in):
    client = signed_in(person)
    raised = client.post("/api/v1/halt", json={"reason": "incident"})
    if person in MAY_RESPOND:
        assert raised.status_code == 204, raised.text
        assert _stopped(client) is True
        assert client.delete("/api/v1/halt").status_code == 204
        assert _stopped(client) is False
    else:
        assert raised.status_code == 403, raised.text
        assert _stopped(client) is False
        # Nor can they lift a stop someone else raised.
        assert signed_in("responder").post("/api/v1/halt", json={"reason": "incident"}).status_code == 204
        assert client.delete("/api/v1/halt").status_code == 403
        assert _stopped(client) is True


@pytest.mark.parametrize("person", NOT_ADMIN)
def test_a_stop_shared_by_every_server_still_needs_an_administrator(person, signed_in, monkeypatch):
    """Where the stop reaches every server, only an administrator may use it;
    ``respond`` unlocks the stop only where an operator could use it before."""
    from maverick_dashboard import api

    monkeypatch.setattr(api, "_shared_halt_backend", lambda: True)
    client = signed_in(person)
    assert client.post("/api/v1/halt", json={"reason": "incident"}).status_code == 403
    assert client.delete("/api/v1/halt").status_code == 403


def test_a_role_held_in_one_workspace_does_not_unlock_the_stop_for_the_whole_installation(signed_in, monkeypatch):
    """The stop halts every workspace, so it follows the role a person holds for
    the whole installation. A role held in one workspace governs that
    workspace's agent controls and approvals, and nothing wider."""
    from maverick_dashboard import rbac

    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    _write_private(rbac.tenant_store_path(), json.dumps({"acme": {
        "user:viewer": "responder", "user:auditor": "approver", "user:responder": "viewer"}}))

    here_only = signed_in("viewer")  # a viewer for the installation, a responder in this workspace
    assert here_only.post(f"{ACP}/principals/suspend", json={"principal": "user:target", "reason": "x"}).status_code == 200
    assert here_only.post(f"{ACP}/principals/resume", json={"principal": "user:target"}).status_code == 200
    assert here_only.post("/api/v1/halt", json={"reason": "incident"}).status_code == 403
    assert _stopped(here_only) is False
    body = _controls_page(here_only)
    assert 'data-can-operate="true"' in body and 'data-can-halt="false"' in body

    approver_here = signed_in("auditor")  # an auditor for the installation, an approver in this workspace
    assert approver_here.get("/api/v1/approvals").status_code == 200
    assert approver_here.post(f"{ACP}/principals/suspend", json={"principal": "user:target", "reason": "x"}).status_code == 403
    assert approver_here.post("/api/v1/halt", json={"reason": "incident"}).status_code == 403

    elsewhere = signed_in("responder")  # a responder for the installation, only a viewer in this workspace
    assert elsewhere.post(f"{ACP}/principals/suspend", json={"principal": "user:target", "reason": "x"}).status_code == 403
    assert 'data-can-operate="false"' in _controls_page(elsewhere)
    assert elsewhere.post("/api/v1/halt", json={"reason": "incident"}).status_code == 204
    assert elsewhere.delete("/api/v1/halt").status_code == 204


# ----------------------------------------------------------------- drift

@pytest.mark.parametrize("person", EVERYONE)
def test_who_may_acknowledge_and_recheck_drift(person, signed_in, agent):
    client = signed_in(person)
    checked = client.post(f"/api/v1/external-agents/{AGENT}/drift/check")
    acknowledged = client.post(f"/api/v1/external-agents/{AGENT}/drift/acknowledge", json={"finding": "new_tool:x"})
    if person in MAY_RESPOND:
        assert checked.status_code == 200, checked.text
        assert acknowledged.status_code == 404, acknowledged.text  # allowed; there is no such finding
    else:
        assert (checked.status_code, acknowledged.status_code) == (403, 403)
    assert client.get(f"/api/v1/external-agents/{AGENT}/drift").status_code == 200  # reading needs only view


def test_a_responder_acknowledges_a_real_change(signed_in, agent):
    from maverick import agent_drift

    now, day = time.time(), 86400
    for back in range(8, 0, -1):
        for _ in range(4):
            agent_drift.observe_screen(AGENT, "lookup_policy", allowed=True, now=now - back * day)
        agent_drift.observe_run(AGENT, cost_dollars=0.2, tool_calls=4, outcome="success", tools=("lookup_policy",),
                                declared={"version": "1", "model": "m1"}, now=now - back * day)
    assert signed_in("boss").post(f"/api/v1/external-agents/{AGENT}/drift/baseline", json={}).status_code == 200
    for _ in range(5):
        agent_drift.observe_screen(AGENT, "export_records", allowed=True, now=now)
    responder, approver = signed_in("responder"), signed_in("approver")
    finding = "new_tool:export_records"
    acknowledge = f"/api/v1/external-agents/{AGENT}/drift/acknowledge"
    assert approver.post(f"/api/v1/external-agents/{AGENT}/drift/check").status_code == 403
    assert finding in responder.post(f"/api/v1/external-agents/{AGENT}/drift/check").json()["new_findings"]

    # The finding has its own button: on for the responder, off for the approver.
    button = f'data-drift-ack="{finding}"'
    assert "disabled" not in responder.get(f"/external-agents/{AGENT}").text.split(button, 1)[1].split(">", 1)[0]
    assert "disabled" in approver.get(f"/external-agents/{AGENT}").text.split(button, 1)[1].split(">", 1)[0]

    assert approver.post(acknowledge, json={"finding": finding}).status_code == 403
    still_open = responder.get(f"/api/v1/external-agents/{AGENT}/drift").json()["findings"]
    assert not any(row["acknowledged"] for row in still_open if row["key"] == finding)
    assert responder.post(acknowledge, json={"finding": finding}).status_code == 200
    after = responder.get(f"/api/v1/external-agents/{AGENT}/drift").json()["findings"]
    assert all(row["acknowledged"] for row in after if row["key"] == finding)


# ----------------------------------------------------------------- the pages

@pytest.mark.parametrize("person", EVERYONE)
def test_what_the_approvals_page_shows(person, signed_in, agent):
    parked = _park(agent)
    page = signed_in(person).get("/approvals")
    if person in MAY_APPROVE:
        assert page.status_code == 200 and page.headers["cache-control"] == "private, no-store"
        assert f'id="approval-{parked["approval_id"]}"' in page.text and "1 waiting" in page.text
        assert 'data-ap-decide="approve"' in page.text and 'data-ap-decide="deny"' in page.text
        assert "One approval is needed." in page.text
    else:
        assert page.status_code == 403
        assert f'id="approval-{parked["approval_id"]}"' not in page.text and "data-ap-decide" not in page.text


@pytest.mark.parametrize("person", EVERYONE)
def test_the_navigation_offers_approvals_only_to_people_who_may_decide(person, signed_in):
    page = signed_in(person).get("/external-agents")
    assert page.status_code == 200
    assert ('href="/approvals"' in page.text) is (person in MAY_APPROVE)
    assert 'href="/agent-control-plane"' in page.text  # everyone may read the agent controls


def _controls_page(client) -> str:
    page = client.get("/agent-control-plane")
    assert page.status_code == 200, page.text
    return page.text


@pytest.mark.parametrize("person", EVERYONE)
def test_what_the_agent_controls_page_shows(person, signed_in):
    body = _controls_page(signed_in(person))
    may = person in MAY_RESPOND
    flag = "true" if may else "false"
    assert f'data-can-operate="{flag}"' in body
    assert f'data-can-halt="{flag}"' in body and 'data-halt-scope="local"' in body
    # Suspend and resume are offered only to people who may use them ...
    assert ('<option value="suspend"' in body) is may and ('<option value="resume"' in body) is may
    assert ('<option value="suspend">Pause</option>' in body) is may  # the group form
    # ... the limits form and the stop form are switched off for everyone else ...
    assert ('id="acp-attenuate-controls" disabled aria-disabled="true" data-role-disabled="true"' in body) is not may
    assert ('id="acp-halt-controls" disabled aria-disabled="true" data-role-disabled="true"' in body) is not may
    assert ('id="acp-clear-halt" type="button" disabled data-role-disabled="true"' in body) is not may
    # ... and isolating stays with an administrator.
    assert ('<option value="contain"' in body) is (person == "boss")
    assert ('<option value="release"' in body) is (person == "boss")
    if person not in MAY_RESPOND | MAY_AUDIT:
        assert 'id="acp-verb-controls" disabled aria-disabled="true" data-role-disabled="true"' in body
        assert 'id="acp-fleet-controls" disabled aria-disabled="true" data-role-disabled="true"' in body


@pytest.mark.parametrize("person", EVERYONE)
def test_the_stop_button_in_the_page_header_follows_the_same_rule(person, signed_in):
    header = signed_in(person).get("/external-agents").text
    assert ('id="halt-pill" class="halt-pill" role="button" data-can-halt="true"' in header) is (person in MAY_RESPOND)
    assert ('data-can-halt="false" aria-disabled="true"' in header) is (person not in MAY_RESPOND)


@pytest.mark.parametrize("person", EVERYONE)
def test_what_an_agents_own_page_offers_for_drift(person, signed_in, agent):
    page = signed_in(person).get(f"/external-agents/{AGENT}")
    assert page.status_code == 200, page.text
    check_now = page.text.split('id="drift-check"', 1)[1].split(">", 1)[0]
    assert ("disabled" in check_now) is (person not in MAY_RESPOND)
    approve_baseline = page.text.split('id="drift-approve"', 1)[1].split(">", 1)[0]
    assert ("disabled" in approve_baseline) is (person != "boss")


def test_the_agent_controls_page_asks_for_respond_and_the_installation_wide_role(monkeypatch):
    """The page's own flags: suspend, resume and limits follow ``respond`` in the
    workspace; the stop follows the installation-wide role, never a role held
    in one workspace only."""
    from pathlib import Path

    from fastapi import FastAPI
    from fastapi.templating import Jinja2Templates

    from maverick_dashboard import agent_control_plane_page as page
    from maverick_dashboard.app import _theme_context

    def rendered(workspace: set[str], everywhere: set[str], *, shared: bool = False) -> str:
        monkeypatch.setattr(page, "require_permission", lambda *_: None)
        monkeypatch.setattr(page, "has_permission", lambda _request, permission: permission in workspace)
        monkeypatch.setattr(page, "has_global_permission", lambda _request, permission: permission in everywhere)
        monkeypatch.setattr(page, "_shared_halt_backend", lambda: shared)
        templates = Jinja2Templates(directory=Path(page.__file__).parent / "templates",
                                    context_processors=[_theme_context])
        templates.env.globals.update(nav_groups=[])
        app = FastAPI()
        app.include_router(page.create_agent_control_plane_page_router(templates))
        return TestClient(app, base_url="http://127.0.0.1").get(page.PAGE_PATH).text

    workspace_only = rendered({"respond"}, {"view"})
    assert 'data-can-operate="true"' in workspace_only
    assert 'data-can-halt="false"' in workspace_only and 'data-halt-scope="local"' in workspace_only

    everywhere = rendered(set(), {"respond"})
    assert 'data-can-operate="false"' in everywhere
    assert 'data-can-halt="true"' in everywhere and 'data-halt-scope="local"' in everywhere

    # ``operate`` alone is no longer what the page asks: the role's permissions
    # carry ``respond`` with it, so the page never needs to ask for both.
    assert 'data-can-operate="false"' in rendered({"operate"}, {"operate"})
    assert 'data-can-halt="false"' in rendered({"operate"}, {"operate"})
    # A stop shared by every server is an administrator's.
    assert 'data-can-halt="false"' in rendered({"respond"}, {"respond"}, shared=True)
    assert 'data-can-halt="true"' in rendered({"respond"}, {"admin"}, shared=True)


def test_the_control_routes_ask_for_respond_and_isolation_for_admin(app, monkeypatch):
    """What each control route asks of the permission check, by name."""
    from fastapi import HTTPException

    from maverick_dashboard import agent_control_plane_api as api_mod

    asked: list[str] = []

    def refuse(_request, permission):
        asked.append(permission)
        raise HTTPException(status_code=403, detail="insufficient role")

    monkeypatch.setattr(api_mod, "require_permission", refuse)
    monkeypatch.delenv("MAVERICK_OIDC_ENABLED")  # the local owner; only the check above refuses
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

    def asks(actions) -> set[str]:
        asked.clear()
        for name, (path, body) in actions.items():
            assert client.post(path, json=body).status_code == 403, name
        return set(asked)

    assert asks(_respond_actions()) == {"respond"}
    assert asks({name: action for name, action in _administrator_actions().items() if action[0].startswith(ACP)}) == {"admin"}


# ----------------------------------------------------------------- a role list that cannot be read

def _nothing_is_allowed(client, parked) -> None:
    assert client.get("/api/v1/approvals").status_code == 403
    assert client.get("/api/v1/approvals/waiting-count").status_code == 403
    assert client.get(f"/api/v1/approvals/{parked['approval_id']}/state").status_code == 403
    assert _approve(client, parked).status_code == 403
    assert _reject(client, parked).status_code == 403
    assert client.get("/approvals").status_code == 403
    assert client.post(f"{ACP}/principals/suspend", json={"principal": "user:target", "reason": "x"}).status_code == 403
    assert client.post(f"{ACP}/principals/resume", json={"principal": "user:target"}).status_code == 403
    assert client.post("/api/v1/halt", json={"reason": "incident"}).status_code == 403
    assert client.post(f"/api/v1/external-agents/{AGENT}/drift/check").status_code == 403


@pytest.mark.parametrize("damage", ["{not json", "[]", '{"user:approver": "approver", "user:responder": "superuser"}', ""])
def test_a_role_list_that_cannot_be_read_grants_neither_right(damage, signed_in, agent):
    from maverick_dashboard import rbac

    parked = _park(agent)
    _write_private(rbac.store_path(), damage)
    for person in ("approver", "responder", "operator", "legacy"):
        _nothing_is_allowed(signed_in(person), parked)
    assert _status(agent, parked) == "pending" and _suspended("user:target") is False


def test_a_role_list_that_went_missing_grants_neither_right(signed_in, agent):
    from maverick_dashboard import auth, rbac

    parked = _park(agent)
    assert auth.role_for_principal("user:approver") == "approver"  # read once: the list is on record
    rbac.store_path().unlink()
    for person in ("approver", "responder", "operator"):
        _nothing_is_allowed(signed_in(person), parked)
    assert _status(agent, parked) == "pending"


@pytest.mark.parametrize("damage", [
    "{not json",
    '{"approvals-desk": {"permissions": ["approve"]}}',                     # every role must grant view
    '{"approvals-desk": {"permissions": ["approve", "decide", "view"]}}',   # not a permission
    '{"approver": {"permissions": ["approve", "respond", "view"]}}',        # a built-in name
])
def test_custom_roles_that_cannot_be_read_grant_neither_right(damage, signed_in, agent):
    from maverick_dashboard import rbac

    parked = _park(agent)
    _write_private(rbac.custom_roles_path(), damage)
    for role in CUSTOM_ROLES:
        assert rbac.permissions_for(role) == frozenset()
        assert rbac.is_known_role(role) is False
    for person in ("desk-approve", "desk-respond", "legacy"):
        _nothing_is_allowed(signed_in(person), parked)
    assert _status(agent, parked) == "pending" and _suspended("user:target") is False


def test_a_custom_role_that_was_deleted_grants_neither_right(signed_in, agent):
    parked = _park(agent)
    _write_roles(custom={})
    for person in ("desk-approve", "desk-respond", "legacy"):
        _nothing_is_allowed(signed_in(person), parked)


def test_a_custom_role_with_neither_permission_gains_neither(signed_in, agent):
    """Only ``operate`` carries the two. A custom role built from the other
    permissions could not approve or stop agents before, and still cannot."""
    from maverick_dashboard import rbac

    _write_roles(people={**PEOPLE, "records": "records-desk", "settings": "settings-desk"},
                 custom={**CUSTOM_ROLES, "records-desk": ["audit", "view"], "settings-desk": ["admin", "view"]})
    assert rbac.permissions_for("records-desk") == frozenset({"audit", "view"})
    assert rbac.permissions_for("settings-desk") == frozenset({"admin", "view"})
    parked = _park(agent)
    for person in ("records", "settings"):
        _nothing_is_allowed(signed_in(person), parked)
    assert _status(agent, parked) == "pending"


def test_a_person_with_no_role_gets_the_default_and_neither_right(signed_in, agent):
    parked = _park(agent)
    newcomer = signed_in("newcomer")
    assert newcomer.get(f"{ACP}/status").status_code == 200  # the default role is viewer
    _nothing_is_allowed(newcomer, parked)


# ----------------------------------------------------------------- roles from the sign-in token

ROLE_MAP = """
[auth.oidc.role_map]
"SecondShift.Approver" = "approver"
"SecondShift.Responder" = "responder"
"SecondShift.Operator" = "operator"
"SecondShift.Auditor" = "auditor"
"SecondShift.ApprovalsDesk" = "approvals-desk"
"""


def test_an_app_role_can_make_someone_an_approver_or_a_responder(installation, signed_in, agent):
    from maverick_dashboard import sign_in_roles

    _configure(installation, ROLE_MAP)
    assert sign_in_roles.role_from_claims({"roles": ["SecondShift.Approver"]}) == "approver"
    assert sign_in_roles.role_from_claims({"roles": "SecondShift.Responder"}) == "responder"

    parked = _park(agent)
    responder = signed_in("rosa", roles=["SecondShift.Responder"])
    assert _approve(responder, parked).status_code == 403
    assert responder.get("/approvals").status_code == 403
    assert responder.post(f"{ACP}/principals/suspend", json={"principal": "user:target", "reason": "x"}).status_code == 200
    assert responder.post(f"{ACP}/principals/resume", json={"principal": "user:target"}).status_code == 200

    approver = signed_in("amal", roles=["SecondShift.Approver"])
    assert approver.post(f"{ACP}/principals/suspend", json={"principal": "user:target", "reason": "x"}).status_code == 403
    assert approver.post("/api/v1/halt", json={"reason": "incident"}).status_code == 403
    assert approver.get("/api/v1/approvals/waiting-count").json() == {"waiting": 1}
    assert _approve(approver, parked).status_code == 204
    assert _status(agent, parked) == "approved"

    # Without the app role the same people are viewers; an unmapped value gives nothing.
    for nobody in (signed_in("rosa"), signed_in("amal", roles=["Payroll.Approver", "approver", "approve"])):
        _nothing_is_allowed(nobody, _park(agent))


def test_an_approver_signs_in_through_the_browser(installation, app, token, agent, monkeypatch):
    from maverick.web_session import verify_session
    from maverick_dashboard import oidc_login

    _configure(installation, ROLE_MAP)
    parked = _park(agent)
    browser = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    location = browser.get("/auth/login", follow_redirects=False).headers["location"]
    query = parse_qs(urlparse(location).query)
    id_token = token("amal", nonce=query["nonce"][0], roles=["SecondShift.Approver"])

    async def exchange(url, *, cfg, code, code_verifier):
        return {"id_token": id_token}

    monkeypatch.setattr(oidc_login, "_exchange_code_for_tokens", exchange)
    assert browser.get(f"/auth/callback?code=c&state={query['state'][0]}", follow_redirects=False).status_code == 303
    session = verify_session(browser.cookies.get(oidc_login.SESSION_COOKIE), SESSION_SECRET)
    assert session["sub"] == "amal" and session["claim_role"] == "approver"

    page = browser.get("/approvals")
    assert page.status_code == 200 and f'id="approval-{parked["approval_id"]}"' in page.text
    assert 'data-can-operate="false"' in _controls_page(browser)
    assert browser.post(f"{ACP}/principals/suspend", json={"principal": "user:target", "reason": "x"}).status_code == 403
    assert _approve(browser, parked).status_code == 204


def test_a_stored_role_still_beats_the_app_role(installation, signed_in, agent):
    _configure(installation, ROLE_MAP)
    parked = _park(agent)
    # "viewer" is stored for this person, so the approver app role does not apply.
    assert _approve(signed_in("viewer", roles=["SecondShift.Approver"]), parked).status_code == 403
    assert _status(agent, parked) == "pending"


def test_an_app_role_taken_out_of_the_settings_stops_applying(installation, signed_in, agent):
    _configure(installation, ROLE_MAP)
    parked = _park(agent)
    approver = signed_in("amal", roles=["SecondShift.Approver"])
    assert approver.get("/api/v1/approvals").status_code == 200
    _configure(installation, '[auth.oidc.role_map]\n"SecondShift.Responder" = "responder"\n')
    _nothing_is_allowed(approver, parked)


@pytest.mark.parametrize("values,winner", [
    (["SecondShift.Approver", "SecondShift.Operator"], "operator"),      # operator covers both
    (["SecondShift.Responder", "SecondShift.Operator"], "operator"),
    (["SecondShift.Responder", "SecondShift.Approver"], "approver"),     # a tie: the order of the built-in roles
    (["SecondShift.Auditor", "SecondShift.Approver"], "approver"),
    (["SecondShift.Auditor", "SecondShift.Responder"], "responder"),
    (["SecondShift.ApprovalsDesk", "SecondShift.Approver"], "approver"),  # a tie: built-in roles first
    (["SecondShift.Auditor", "SecondShift.Operator"], "operator"),       # as before
])
def test_several_app_roles_still_give_one_role(installation, values, winner):
    from maverick_dashboard import sign_in_roles

    _configure(installation, ROLE_MAP)
    assert sign_in_roles.role_from_claims({"roles": values}) == winner
    assert sign_in_roles.role_from_claims({"roles": list(reversed(values))}) == winner


def test_what_comes_with_operate_is_not_counted_twice_when_roles_are_compared():
    """Roles that were compared before the two permissions existed still
    compare the same way: ``operate`` and view count as two, as they did."""
    from maverick_dashboard import sign_in_roles

    _write_roles(custom={"zeta-desk": ["operate", "view"], "alpha-desk": ["audit", "view"],
                         "wide-desk": ["audit", "operate", "view"], "top-desk": ["admin", "audit", "view"],
                         "both-desk": ["approve", "respond", "view"]}, people={})
    assert sign_in_roles.strongest(["zeta-desk", "alpha-desk"]) == "alpha-desk"    # same size: by name
    assert sign_in_roles.strongest(["zeta-desk", "auditor"]) == "auditor"          # same size: built-in first
    assert sign_in_roles.strongest(["operator", "top-desk"]) == "top-desk"         # three against two
    assert sign_in_roles.strongest(["operator", "wide-desk"]) == "wide-desk"
    assert sign_in_roles.strongest(["wide-desk", "governance_lead"]) == "governance_lead"
    assert sign_in_roles.strongest(["approver", "responder", "viewer"]) == "approver"
    assert sign_in_roles.strongest(["both-desk", "approver", "responder", "auditor"]) == "both-desk"


# ----------------------------------------------------------------- what was already true

def test_the_local_owner_with_sign_in_off_can_still_do_everything(app, monkeypatch):
    """No sign-in configured: the person at this computer owns the installation."""
    monkeypatch.delenv("MAVERICK_OIDC_ENABLED")
    local = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert local.get("/api/v1/approvals").status_code == 200
    assert local.get("/approvals").status_code == 200
    assert local.post(f"{ACP}/principals/suspend", json={"principal": "user:target", "reason": "x"}).status_code == 200
    assert local.post(f"{ACP}/principals/resume", json={"principal": "user:target"}).status_code == 200
    assert 'data-can-operate="true"' in _controls_page(local)


def test_someone_who_is_not_signed_in_gets_nothing(app, agent):
    parked = _park(agent)
    stranger = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert stranger.get("/api/v1/approvals").status_code == 401
    assert _approve(stranger, parked).status_code == 401
    assert stranger.post(f"{ACP}/principals/suspend", json={"principal": "user:target", "reason": "x"}).status_code == 401
    assert stranger.post("/api/v1/halt", json={"reason": "incident"}).status_code == 401


def test_the_agent_itself_cannot_decide_or_use_the_controls(agent):
    parked = _park(agent)
    assert _approve(agent, parked).status_code in (401, 403)
    assert agent.post(f"{ACP}/principals/suspend", json={"principal": "user:target", "reason": "x"}).status_code in (401, 403)
    assert _status(agent, parked) == "pending"
