# ruff: noqa: F811
"""Export packages for a released factory agent: Azure, AWS AgentCore and Microsoft Foundry.

Hermetic: no cloud is contacted. Checks what each package holds, that the definition in it is the version's exact
definition, that no secret is anywhere in a package, that the access key is made on request and shown once, and who may
export.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import zipfile

import pytest

from tests.new.test_agent_factory import (  # noqa: F401  (fixtures and helpers shared with the factory tests)
    MODEL_ENDPOINT,
    MODEL_KEY,
    app,
    installation,
    model,
    person,
    released_agent,
    world,
)

pytest.importorskip("second_shift_runtime.skills_service", reason="needs the runtime with the skills service")

SKILLS = [{"name": "fetch_web_page"}, {"name": "web_search"}, {"name": "create_word_document"}]
SEARCH_KEY = "brave-key-value-123"  # pragma: allowlist secret


@pytest.fixture
def released(person, model, world, monkeypatch):
    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", SEARCH_KEY)
    return released_agent(person, model, world, skills=SKILLS)


def url(agent, target, number=1):
    return f"/api/v1/factory/agents/{agent['id']}/versions/{number}/exports/{target}"


def export(client, agent, target, **body):
    out = client.post(url(agent, target), json=body)
    assert out.status_code == 200, out.text
    data = out.json()
    return data, zipfile.ZipFile(io.BytesIO(base64.b64decode(data["package_base64"])))


def files_of(archive):
    root = archive.namelist()[0].split("/")[0]
    return {n.removeprefix(root + "/"): archive.read(n) for n in archive.namelist() if not n.endswith("/")}


# --- contents -------------------------------------------------------------------------------------------------

def test_the_azure_package_has_the_definition_a_recipe_a_bicep_module_and_a_readme(person, released):
    data, archive = export(person("boss"), released, "azure")
    files = files_of(archive)
    assert {"agent.json", "Dockerfile", "main.bicep", "README.md", "runtime/pyproject.toml",
            "runtime/second_shift_runtime/server.py", "runtime/second_shift_runtime/skills_service.py"} <= set(files)
    docker = files["Dockerfile"].decode()
    assert "FROM python:3.12-slim" in docker and "'./runtime[office]'" in docker and "linux/arm64" not in docker
    assert '"serve"' in docker and "/ping" in docker and "USER 10001" in docker
    bicep = files["main.bicep"].decode()
    for needed in ("Microsoft.ManagedIdentity/userAssignedIdentities", "type: 'UserAssigned'", "keyVaultUrl:", "identity: identity.id",
                   "/ping", "type: 'Startup'", "type: 'Liveness'", "type: 'Readiness'", "targetPort: 8080", "external: externalIngress",
                   "4633458b-17de-408a-b874-0445c86b69e6", "7f951dda-4ed3-4680-a7ca-43fe172d538d"):
        assert needed in bicep, needed
    assert "param externalIngress bool = false" in bicep
    for secret in ("policy-helper-model-key", "policy-helper-second-shift-key", "policy-helper-search-key", "policy-helper-inbound-key"):
        assert f"'{secret}'" in bicep and secret in files["README.md"].decode()
    for env in ("FACTORY_TEST_KEY", "SECOND_SHIFT_AGENT_KEY", "BRAVE_SEARCH_API_KEY", "SECOND_SHIFT_URL"):
        assert f"name: '{env}'" in bicep
    assert data["target"] == "azure" and data["filename"].endswith("-azure.zip") and data["key"] is None


def test_the_aws_package_is_arm64_and_meets_the_agentcore_contract(person, released):
    _, archive = export(person("boss"), released, "aws")
    files = files_of(archive)
    assert {"agent.json", "Dockerfile", "entrypoint.py", "secret-names.json", "trust-policy.json", "execution-policy.json",
            "README.md"} <= set(files)
    docker = files["Dockerfile"].decode()
    assert docker.count("FROM --platform=linux/arm64 python:3.12-slim") == 1 and "EXPOSE 8080" in docker and "/ping" in docker
    assert json.loads(files["secret-names.json"]) == {
        "FACTORY_TEST_KEY": "policy-helper-model-key", "SECOND_SHIFT_AGENT_KEY": "policy-helper-second-shift-key",
        "BRAVE_SEARCH_API_KEY": "policy-helper-search-key"}
    trust = json.loads(files["trust-policy.json"])
    assert trust["Statement"][0]["Principal"] == {"Service": "bedrock-agentcore.amazonaws.com"}
    policy = json.loads(files["execution-policy.json"])
    (secrets,) = [s for s in policy["Statement"] if s.get("Sid") == "ReadNamedSecrets"]
    assert secrets["Action"] == ["secretsmanager:GetSecretValue"] and len(secrets["Resource"]) == 3
    assert all(":secret:policy-helper-" in r for r in secrets["Resource"])
    readme = files["README.md"].decode()
    for step in ("aws ecr create-repository", "docker buildx build --platform linux/arm64", "create-agent-runtime",
                 "aws secretsmanager create-secret", "invoke_agent_runtime"):
        assert step in readme, step


def test_the_aws_entry_point_reads_each_named_secret_into_the_variable_the_definition_names():
    from maverick.factory.export import _ENTRYPOINT

    scope: dict = {}
    exec(compile(_ENTRYPOINT.replace('if __name__ == "__main__":\n    raise SystemExit(main())', ""), "entrypoint", "exec"), scope)  # noqa: S102

    class Client:
        def get_secret_value(self, SecretId):
            return {"SecretString": f"value-of-{SecretId}"}

    env: dict = {}
    names = {"MODEL_KEY": "agent-model-key"}
    scope["load_secrets"](Client(), names, env)
    assert env == {"MODEL_KEY": "value-of-agent-model-key"}

    class Broken:
        def get_secret_value(self, SecretId):
            raise RuntimeError("no such secret")

    with pytest.raises(RuntimeError):
        scope["load_secrets"](Broken(), names, {})


def test_the_foundry_package_has_a_prompt_agent_whose_only_tool_is_the_governed_skills_service(person, released):
    from second_shift_runtime.skills_service import check_foundry_openapi

    _, archive = export(person("boss"), released, "foundry", skills_url="https://skills.contoso.example/",
                        connection_id="/subscriptions/s/resourceGroups/g/providers/Microsoft.CognitiveServices/accounts/a/projects/p/connections/c")
    files = files_of(archive)
    assert {"agent.json", "foundry-agent.json", "skills-openapi.json", "README.md", "skills-service/Dockerfile", "skills-service/main.bicep",
            "skills-service/agent.json", "skills-service/runtime/second_shift_runtime/skills_service.py",
            "skills-service/README.md"} <= set(files)
    body = json.loads(files["foundry-agent.json"])
    assert body["name"] == "policy-helper" and body["definition"]["kind"] == "prompt" and body["definition"]["model"] == "gpt-test"
    assert body["definition"]["instructions"].startswith(json.loads(files["agent.json"])["instructions"])
    (tool,) = body["definition"]["tools"]
    assert tool["type"] == "openapi" and tool["openapi"]["auth"] == {"type": "project_connection", "security_scheme": {
        "project_connection_id": "/subscriptions/s/resourceGroups/g/providers/Microsoft.CognitiveServices/accounts/a/projects/p/connections/c"}}
    spec = tool["openapi"]["spec"]
    assert check_foundry_openapi(spec) == [] and spec["servers"] == [{"url": "https://skills.contoso.example"}]
    assert {o["post"]["operationId"] for o in spec["paths"].values()} == {s["name"] for s in SKILLS}
    assert json.loads(files["skills-openapi.json"]) == spec
    docker = files["skills-service/Dockerfile"].decode()
    assert '"serve-skills"' in docker and "SECOND_SHIFT_SKILLS_KEY" in docker
    bicep = files["skills-service/main.bicep"].decode()
    assert "SECOND_SHIFT_SKILLS_KEY" in bicep and "FACTORY_TEST_KEY" not in bicep and "/ping" in bicep
    assert "policy-helper-skills-key" in bicep and "x-api-key" in files["README.md"].decode()


def test_without_an_address_the_foundry_package_says_where_to_put_it(person, released):
    _, archive = export(person("boss"), released, "foundry")
    files = files_of(archive)
    assert "SKILLS-SERVICE-ADDRESS" in files["foundry-agent.json"].decode() and "<PROJECT-CONNECTION-RESOURCE-ID>" in files["foundry-agent.json"].decode()
    assert "Replace it" in files["README.md"].decode()


def test_the_definition_in_every_package_is_the_versions_exact_definition(person, released):
    from second_shift_runtime.definition import parse_definition

    version = released["versions"][0]
    for target in ("azure", "aws", "foundry"):
        _, archive = export(person("boss"), released, target)
        shipped = json.loads(files_of(archive)["agent.json"])
        assert shipped == version["definition"]
        assert parse_definition(shipped).config_digest == version["config_digest"]
        assert version["config_digest"] in files_of(archive)["README.md"].decode()


def test_a_package_is_the_same_every_time(person, released):
    first, _ = export(person("boss"), released, "azure")
    second, _ = export(person("boss"), released, "azure")
    assert first["sha256"] == second["sha256"] and first["size"] == second["size"]
    assert hashlib.sha256(base64.b64decode(first["package_base64"])).hexdigest() == first["sha256"]


# --- no secret anywhere ---------------------------------------------------------------------------------------

def test_no_secret_is_in_any_package_and_the_key_is_made_once(person, released, installation):
    boss = person("boss")
    secrets = [MODEL_KEY, MODEL_ENDPOINT, SEARCH_KEY]
    for target in ("azure", "aws", "foundry"):
        data, archive = export(boss, released, target, mint_key=True)
        key = data["key"]
        assert key["shown_once"] and key["value"].startswith("ss-rest-") and key["where_to_store"] and key["secret_names"]
        for name, content in files_of(archive).items():
            text = content.decode("utf-8", "replace")
            for secret in [*secrets, key["value"]]:
                assert secret not in text, (target, name)
            assert not re.search(r"ss-(rest|a2a|grpc|mcp)-[A-Za-z0-9_-]{10,}", text), (target, name)
        assert key["value"] not in json.dumps({k: v for k, v in data.items() if k not in ("key",)})


def test_a_key_is_made_only_when_asked_works_for_the_agent_and_replaces_the_old_one(person, released, app):
    from fastapi.testclient import TestClient

    boss = person("boss")
    data, _ = export(boss, released, "azure")
    assert data["key"] is None
    first, _ = export(boss, released, "azure", mint_key=True)
    agent = lambda token: TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": f"Bearer {token}"})  # noqa: E731
    ok = agent(first["key"]["value"]).post("/api/v1/external/screen", json={"tool": "create_word_document", "risk": "low"})
    assert ok.status_code == 200 and ok.json()["allowed"] is True
    second, _ = export(boss, released, "aws", mint_key=True)
    assert second["key"]["value"] != first["key"]["value"]
    assert agent(first["key"]["value"]).post("/api/v1/external/screen", json={"tool": "x"}).status_code == 401
    assert agent(second["key"]["value"]).post("/api/v1/external/screen", json={"tool": "create_word_document", "risk": "low"}).status_code == 200
    again = boss.get(f"/api/v1/factory/agents/{released['id']}").text
    assert second["key"]["value"] not in again and first["key"]["value"] not in again


@pytest.fixture
def audit_rows(monkeypatch):
    import maverick.audit as audit_pkg

    rows: list[dict] = []

    def record(kind, *, agent="system", goal_id=None, **payload):
        rows.append({"kind": str(kind), "agent": agent, **payload})
        return True

    monkeypatch.setattr(audit_pkg, "record", record)
    return rows


def test_the_export_is_audited_without_the_key(person, released, audit_rows):
    del audit_rows[:]
    data, _ = export(person("boss"), released, "azure", mint_key=True)
    mine = [r for r in audit_rows if r["kind"].startswith("factory_export")]
    assert [r["kind"] for r in mine] == ["factory_export_requested", "factory_export_made"]
    assert mine[0]["requested_by"] == "user:boss" and mine[1]["target"] == "azure" and mine[1]["key_minted"] is True
    assert data["key"]["value"] not in json.dumps(audit_rows) and MODEL_KEY not in json.dumps(audit_rows)


def test_an_audit_log_that_cannot_take_the_record_stops_the_export(person, released, monkeypatch):
    import maverick.audit as audit_pkg

    monkeypatch.setattr(audit_pkg, "record", lambda *a, **k: False)
    out = person("boss").post(url(released, "azure"), json={"mint_key": True})
    assert out.status_code == 503 and "key" not in out.text.lower().replace("access key", "")


# --- who and what ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("who", ["alice", "carol", "dave"])
def test_only_an_administrator_may_export(person, released, who):
    out = person(who).post(url(released, "azure"), json={})
    assert out.status_code == 403
    assert person(who).post(url(released, "azure"), json={"mint_key": True}).status_code == 403


def test_a_visitor_with_no_role_cannot_export(app, released):
    from fastapi.testclient import TestClient

    stranger = TestClient(app, base_url="http://127.0.0.1", client=("10.9.9.9", 5), headers={"X-Forwarded-User": "boss"})
    assert stranger.post(url(released, "azure"), json={}).status_code in (401, 403)


def test_only_a_released_version_can_be_exported_and_the_target_and_address_are_checked(person, model, released):
    boss = person("boss")
    assert boss.post(url(released, "nowhere"), json={}).status_code == 422
    assert boss.post(url(released, "azure", 7), json={}).status_code in (404, 409)
    assert boss.post(url(released, "foundry"), json={"skills_url": "http://plain.example"}).status_code == 422
    assert boss.post(url(released, "foundry"), json={"skills_url": "https://x.example/?key=1"}).status_code == 422
    assert boss.post(url(released, "azure"), json={"surprise": 1}).status_code == 422
    # a retired agent cannot be exported or given a key
    assert boss.post(f"/api/v1/factory/agents/{released['id']}/retire").status_code == 200
    assert boss.post(url(released, "azure"), json={"mint_key": True}).status_code == 409


def test_a_draft_cannot_be_exported(person, model):
    from tests.new.test_agent_factory import new_agent

    draft = new_agent(person("alice"))
    assert person("boss").post(url(draft, "azure"), json={}).status_code == 409


def test_the_agent_page_has_an_export_section_for_an_administrator_only(person, released):
    page = person("boss").get(f"/factory/{released['id']}").text
    assert 'id="fx-export"' in page
    assert 'id="fx-export"' in person("alice").get(f"/factory/{released['id']}").text  # the section is there; the buttons are not
    js = person("alice").get("/static/second-shift-factory.js").text
    assert "exports/" in js


def test_nothing_a_person_reads_in_a_package_uses_an_internal_product_name(person, released):
    for target in ("azure", "aws", "foundry"):
        _, archive = export(person("boss"), released, target)
        for name, content in files_of(archive).items():
            assert not re.search(r"lightwork|daybreak|maverick", content.decode("utf-8", "replace"), re.I), (target, name)
    assert "second-shift" in export(person("boss"), released, "azure")[0]["filename"]


def test_the_page_carries_the_push_status_and_the_script_says_what_is_not_built(person, released):
    page = person("boss").get(f"/factory/{released['id']}").text
    assert '"foundry_push"' in page and 'id="fx-export"' in page
    js = person("boss").get("/static/second-shift-factory.js").text
    assert "Azure Container Apps or AWS is not built in this version" in js and "Push to Foundry" in js
