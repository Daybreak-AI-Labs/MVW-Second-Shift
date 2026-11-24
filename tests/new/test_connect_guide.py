"""The guided "connect an agent" path: what each platform is told, and the page that holds it."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from maverick import connect_guide, external_agents


@pytest.fixture
def home(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()

    def write(text: str) -> None:
        (tmp_path / "config.toml").write_text(text, encoding="utf-8")
        config.reset_config_cache()

    write("")
    yield write
    config.reset_config_cache()


def test_every_platform_has_steps_and_every_step_is_plain(home):
    for key in external_agents.PLATFORMS:
        guide = connect_guide.guide_for(key, external_ref="")
        assert guide["steps"], key
        text = " ".join(s["title"] + " " + s["body"] for s in guide["steps"])
        for banned in ("Lightwork", "Maverick", "Daybreak", "MAVERICK_"):
            assert banned not in text
        assert "docs/connect-an-agent.md" in text or guide["steps"]


def test_foundry_and_custom_agents_use_the_connection_api(home):
    for key in ("foundry", "custom", "servicenow", "workday"):
        guide = connect_guide.guide_for(key, external_ref="")
        assert guide["kind"] == "api"
        assert any("connection file" in s["body"].lower() for s in guide["steps"])
    assert "coming" in " ".join(s["body"] for s in connect_guide.guide_for("foundry", external_ref="")["steps"]).lower()


def test_copilot_studio_without_a_gate_gets_per_agent_steps(home):
    guide = connect_guide.guide_for("copilot", external_ref="copilot_studio:org1.crm.dynamics.com/abc")
    assert guide["kind"] == "copilot_manual" and guide["gate"] == "none"


def test_copilot_studio_covered_by_the_gate_has_nothing_to_do(home):
    home('[copilot_studio_gate]\nenvironments = ["https://org1.crm.dynamics.com"]\n')
    guide = connect_guide.guide_for("copilot", external_ref="copilot_studio:org1.crm.dynamics.com/abc")
    assert guide["kind"] == "copilot_gate" and guide["gate"] == "covered"
    assert "nothing to do" in guide["steps"][0]["body"].lower()


def test_copilot_studio_in_another_environment_is_not_covered(home):
    home('[copilot_studio_gate]\nenvironments = ["org1.crm.dynamics.com"]\n')
    guide = connect_guide.guide_for("copilot", external_ref="copilot_studio:other.crm.dynamics.com/abc")
    assert guide["kind"] == "copilot_manual" and guide["gate"] == "none"


def test_copilot_studio_without_a_record_says_which_case_applies(home):
    home('[copilot_studio_gate]\nenvironments = ["org1.crm.dynamics.com"]\n')
    guide = connect_guide.guide_for("copilot", external_ref="")
    assert guide["gate"] == "maybe" and guide["kind"] == "copilot_manual"


@pytest.mark.parametrize("text", ['[copilot_studio_gate]\nenvironments = "x"\n', "[copilot_studio_gate]\nenvironments = 5\n",
                                  "[copilot_studio_gate]\n", "copilot_studio_gate = 3\n"])
def test_a_missing_or_odd_gate_setting_is_treated_as_absent(home, text):
    home(text)
    assert connect_guide.guide_for("copilot", external_ref="copilot_studio:a/b")["gate"] == "none"


def test_the_untested_parts_are_said_plainly(home):
    for key in external_agents.PLATFORMS:
        assert "not been tested" in connect_guide.guide_for(key, external_ref="")["untested"].lower()


def test_the_page_holds_the_guide_and_its_waiting_step(home):
    from maverick_dashboard.app import app

    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as c:
        page = c.get("/external-agents").text
    for needle in ('id="xa-connect"', "Waiting to hear from the agent", "Check again", 'data-guide-for="foundry"',
                   'data-guide-for="copilot"', "/api/v1/external-agents/"):
        assert needle in page
