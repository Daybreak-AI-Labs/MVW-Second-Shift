import copy
import json

import pytest

from second_shift_runtime.definition import DefinitionError, load_definition, parse_definition

from fakes import definition_dict


def test_a_good_definition_loads():
    d = parse_definition(definition_dict())
    assert d.id == "helper" and d.model.deployment == "gpt-test" and d.limits.max_steps == 5
    assert d.skills[0].name == "fetch_web_page"


@pytest.mark.parametrize("path,value,fragment", [
    (("surprise",), 1, "unknown field 'surprise'"),
    (("model", "surprise"), 1, "model: unknown field 'surprise'"),
    (("limits", "max_step"), 3, "limits: unknown field 'max_step'"),
    (("governance", "token"), "x", "governance: unknown field"),
    (("model", "provider"), "openai", "must be one of: foundry_openai, foundry_anthropic"),
    (("model", "api_key_env"), "sk-abc123!", "NAME of an environment variable"),
    (("model", "endpoint_env"), "https://x.example.com", "NAME of an environment variable"),
    (("governance", "agent_key_env"), "my key", "NAME of an environment variable"),
    (("id",), "../etc", "letters, digits"),
    (("model", "max_output_tokens"), 0, "between"),
    (("model", "max_output_tokens"), "lots", "must be a number"),
    (("limits", "max_steps"), 0, "between"),
    (("limits", "max_steps"), 2.5, "whole number"),
    (("skills",), [{"name": "nope"}], "no skill called 'nope'"),
    (("skills",), [{"name": "fetch_web_page"}, {"name": "fetch_web_page"}], "listed twice"),
    (("skills",), [{"name": "fetch_web_page", "settings": {"colour": 1}}], "unknown setting 'colour'"),
    (("skills",), [{"name": "fetch_web_page", "risk": "extreme"}], "must be one of: low, medium, high"),
    (("skills",), [{"name": "web_search", "settings": {"provider": "bing"}}], "must be one of: brave"),
    (("instructions",), "  ", "must not be empty"),
])
def test_bad_definitions_are_refused_in_plain_words(path, value, fragment):
    raw = copy.deepcopy(definition_dict())
    target = raw
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(DefinitionError) as err:
        parse_definition(raw)
    assert fragment in str(err.value)


def test_missing_required_fields_are_named():
    raw = definition_dict()
    del raw["model"]["deployment"]
    with pytest.raises(DefinitionError, match="model: missing required field 'deployment'"):
        parse_definition(raw)
    with pytest.raises(DefinitionError, match="must be a JSON object"):
        parse_definition([])


def test_a_definition_may_raise_a_risk_rating_but_not_lower_it():
    raw = definition_dict(skills=[{"name": "web_search", "risk": "high"}])
    assert parse_definition(raw).skills[0].risk == "high"
    from second_shift_runtime.skills import registry, resolve_skills

    assert resolve_skills(parse_definition(raw).skills)["web_search"].risk == "high"
    assert resolve_skills(parse_definition(definition_dict()).skills)["fetch_web_page"].risk == "low"
    assert registry()["fetch_web_page"].default_risk == "low"


def test_the_risk_of_a_skill_cannot_be_lowered(monkeypatch):
    from second_shift_runtime.skills import Skill, web

    monkeypatch.setattr(web.FetchWebPage, "default_risk", "medium")
    assert issubclass(web.FetchWebPage, Skill)
    with pytest.raises(DefinitionError, match="may raise a rating, never lower it"):
        parse_definition(definition_dict(skills=[{"name": "fetch_web_page", "risk": "low"}]))


def test_a_cost_limit_needs_prices_and_prices_come_in_pairs():
    raw = definition_dict()
    del raw["model"]["input_price_per_million"], raw["model"]["output_price_per_million"]
    with pytest.raises(DefinitionError, match="needs model prices"):
        parse_definition(raw)
    raw["limits"].pop("max_cost_dollars")
    assert parse_definition(raw).model.input_price_per_million is None
    raw["model"]["input_price_per_million"] = 1
    with pytest.raises(DefinitionError, match="both input_price_per_million and output_price_per_million"):
        parse_definition(raw)


def test_the_digest_is_stable_and_changes_with_the_definition():
    a, b = parse_definition(definition_dict()), parse_definition(dict(reversed(list(definition_dict().items()))))
    assert a.config_digest == b.config_digest and len(a.config_digest) == 64
    changed = parse_definition(definition_dict(instructions="Be long."))
    assert changed.config_digest != a.config_digest


def test_loading_a_file_reports_unreadable_and_invalid_files(tmp_path):
    good = tmp_path / "a.json"
    good.write_text(json.dumps(definition_dict()))
    assert load_definition(str(good)).name == "Research helper"
    with pytest.raises(DefinitionError, match="could not be read"):
        load_definition(str(tmp_path / "missing.json"))
    bad = tmp_path / "b.json"
    bad.write_text("{nope")
    with pytest.raises(DefinitionError, match="not valid JSON"):
        load_definition(str(bad))
