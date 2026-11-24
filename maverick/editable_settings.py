"""The settings an administrator may change in the product, and where the change is kept.

Everything else stays in the deployment's settings file and environment
variables. This module holds:

* the allowlist: each editable setting with its type, range or choices, a plain
  label and a one-line explanation of what it changes;
* validation: a value that is not exactly what the setting takes is refused,
  and so is any setting that is not on the list;
* the settings layer: ``settings-layer.toml`` in the data folder, owned by the
  app and applied on top of the deployment's file by ``config.load_config``;
* what a person sees: each setting's effective value and where it comes from;
* changing and resetting a setting, which is audited.

What it does not do. It never stores, reads back or shows a secret: a
credential is a variable NAME in the settings, and the page shows only whether
that variable is set. It does not touch the deployment's file or environment.
A setting the deployment locks cannot be changed here: one set by an
environment variable, one listed under ``[settings] locked`` in the
deployment's file, and one the operator overlay sets (it would win anyway).

The layer is read like the deployment's file. If it cannot be read it is held
whole, its error is reported by ``config.config_source_errors`` so every
caller that fails closed on an unreadable file does the same for it, and no
change is written over it.
"""
from __future__ import annotations

import copy
import json
import math
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import SETTINGS_LAYER_BASENAME as LAYER_BASENAME

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore
#: ``[settings] locked = [...]`` in the deployment's file names the keys below that only it may set.
LOCKED_SECTION = "settings"

_ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")
_GUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_EMAIL = re.compile(r"[^\s@<>\"',;]{1,64}@[A-Za-z0-9.-]{1,200}\.[A-Za-z]{2,24}")
_HTTPS_ADDRESS = re.compile(r"https://[A-Za-z0-9.-]{1,253}(?:/[A-Za-z0-9._~:/@%+-]{0,200})?")
_DEPLOYMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_ZONE = re.compile(r"[A-Za-z][A-Za-z0-9_+/-]{0,63}")
_CHANNEL = re.compile(r"[A-Za-z0-9:._@+-]{1,200}")

_GUID_WORDS = "an id like 11111111-2222-3333-4444-555555555555"
SECRET_REFUSAL = ("Enter the NAME of the environment variable that holds it: capital letters, digits and "
                  "underscores, such as SS_MS_CLIENT_SECRET. Never type the secret itself.")


class SettingRefused(Exception):
    """A change that was not made. The message is a plain sentence for the person who asked.

    ``status`` is the HTTP answer for it: 404 unknown setting, 409 locked or not available,
    422 a value the setting does not take, 503 the saved settings or the audit log cannot be used.
    """

    def __init__(self, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Setting:
    key: str                      # dotted path in the settings tree, e.g. "agent_drift.learning_days"
    section: str
    kind: str                     # bool int float choice text guid env_name list_choice list_guid list_text map
    label: str
    help: str
    default: Any = None
    minimum: float | None = None
    maximum: float | None = None
    choices: tuple[str, ...] = ()
    choice_labels: Mapping[str, str] = field(default_factory=dict)
    env: tuple[str, ...] = ()     # environment variables that, when set, decide the value
    pattern: re.Pattern[str] | None = None
    pattern_help: str = ""
    max_length: int = 200
    max_items: int = 20
    allow_empty: bool = False     # text: "" is a value (it clears the setting)
    empty_stored_as: tuple[str, ...] | None = None   # list_choice: what an empty list is saved as
    note: str = ""                # when a change takes effect, if not at once
    restart: bool = False         # a change needs the app restarted
    unit: str = ""
    reader: Callable[[], Any] | None = None          # the feature's own answer, where the tree alone cannot give it

    @property
    def path(self) -> tuple[str, ...]:
        return tuple(self.key.split("."))


@dataclass(frozen=True)
class Section:
    id: str
    title: str
    about: str
    tests: tuple[tuple[str, str, str], ...] = ()      # (button text, POST address, what it does)
    needs: str = ""                                   # a feature that must be installed
    secrets: tuple[tuple[str, str], ...] = ()         # (what, environment variable) shown only as set or not


# ----------------------------------------------------------------------------- the allowlist

def _drift_settings() -> list[Setting]:
    from . import agent_drift

    table = agent_drift._NUMBER_SETTINGS
    words = {
        "baseline_days": ("Baseline length", "How many days of an agent's behaviour make up its baseline.", "days"),
        "window_days": ("Comparison window", "How many recent days are compared with the baseline. Never longer than the baseline.", "days"),
        "min_runs": ("Runs needed", "An agent needs at least this many runs before its pace and cost are compared.", "runs"),
        "min_screens": ("Checks needed", "An agent needs at least this many checked actions before its denial rate is compared.", "actions"),
        "tool_mix_min_samples": ("Tool uses needed", "At least this many tool uses are needed before the mix of tools is compared.", "uses"),
        "tool_mix_threshold": ("Tool mix change", "How far the mix of tools may move from the baseline, from 0.01 to 1, before it is a finding.", ""),
        "volume_ratio": ("Run volume change", "A finding is made when the number of runs is this many times the baseline, or its inverse.", "times"),
        "cost_ratio": ("Cost change", "A finding is made when the cost of a run is this many times the baseline.", "times"),
        "denial_rate_rise": ("Denied actions rise", "A finding is made when the share of denied actions rises by this much (0.15 is 15 points).", ""),
        "failure_rate_rise": ("Failed runs rise", "A finding is made when the share of failed runs rises by this much (0.2 is 20 points).", ""),
        "check_minutes": ("How often agents are compared", "Every agent is compared with its baseline this often.", "minutes"),
        "silent_hours": ("Silence before a finding", "An agent that used to report and has been quiet this long is flagged.", "hours"),
        "learning_days": ("Learning period", "After a baseline is approved, changes are recorded but not alerted for this long. 0 turns it off.", "days"),
    }
    out = [Setting(
        "agent_drift.enable", "drift", "bool", "Compare agents with their baselines",
        "Turn this off and nobody is told when an agent starts behaving differently.",
        default=True, env=("MAVERICK_AGENT_DRIFT",))]
    for name, (kind, default, low, high) in table.items():
        label, help_, unit = words[name]
        note = "Takes effect at the next comparison." if name == "check_minutes" else ""
        out.append(Setting(f"agent_drift.{name}", "drift", "int" if kind is int else "float", label, help_,
                           default=default, minimum=low, maximum=high, unit=unit, note=note))
    out.append(Setting(
        "agent_drift.on_drift", "drift", "choice", "What happens on a serious finding",
        "Tell people only, or also contain the agent until someone releases it.",
        default="alert", choices=agent_drift._REACTIONS,
        choice_labels={"alert": "Tell people", "contain": "Tell people and contain the agent"}))
    return out


def _model_settings() -> list[Setting]:
    from . import model_drift

    words = {
        "bins": ("Histogram bins", "How many groups a numeric series is split into when it is compared.", ""),
        "min_samples": ("Values needed", "A series needs at least this many values before it is compared.", "values"),
        "psi_threshold": ("Population stability limit", "A finding is made when the population stability index is at or above this.", ""),
        "js_threshold": ("Divergence limit", "A finding is made when the Jensen-Shannon divergence is at or above this.", "bits"),
        "ks_p_value_floor": ("Kolmogorov-Smirnov p-value floor", "A finding is made when this test's p-value is at or below this.", ""),
        "chi2_p_value_floor": ("Chi-squared p-value floor", "A finding is made when this test's p-value is at or below this.", ""),
        "embedding_cosine_threshold": ("Embedding distance limit", "A finding is made when the cosine distance between embeddings is at or above this.", ""),
        "accuracy_decay_threshold": ("Accuracy drop limit", "A finding is made when accuracy has fallen by this much (0.05 is five points).", ""),
        "batches_per_minute": ("Batches a minute", "The most batches of samples one caller may send for one model each minute.", "a minute"),
    }
    out = [Setting("model_drift.enable", "models", "bool", "Check models for drift",
                   "Turn this off and sample batches are no longer accepted. The register still works.", default=True)]
    for name, (kind, default, low, high) in model_drift._NUMBER_SETTINGS.items():
        label, help_, unit = words[name]
        out.append(Setting(f"model_drift.{name}", "models", "int" if kind is int else "float", label, help_,
                           default=default, minimum=low, maximum=high, unit=unit))
    return out


_PLATFORMS = {
    "entra_agent_id": ("Microsoft Entra Agent ID", ("tenant_id_env", "client_id_env", "client_secret_env")),
    "foundry": ("Microsoft Foundry", ("tenant_id_env", "client_id_env", "client_secret_env")),
    "copilot_studio": ("Copilot Studio", ("tenant_id_env", "client_id_env", "client_secret_env")),
    "servicenow": ("ServiceNow", ("client_id_env", "client_secret_env")),
    "workday": ("Workday", ("client_id_env", "client_secret_env", "refresh_token_env")),
}
_CREDENTIAL_WORDS = {
    "tenant_id_env": "tenant id",
    "client_id_env": "client id",
    "client_secret_env": "client secret",
    "refresh_token_env": "refresh token",
}


def _platform_settings() -> list[Setting]:
    from . import agent_watch

    out = [
        Setting("agent_watch.enable", "platform_checks", "bool", "Check the platforms agents run on",
                "Ask each listed platform which agents it has and how each is set up. Checks only read.",
                default=False, env=("MAVERICK_AGENT_WATCH",)),
        Setting("agent_watch.platforms", "platform_checks", "list_choice", "Platforms to check",
                "Only the platforms ticked here are asked. Each needs its own settings below.",
                default=[], choices=tuple(_PLATFORMS), choice_labels={k: v[0] for k, v in _PLATFORMS.items()},
                empty_stored_as=()),
    ]
    default, low, high = agent_watch._NUMBER_SETTINGS["sync_minutes"]
    out.append(Setting("agent_watch.sync_minutes", "platform_checks", "int", "How often platforms are checked",
                       "The time between checks of every listed platform.", default=default, minimum=low,
                       maximum=high, unit="minutes", note="Takes effect after the current wait ends."))
    for platform, (name, keys) in _PLATFORMS.items():
        for key in keys:
            out.append(Setting(
                f"agent_watch.{platform}.{key}", "platform_checks", "env_name",
                f"{name}: variable for the {_CREDENTIAL_WORDS[key]}",
                f"The name of the environment variable that holds the {_CREDENTIAL_WORDS[key]} {name} is checked with.",
                default=""))
    out.append(Setting(
        "agent_watch.entra_agent_id.allow_switch_off", "platform_checks", "bool",
        "Allow switching an agent off on Microsoft Entra Agent ID",
        "When on, an administrator may switch an agent off on its platform from the agent's page.", default=False))
    return out


def _ekko_choices() -> tuple[str, ...]:
    from .work_discovery import DEFAULT_BLOCKED_APPS, KNOWN_APPS

    return tuple(sorted(KNOWN_APPS - DEFAULT_BLOCKED_APPS))


def _alert_channels() -> list[str]:
    from . import ops_alert

    return [name for name in ops_alert._configured_names() if name in ("teams", "email")]


def _build() -> tuple[Setting, ...]:
    from .config_contracts import CHOICE_SETTINGS

    second_person = CHOICE_SETTINGS["approval.separate_approver"]
    settings: list[Setting] = [
        # ---------------------------------------------------------------- alerts
        Setting("alerts.enabled", "alerts", "bool", "Send alerts",
                "Off, nobody is told about a blocked agent, a drift finding or a request about to run out.",
                default=False, env=("MAVERICK_ALERTS",)),
        Setting("alerts.backends", "alerts", "list_choice", "Where alerts go",
                "Teams, email or both. Each needs its own address set up in the deployment.",
                default=[], choices=("teams", "email"), choice_labels={"teams": "Microsoft Teams", "email": "Email"},
                empty_stored_as=("none",), reader=_alert_channels),
        Setting("notifications.email.to", "alerts", "list_text", "Email addresses that receive alerts",
                "Who alerts are emailed to. Used only when email is a channel.", default=[], pattern=_EMAIL,
                pattern_help="an email address", max_items=10, max_length=254),
        # -------------------------------------------------------------- approvals
        Setting("approval.separate_approver", "approvals", "choice", "A second person approves",
                "Whether the person who asked for a high-risk request may also approve it.",
                default=second_person.default, choices=second_person.options, env=second_person.dashboard_env,
                choice_labels={"always": "Always a different person", "when_available": "A different person when there is one",
                               "never": "The same person may approve"}),
        Setting("approval.reminder_fraction_left", "approvals", "float", "Reminder before a request runs out",
                "One reminder when this share of a waiting request's time is left (0.25 is a quarter). 0 means never.",
                default=0.25, minimum=0.0, maximum=0.9),
        Setting("external_agents.show_request_detail", "approvals", "bool", "Show the agent's own description of an action",
                "A person deciding a request sees what the agent says it is doing, shortened. Off shows only the agent, the action name and the risk.",
                default=True),
        # ----------------------------------------------------------------- drift
        *_drift_settings(),
        # --------------------------------------------------------- platform checks
        *_platform_settings(),
        # ------------------------------------------------------------------ Teams
        Setting("teams.enabled", "teams", "bool", "Approvals in Microsoft Teams",
                "Post each waiting request to Teams, with buttons to approve or reject it.", default=False),
        Setting("teams.app_id", "teams", "guid", "Bot application id", "The application id of the Teams bot.",
                default="", allow_empty=True),
        Setting("teams.tenant_id", "teams", "guid", "Your Microsoft tenant id", "Only this tenant's people may press a button.",
                default="", allow_empty=True),
        Setting("teams.app_secret_env", "teams", "env_name", "Variable for the bot's secret",
                "The name of the environment variable that holds the bot's client secret.", default="TEAMS_BOT_SECRET"),
        Setting("teams.channel_id", "teams", "text", "Channel for requests",
                "Also post each request to this Teams channel. Leave empty to send only to the people who may decide it.",
                default="", allow_empty=True, pattern=_CHANNEL, pattern_help="a Teams channel id"),
        Setting("teams.allowed_tenants", "teams", "list_guid", "Other tenants to accept",
                "Extra Microsoft tenants whose people may press a button. Your own tenant is always accepted.", default=[]),
        Setting("teams.allowed_users", "teams", "list_guid", "Only these people may press a button",
                "Entra object ids. Empty means anyone in an accepted tenant who may decide the request.", default=[]),
        # ---------------------------------------------------- Copilot Studio gate
        Setting("copilot_studio_gate.enable", "copilot_gate", "bool", "Decide Copilot Studio tool calls",
                "While off, Second Shift answers Copilot Studio as the 'when it cannot decide' choice below says.", default=False),
        Setting("copilot_studio_gate.tenant_id", "copilot_gate", "guid", "Your Microsoft tenant id",
                "Calls from any other tenant are refused.", default="", allow_empty=True),
        Setting("copilot_studio_gate.app_id", "copilot_gate", "guid", "Application id given to Power Platform",
                "The application id Power Platform calls Second Shift with.", default="", allow_empty=True),
        Setting("copilot_studio_gate.audience", "copilot_gate", "text", "Application ID URI",
                "The address from the app registration that tokens are issued for, such as https://second-shift.example.com.",
                default="", allow_empty=True, pattern=_HTTPS_ADDRESS, pattern_help="an https address"),
        Setting("copilot_studio_gate.api_client_id", "copilot_gate", "guid", "Exposed API's own application id",
                "Only if tokens carry it as the audience. Usually empty.", default="", allow_empty=True),
        Setting("copilot_studio_gate.environments", "copilot_gate", "map", "Power Platform environments",
                "Which Dataverse host belongs to each environment id, one per line as: environment id = host.crm.dynamics.com.",
                default={}, max_items=50),
        Setting("copilot_studio_gate.unenrolled", "copilot_gate", "choice", "Agents that are not enrolled",
                "What happens to a tool call from a Copilot Studio agent nobody enrolled.", default="allow",
                choices=("allow", "block"),
                choice_labels={"allow": "Allow it and record that it was seen", "block": "Block it"}),
        Setting("copilot_studio_gate.on_error", "copilot_gate", "choice", "When Second Shift cannot decide",
                "What happens to a tool call when something goes wrong. Block is the safer choice.", default="block",
                choices=("block", "allow"), choice_labels={"block": "Block it", "allow": "Allow it"}),
        Setting("copilot_studio_gate.default_risk", "copilot_gate", "choice", "Risk of a tool nobody rated",
                "The risk used for a tool the enrollment does not rate.", default="medium",
                choices=("low", "medium", "high", "critical")),
        Setting("copilot_studio_gate.approval_window_seconds", "copilot_gate", "int", "How long a decision can be used",
                "After a person decides, Copilot Studio may retry within this time.", default=900, minimum=60,
                maximum=3600, unit="seconds"),
        Setting("copilot_studio_gate.record_user", "copilot_gate", "bool", "Record who used the agent",
                "Keep the Entra user id of the person in each audit entry.", default=False),
        # ------------------------------------------------------- Entra directory
        Setting("entra_directory.enable", "entra", "bool", "Look up people in Microsoft Entra",
                "Lets approval pickers and role pages find people by name.", default=False,
                env=("MAVERICK_ENTRA_DIRECTORY",)),
        Setting("entra_directory.tenant_id_env", "entra", "env_name", "Variable for the tenant id",
                "The name of the environment variable that holds your tenant id.", default=""),
        Setting("entra_directory.client_id_env", "entra", "env_name", "Variable for the client id",
                "The name of the environment variable that holds the client id.", default=""),
        Setting("entra_directory.client_secret_env", "entra", "env_name", "Variable for the client secret",
                "The name of the environment variable that holds the client secret.", default=""),
        Setting("entra_directory.service_principal_id", "entra", "guid", "Second Shift application (object id)",
                "The object id of the Second Shift enterprise application, where its app roles live.",
                default="", allow_empty=True),
        Setting("entra_directory.app_id", "entra", "guid", "Second Shift application (client id)",
                "The application (client) id, if you do not give the object id. With neither, the sign-in client id is used.",
                default="", allow_empty=True),
        Setting("entra_directory.cache_minutes", "entra", "int", "How long answers are kept",
                "Directory answers are kept in memory this long. 0 keeps nothing.", default=5, minimum=0,
                maximum=60, unit="minutes"),
        # ------------------------------------------------------------------- Ekko
        Setting("ekko.enable", "ekko", "bool", "Discover work to automate",
                "Off, no device can be enrolled and nothing is recorded.", default=False, env=("MAVERICK_EKKO",)),
        Setting("ekko.allowed_apps", "ekko", "list_choice", "Applications that may be observed",
                "Only these applications are recorded, and only by name. Mail, chat, CRM and similar apps can never be added.",
                default=[], choices=_ekko_choices(), max_items=64, empty_stored_as=()),
        Setting("ekko.retention_days", "ekko", "int", "How long activity is kept",
                "Each recorded activity is deleted after this many days.", default=14, minimum=2, maximum=30, unit="days"),
        Setting("ekko.enrollment_days", "ekko", "int", "Length of consent suggested",
                "The length of consent the enrollment page suggests to a person.", default=30, minimum=1, maximum=90, unit="days"),
        Setting("ekko.poll_interval_seconds", "ekko", "int", "How often a recorder asks what to do",
                "The time between a recorder's check-ins.", default=5, minimum=1, maximum=300, unit="seconds"),
        Setting("ekko.min_occurrences", "ekko", "int", "Repeats before something is suggested",
                "Work is suggested only after it has repeated this many times.", default=3, minimum=2, maximum=100),
        Setting("ekko.min_distinct_days", "ekko", "int", "Different days before something is suggested",
                "...on at least this many different days. Never more than the retention days.", default=2, minimum=2, maximum=30, unit="days"),
        # ---------------------------------------------------------- agent factory
        Setting("factory.provider", "factory", "choice", "Model service",
                "The service that drafts and tests agents.", default="", choices=("foundry_openai", "foundry_anthropic"),
                choice_labels={"foundry_openai": "Microsoft Foundry (OpenAI models)",
                               "foundry_anthropic": "Microsoft Foundry (Anthropic models)"}),
        Setting("factory.deployment", "factory", "text", "Model deployment", "The name of the model deployment to use.",
                default="", allow_empty=True, pattern=_DEPLOYMENT, pattern_help="a deployment name"),
        Setting("factory.endpoint_env", "factory", "env_name", "Variable for the model address",
                "The name of the environment variable that holds the model's address.",
                default="SECOND_SHIFT_FACTORY_MODEL_ENDPOINT"),
        Setting("factory.api_key_env", "factory", "env_name", "Variable for the model key",
                "The name of the environment variable that holds the model's key.",
                default="SECOND_SHIFT_FACTORY_MODEL_KEY"),
        Setting("factory.max_output_tokens", "factory", "int", "Longest answer from the model",
                "The most the model may write in one answer.", default=2000, minimum=16, maximum=200_000, unit="tokens"),
        Setting("factory.max_test_cases", "factory", "int", "Most test cases in a run", "A test run is refused above this.",
                default=20, minimum=1, maximum=200),
        Setting("factory.max_case_seconds", "factory", "float", "Longest a test case may take",
                "One test case is stopped after this time.", default=120.0, minimum=1, maximum=3600, unit="seconds"),
        Setting("factory.max_test_run_seconds", "factory", "float", "Longest a test run may take",
                "A whole test run is stopped after this time.", default=900.0, minimum=1, maximum=86_400, unit="seconds"),
        Setting("factory.max_test_run_cost_dollars", "factory", "float", "Most a test run may cost",
                "A test run is stopped when its estimated cost reaches this.", default=2.0, minimum=0.0,
                maximum=100_000, unit="dollars"),
        # ------------------------------------------------------------ access keys
        Setting("agent_keys.expiry_warning_days", "keys", "int", "Warn before an access key ends",
                "Administrators are alerted once when an agent's access key will end within this many days. 0 never warns.",
                default=14, minimum=0, maximum=365, unit="days"),
        # ------------------------------------------------------------ owner notes
        Setting("owner_note.enabled", "owner_note", "bool", "Send the weekly note to agent owners",
                "Each owner gets at most one email a week listing only what needs them. Needs alerts by email to be set up.",
                default=False),
        Setting("owner_note.weekday", "owner_note", "choice", "Day it goes out", "The day of the week the note is sent.",
                default="monday", choices=("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"),
                choice_labels={d: d.capitalize() for d in ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")}),
        Setting("owner_note.hour", "owner_note", "int", "Hour it goes out", "The hour of the day, in the time zone below.",
                default=8, minimum=0, maximum=23, unit="o'clock"),
        Setting("owner_note.timezone", "owner_note", "text", "Time zone", "A time zone name such as UTC or Europe/London.",
                default="UTC", pattern=_ZONE, pattern_help="a time zone name such as Europe/London", max_length=64),
        Setting("owner_note.teams", "owner_note", "bool", "Also message owners in Teams",
                "When Teams is set up, the same short list also goes to the owner's own Teams chat.", default=False),
        # ----------------------------------------------------------------- models
        *_model_settings(),
    ]
    return tuple(settings)


SECTIONS: tuple[Section, ...] = (
    Section("alerts", "Alerts", "Who is told when an agent is blocked, drifts or a request is about to run out.",
            tests=(("Send a test alert", "/api/v1/alerts/test", "Sends a test message to every alert channel now."),),
            secrets=(("Teams webhook address", "TEAMS_NOTIFY_WEBHOOK_URL"), ("Email password", "MAVERICK_SMTP_PASSWORD"))),
    Section("approvals", "Approvals", "How requests that wait for a person are decided and reminded about."),
    Section("drift", "Drift", "When a change in an outside agent's behaviour is a finding, and what happens next."),
    Section("platform_checks", "Platform checks",
            "Asking each platform which agents it has and how each is set up. Credentials are variable names only."
            " Where a platform's addresses (endpoints, environments, instances) are set stays in the deployment's file.",
            tests=(("Run a platform check now", "/api/v1/agent-watch/sync", "Asks every listed platform for its agents now."),)),
    Section("teams", "Teams", "Approving requests from Microsoft Teams.",
            tests=(("Send a test Teams card", "/api/v1/teams/test", "Checks the bot's credentials and sends a test card."),),
            secrets=(("Bot secret", "the variable named below"),)),
    Section("copilot_gate", "Copilot Studio gate", "Deciding the tool calls Copilot Studio agents make."),
    Section("entra", "Entra directory", "Looking up people in Microsoft Entra."),
    Section("ekko", "Ekko", "Finding repeated work worth automating from application names only."),
    Section("factory", "Agent factory", "The model that drafts and tests new agents, and the limits on a test run.",
            needs="factory"),
    Section("keys", "Access keys", "When people are warned that an agent's access key is about to end."),
    Section("owner_note", "Owner notes", "The weekly note that tells each agent owner what needs them."),
    Section("models", "Models", "The statistical limits that make a change in a model's data a finding."),
)

SETTINGS: tuple[Setting, ...] = _build()
_BY_KEY: dict[str, Setting] = {s.key: s for s in SETTINGS}
if len(_BY_KEY) != len(SETTINGS):  # pragma: no cover -- a build-time slip
    raise RuntimeError("a setting is listed twice")
ALLOWED_KEYS: frozenset[str] = frozenset(_BY_KEY)


def get(key: str) -> Setting:
    try:
        return _BY_KEY[key]
    except KeyError:
        raise SettingRefused("That is not a setting that can be changed here.", 404) from None


# --------------------------------------------------------------------------- validation

def _no_controls(text: str) -> bool:
    return all(ord(c) >= 32 and ord(c) != 127 for c in text)


def _text(setting: Setting, raw: Any, *, pattern: re.Pattern[str] | None = None, what: str = "",
          allow_empty: bool = False) -> str:
    if not isinstance(raw, str):
        raise SettingRefused(f"{setting.label}: enter text.")
    text = raw.strip()
    if not text:
        if allow_empty:
            return ""
        raise SettingRefused(f"{setting.label}: this cannot be empty.")
    if len(text) > setting.max_length or not _no_controls(text):
        raise SettingRefused(f"{setting.label}: this is too long or holds characters that are not allowed.")
    pattern = pattern or setting.pattern
    if pattern is not None and not pattern.fullmatch(text):
        raise SettingRefused(f"{setting.label}: enter {what or setting.pattern_help or 'a valid value'}.")
    return text


def _clean_list(setting: Setting, raw: Any) -> list[Any]:
    if not isinstance(raw, list):
        raise SettingRefused(f"{setting.label}: send a list.")
    if len(raw) > setting.max_items:
        raise SettingRefused(f"{setting.label}: at most {setting.max_items} entries.")
    return raw


def validate(setting: Setting, raw: Any) -> Any:
    """The value to save, or :class:`SettingRefused` saying what to fix. Nothing is coerced:
    a number sent as text, a boolean sent as a number and the like are refused."""
    kind = setting.kind
    if kind == "bool":
        if not isinstance(raw, bool):
            raise SettingRefused(f"{setting.label}: choose on or off.")
        return raw
    if kind in ("int", "float"):
        if isinstance(raw, bool) or not isinstance(raw, (int, float)) or (isinstance(raw, float) and not math.isfinite(raw)):
            raise SettingRefused(f"{setting.label}: enter a number.")
        if kind == "int" and (isinstance(raw, float) and raw != int(raw)):
            raise SettingRefused(f"{setting.label}: enter a whole number.")
        low, high = setting.minimum, setting.maximum
        if (low is not None and raw < low) or (high is not None and raw > high):
            raise SettingRefused(f"{setting.label}: enter a number from {_plain_number(low)} to {_plain_number(high)}.")
        return int(raw) if kind == "int" else float(raw)
    if kind == "choice":
        if not isinstance(raw, str) or raw not in setting.choices:
            raise SettingRefused(f"{setting.label}: choose one of the listed options.")
        return raw
    if kind == "text":
        return _free_text(setting, raw)
    if kind == "guid":
        return _text(setting, raw, pattern=_GUID, what=_GUID_WORDS, allow_empty=setting.allow_empty).lower()
    if kind == "env_name":
        if not isinstance(raw, str) or not _ENV_NAME.fullmatch(raw.strip()):
            raise SettingRefused(f"{setting.label}: {SECRET_REFUSAL}")
        return raw.strip()
    if kind == "list_choice":
        items = _clean_list(setting, raw)
        seen: list[str] = []
        for item in items:
            if not isinstance(item, str) or item not in setting.choices:
                raise SettingRefused(f"{setting.label}: choose from the listed options only.")
            if item not in seen:
                seen.append(item)
        return seen
    if kind == "list_guid":
        return list(dict.fromkeys(
            _text(setting, item, pattern=_GUID, what=_GUID_WORDS).lower()
            for item in _clean_list(setting, raw)))
    if kind == "list_text":
        return list(dict.fromkeys(_text(setting, item) for item in _clean_list(setting, raw)))
    if kind == "map":
        return _environments(setting, raw)
    raise SettingRefused("That setting cannot be changed here.", 409)  # pragma: no cover


def _free_text(setting: Setting, raw: Any) -> str:
    text = _text(setting, raw, allow_empty=setting.allow_empty)
    if setting.key == "owner_note.timezone":
        from .owner_note import _zone
        if _zone(text) is None:
            raise SettingRefused(f"{setting.label}: that time zone is not known. Use a name such as Europe/London.")
    return text


def _plain_number(value: float | None) -> str:
    return "" if value is None else (str(int(value)) if float(value) == int(value) else repr(float(value)))


def _environments(setting: Setting, raw: Any) -> dict[str, str]:
    from .copilot_studio_gate import _DATAVERSE_HOST
    from .copilot_studio_gate import _GUID as GATE_GUID

    if not isinstance(raw, dict):
        raise SettingRefused(f"{setting.label}: send environment ids with their hosts.")
    if len(raw) > setting.max_items:
        raise SettingRefused(f"{setting.label}: at most {setting.max_items} environments.")
    out: dict[str, str] = {}
    for env_id, host in raw.items():
        env_text = env_id.strip().lower() if isinstance(env_id, str) else ""
        host_text = host.strip().lower() if isinstance(host, str) else ""
        if not GATE_GUID.fullmatch(env_text) or not _DATAVERSE_HOST.fullmatch(host_text):
            raise SettingRefused(f"{setting.label}: each line must be an environment id, then =, then a host such as "
                                 "contoso.crm.dynamics.com.")
        out[env_text] = host_text
    return out


# ------------------------------------------------------------------------------ the layer

def layer_path() -> Path:
    from .config import settings_layer_path

    return settings_layer_path()


def _get_path(tree: Any, path: tuple[str, ...]) -> tuple[bool, Any]:
    node = tree
    for part in path:
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _set_path(tree: dict, path: tuple[str, ...], value: Any) -> None:
    node = tree
    for part in path[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
        else:
            child = dict(child)
        node[part] = child
        node = child
    node[path[-1]] = value


def locked_keys(*deployment: Mapping[str, Any]) -> frozenset[str]:
    """The settings the deployment's own files (not the layer) lock: ``[settings] locked`` of each tree
    given, together. A value that is not a list of names locks everything, so a typo cannot unlock one."""
    out: set[str] = set()
    for tree in deployment:
        table = tree.get(LOCKED_SECTION)
        if table is None:
            continue
        names = table.get("locked") if isinstance(table, dict) else ("?",)
        if names is None:
            continue
        if not isinstance(names, list) or any(not isinstance(n, str) for n in names):
            return ALLOWED_KEYS
        out.update(n.strip() for n in names)
    return frozenset(out)


def env_lock(setting: Setting) -> str:
    """The environment variable that decides this setting now, or ""."""
    for name in setting.env:
        if name in os.environ and (os.environ[name].strip() or setting.key == "ekko.enable"):
            return name
    return ""


def apply_layer(cfg: dict, raw: Mapping[str, Any], locked: frozenset[str]) -> dict:
    """``cfg`` with the layer's allowed, valid, unlocked values on top. ``config`` calls this between the
    deployment's file and the operator overlay. A value that is not on the allowlist, does not validate,
    is locked or is decided by an environment variable is ignored, so a hand-edited layer cannot do more
    than the page can."""
    if not raw:
        return cfg
    out = dict(cfg)
    for setting in SETTINGS:
        if setting.key in locked or env_lock(setting):
            continue
        found, value = _get_path(raw, setting.path)
        if not found:
            continue
        try:
            value = validate(setting, value)
        except SettingRefused:
            continue
        if setting.kind == "list_choice" and not value and setting.empty_stored_as is not None:
            value = list(setting.empty_stored_as)
        _set_path(out, setting.path, value)
    return out


def _read_layer_strict(path: Path) -> dict:
    """The layer as saved, parsed afresh. Raises ``SettingRefused`` (503) when it cannot be read or is not
    a table of tables: a write never replaces what it could not read."""
    from .file_lock import atomic_read_bytes

    try:
        data = atomic_read_bytes(path)
    except (FileNotFoundError, NotADirectoryError):
        return {}
    except OSError:
        raise SettingRefused(_LAYER_UNREADABLE, 503) from None
    try:
        tree = tomllib.loads(data.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        raise SettingRefused(_LAYER_UNREADABLE, 503) from None
    return tree


_LAYER_UNREADABLE = ("The settings saved in the dashboard cannot be read, so nothing was changed and the saved "
                     "settings are not being applied. Restore the file settings-layer.toml in the data folder "
                     "from a backup, or move it aside to start again.")


def _toml_key(name: str) -> str:
    return name if re.fullmatch(r"[A-Za-z0-9_-]+", name) else json.dumps(name, ensure_ascii=False)


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{_toml_key(str(k))} = {_toml_value(v)}" for k, v in value.items()) + "}"
    raise TypeError("a setting value of this kind cannot be saved")  # pragma: no cover


def dumps(tree: Mapping[str, Any], *, _prefix: tuple[str, ...] = ()) -> str:
    """The layer as TOML: scalars and lists first, then each sub-table, in a fixed order."""
    lines: list[str] = []
    tables = [(k, v) for k, v in tree.items() if isinstance(v, dict) and not _is_inline(_prefix + (k,))]
    for key, value in tree.items():
        if (key, value) not in tables:
            lines.append(f"{_toml_key(key)} = {_toml_value(value)}")
    text = ""
    if _prefix and lines:
        text += "[" + ".".join(_toml_key(p) for p in _prefix) + "]\n"
    text += "\n".join(lines) + ("\n" if lines else "")
    for key, value in tables:
        text += ("\n" if text else "") + dumps(value, _prefix=_prefix + (key,))
    return text


def _is_inline(path: tuple[str, ...]) -> bool:
    """A map setting is written as one inline table, so a reset removes it whole."""
    setting = _BY_KEY.get(".".join(path))
    return setting is not None and setting.kind == "map"


def _prune(tree: dict, path: tuple[str, ...]) -> None:
    parents = [tree]
    for part in path[:-1]:
        child = parents[-1].get(part)
        if not isinstance(child, dict):
            return
        parents.append(child)
    parents[-1].pop(path[-1], None)
    for depth in range(len(path) - 1, 0, -1):
        if not parents[depth]:
            parents[depth - 1].pop(path[depth - 1], None)


def layer_problem() -> str:
    """Why the saved settings cannot be used, or "" when they can (or none are saved)."""
    from .config import _read_toml_raw, config_source_errors

    _read_toml_raw(layer_path())  # reading is what records an error, so ask it to
    return _LAYER_UNREADABLE if str(layer_path()) in config_source_errors(include_tenant=False) else ""


# ------------------------------------------------------------------ what a person sees

def _deployment_trees() -> tuple[dict, dict, dict]:
    """The deployment's file, the operator overlay and the earlier dashboard overlay, each as saved
    (without the layer). Unreadable ones are empty here; ``layer_problem`` and the health check say so."""
    from .config import CONFIG_OVERLAY_ENV, _load_config_file, config_path, dashboard_overrides_path

    def read(path: Path) -> dict:
        try:
            return _load_config_file(path)
        except Exception:  # noqa: BLE001 -- an unreadable file is reported elsewhere
            return {}

    overlay = os.environ.get(CONFIG_OVERLAY_ENV)
    return (read(config_path()), read(Path(overlay).expanduser()) if overlay else {},
            read(dashboard_overrides_path()))


def _layer_tree() -> dict:
    from .config import _read_toml_raw

    try:
        return copy.deepcopy(dict(_read_toml_raw(layer_path())))
    except Exception:  # noqa: BLE001
        return {}


def _clamp(setting: Setting, raw: Any) -> tuple[bool, Any]:
    """What the feature itself would use for a saved value: the value if usable (numbers are
    clamped into range, as the readers do), else nothing."""
    if setting.kind in ("int", "float"):
        if isinstance(raw, bool) or not isinstance(raw, (int, float)) or (isinstance(raw, float) and not math.isfinite(raw)):
            return False, None
        if setting.kind == "int" and raw != int(raw):
            return False, None
        low = setting.minimum if setting.minimum is not None else raw
        high = setting.maximum if setting.maximum is not None else raw
        value = max(low, min(high, raw))
        return True, int(value) if setting.kind == "int" else float(value)
    if setting.kind in ("text", "guid", "env_name"):
        # A value the deployment wrote is shown as it is; only the page's own writes are held to the pattern.
        return (True, raw.strip()) if isinstance(raw, str) and len(raw) <= 2000 else (False, None)
    if setting.kind in ("list_text", "list_guid", "list_choice"):
        raw = [raw] if isinstance(raw, str) else raw
        if not isinstance(raw, list) or any(not isinstance(i, str) for i in raw):
            return False, None
        items = [i.strip().lower() if setting.kind != "list_text" else i.strip() for i in raw if i.strip()]
        if setting.kind == "list_choice":
            items = [i for i in dict.fromkeys(items) if i in setting.choices]
        return True, list(dict.fromkeys(items))
    if setting.kind == "map":
        if not isinstance(raw, dict):
            return False, None
        return True, {str(k).lower(): str(v).lower() for k, v in raw.items()}
    try:
        value = validate(setting, raw)
    except SettingRefused:
        return False, None
    return True, value


def _env_value(setting: Setting, name: str) -> Any:
    raw = os.environ.get(name, "").strip()
    if setting.kind == "bool":
        from .config import env_flag
        flag = env_flag(name)
        return bool(flag) if flag is not None else (False if name in os.environ and setting.key == "ekko.enable" else setting.default)
    if setting.kind == "choice":
        return raw.lower() if raw.lower() in setting.choices else setting.default
    return raw


def _variable_is_set(name: str) -> bool:
    if not name:
        return False
    try:
        from .secret_provider import get_secret
        return bool(str(get_secret(name) or "").strip())
    except Exception:  # noqa: BLE001 -- an unreadable secret is a missing one
        return False


def _describe_value(setting: Setting, value: Any) -> dict:
    out: dict[str, Any] = {"value": value}
    if setting.kind == "env_name":
        out["variable_set"] = _variable_is_set(value if isinstance(value, str) else "")
    return out


def _find(setting: Setting, trees: Mapping[str, dict], effective: dict) -> dict:
    """Where this setting's value comes from, whether the deployment locks it, and the value."""
    deployment, operator, earlier = trees["file"], trees["operator"], trees["earlier"]
    locked = setting.key in locked_keys(deployment, operator)
    variable = env_lock(setting)
    here = _get_path(trees["layer"], setting.path)
    if variable:
        return {"source": "environment", "source_text": f"Set by the environment variable {variable}. Change it there.",
                "locked": True, "locked_by": variable,
                "value": _env_value(setting, variable)}
    in_operator = _get_path(operator, setting.path)[0]
    if locked or in_operator:
        for tree in (operator, earlier, deployment):
            found, raw = _get_path(tree, setting.path)
            if found:
                ok, value = _clamp(setting, raw)
                return {"source": "deployment", "source_text": "Set by the deployment. Change it there.",
                        "locked": True, "locked_by": "", "value": value if ok else _default(setting)}
        return {"source": "deployment", "source_text": "Set by the deployment. Change it there.",
                "locked": True, "locked_by": "", "value": _default(setting)}
    if here[0]:
        ok, value = _clamp(setting, here[1])
        if ok:
            return {"source": "settings", "source_text": "Changed here.", "locked": False, "locked_by": "", "value": value}
    for label, tree in (("the dashboard's earlier settings", earlier), ("the deployment's settings file", deployment)):
        found, raw = _get_path(tree, setting.path)
        if found:
            ok, value = _clamp(setting, raw)
            if ok:
                return {"source": "deployment" if tree is deployment else "earlier",
                        "source_text": f"From {label}.", "locked": False, "locked_by": "", "value": value}
            return {"source": "default", "source_text": f"The value in {label} is not usable, so the built-in default applies.",
                    "locked": False, "locked_by": "", "value": _default(setting)}
    return {"source": "default", "source_text": "Built-in default.", "locked": False, "locked_by": "",
            "value": _default(setting)}


def _default(setting: Setting) -> Any:
    return copy.deepcopy(setting.default)


def _installed(section: Section) -> tuple[bool, str]:
    if section.needs == "factory":
        from .factory import NOT_INSTALLED, runtime_available

        return (True, "") if runtime_available() else (False, NOT_INSTALLED)
    return True, ""


def _secret_rows(section: Section, view: dict[str, dict]) -> list[dict]:
    rows = []
    for what, variable in section.secrets:
        name = variable
        if section.id == "teams":
            name = (view.get("teams.app_secret_env") or {}).get("value") or "TEAMS_BOT_SECRET"
        saved = False
        if section.id == "alerts":
            from .config import load_config
            notifications = (load_config() or {}).get("notifications") or {}
            email = notifications.get("email") if isinstance(notifications.get("email"), dict) else {}
            saved = bool(str(notifications.get("teams_webhook") or "").strip()) if variable.startswith("TEAMS") \
                else bool(str(email.get("password") or "").strip())
        rows.append({"what": what, "variable": name, "set": saved or _variable_is_set(name)})
    return rows


def _status_lines(section: Section) -> list[str]:
    """A line or two on whether a feature will act, for sections that have one."""
    if section.id != "owner_note":
        return []
    try:
        import time as _time

        from .owner_note import status
        found = status()
    except Exception:  # noqa: BLE001
        return ["The state of the weekly note could not be read."]
    if found["active"]:
        return ["The weekly note is on. The next one is due " + _time.strftime("%d %B %Y at %H:%M UTC", _time.gmtime(found["next_at"])) + "."]
    if not found["enabled"]:
        return ["The weekly note is off."]
    return ["The weekly note is on but cannot be sent: " + (found["email_problem"] or "email alerts are not set up.")]


def describe() -> dict:
    """Every section with its settings, each setting's effective value and source, for the page and the API."""
    from .config import load_config

    config_tree = load_config() or {}
    trees = {"layer": _layer_tree()}
    trees["file"], trees["operator"], trees["earlier"] = _deployment_trees()
    problem = layer_problem()
    sections: list[dict] = []
    for section in SECTIONS:
        installed, why = _installed(section)
        rows: list[dict] = []
        view: dict[str, dict] = {}
        for setting in SETTINGS:
            if setting.section != section.id:
                continue
            found = _find(setting, trees, config_tree)
            if setting.reader is not None and not found["locked_by"]:
                try:
                    found["value"] = setting.reader()
                except Exception:  # noqa: BLE001
                    pass
            row = {
                "key": setting.key, "label": setting.label, "help": setting.help, "kind": setting.kind,
                "default": _default(setting), "minimum": setting.minimum, "maximum": setting.maximum,
                "choices": [{"value": c, "label": setting.choice_labels.get(c, c)} for c in setting.choices],
                "unit": setting.unit, "note": setting.note, "restart": setting.restart,
                "pattern_help": setting.pattern_help, "allow_empty": setting.allow_empty,
                **found, **_describe_value(setting, found["value"]),
            }
            if setting.kind == "map":
                row["value_text"] = "\n".join(f"{k} = {v}" for k, v in (found["value"] or {}).items())
            if setting.kind == "env_name":
                row["secret_note"] = "Only the variable's name is kept here, never its value."
            rows.append(row)
            view[setting.key] = row
        sections.append({
            "id": section.id, "title": section.title, "about": section.about, "installed": installed,
            "not_installed": why, "settings": rows if installed else [],
            "tests": [{"label": a, "url": u, "what": w} for a, u, w in section.tests] if installed else [],
            "secrets": _secret_rows(section, view) if installed else [],
            "status": _status_lines(section) if installed else [],
        })
    return {"sections": sections, "layer_problem": problem, "layer_file": LAYER_BASENAME}


def setting_view(key: str) -> dict:
    """One setting as :func:`describe` shows it."""
    get(key)
    for section in describe()["sections"]:
        for row in section["settings"]:
            if row["key"] == key:
                return row
    raise SettingRefused("That setting is not available here.", 409)


# ------------------------------------------------------------------------------ changes

def _audit(kind: str, **payload: Any) -> None:
    """One audit row. Fails closed: when the log cannot take it, the change is not made."""
    from .audit import audit_event

    if not audit_event(kind, agent="settings", **payload):
        raise SettingRefused("This could not be written to the audit log, so nothing was changed. "
                             "Try again; if it keeps failing, check where the audit log is stored.", 503)


def _check_changeable(setting: Setting) -> dict:
    section = next(s for s in SECTIONS if s.id == setting.section)
    installed, why = _installed(section)
    if not installed:
        raise SettingRefused(why, 409)
    current = setting_view(setting.key)
    if current["locked"]:
        raise SettingRefused(f"{setting.label} is {current['source_text'][0].lower()}{current['source_text'][1:]}", 409)
    return current


def _write(setting: Setting, value: Any, *, remove: bool, actor: str, old: Any) -> None:
    from .config import reset_config_cache
    from .file_lock import atomic_write_text, cross_process_lock, ensure_private_directory

    path = layer_path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path):
        tree = _read_layer_strict(path)
        if remove:
            _prune(tree, setting.path)
        else:
            _set_path(tree, setting.path, value)
        _audit("setting_changed", setting=setting.key, old=old, new=None if remove else value,
               reset=remove, actor=actor, source="settings page")
        try:
            atomic_write_text(path, dumps(tree))
        except Exception as exc:  # noqa: BLE001
            try:
                _audit("setting_change_failed", setting=setting.key, actor=actor)
            except SettingRefused:
                pass
            raise SettingRefused("The change could not be saved. Nothing was changed.", 503) from exc
    reset_config_cache()


def change(key: str, raw: Any, *, actor: str) -> dict:
    """Save a new value for one setting. Returns the setting as the page shows it afterwards.
    Raises :class:`SettingRefused` for an unknown setting, a locked one, a value it does not take,
    an unreadable settings layer or an audit log that cannot take the entry."""
    setting = get(key)
    current = _check_changeable(setting)
    value = validate(setting, raw)
    stored = list(setting.empty_stored_as) if (setting.kind == "list_choice" and not value
                                               and setting.empty_stored_as is not None) else value
    _write(setting, stored, remove=False, actor=actor, old=current["value"])
    return setting_view(key)


def reset(key: str, *, actor: str) -> dict:
    """Remove the saved change, so the deployment's value (or the built-in default) applies again."""
    setting = get(key)
    current = _check_changeable(setting)
    _write(setting, None, remove=True, actor=actor, old=current["value"])
    return setting_view(key)


__all__ = [
    "ALLOWED_KEYS", "SECTIONS", "SETTINGS", "Setting", "SettingRefused", "apply_layer", "change", "describe",
    "dumps", "layer_path", "layer_problem", "locked_keys", "reset", "setting_view", "validate",
]
