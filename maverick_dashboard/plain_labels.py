"""Plain-language labels for administration pages.

Stored values such as model identifiers (``openai:gpt-5.4``), configuration
sources (``environment:ANTHROPIC_API_KEY``, ``config.toml``) and setting keys
(``code_exec``) are exact and must stay exact in forms and storage. This
module turns them into the words a person sees, so templates never print the
raw value. Every function is total: an unknown value still gets a readable
label rather than an error.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

_UPPER_WORDS = {"gpt": "GPT", "ai": "AI", "llm": "AI model", "vl": "VL", "api": "API",
                "sms": "SMS", "ros": "ROS", "ui": "UI", "pro": "Pro"}
_BRAND_WORDS = {"deepseek": "DeepSeek", "openai": "OpenAI", "xai": "xAI",
                "openrouter": "OpenRouter", "minimax": "MiniMax", "qwen3": "Qwen3",
                "qwen": "Qwen", "kimi": "Kimi", "llama": "Llama", "grok": "Grok",
                "gemini": "Gemini", "claude": "Claude", "moonshot": "Moonshot"}


def provider_name(provider: str) -> str:
    """Short provider name: ``anthropic`` -> ``Anthropic``."""
    try:
        from maverick.llm import PROVIDER_LABELS
        label = PROVIDER_LABELS.get(provider)
    except Exception:  # pragma: no cover -- labels are best effort
        label = None
    if not label:
        label = _BRAND_WORDS.get(provider.lower(), provider.replace("_", " ").title())
    # "Anthropic (Claude)" -> "Anthropic"; "Ollama (self-hosted)" -> "Ollama".
    return re.sub(r"\s*\(.*\)\s*$", "", label).strip() or label


def _word(token: str) -> str:
    low = token.lower()
    if low in _UPPER_WORDS:
        return _UPPER_WORDS[low]
    if low in _BRAND_WORDS:
        return _BRAND_WORDS[low]
    if re.fullmatch(r"\d+(\.\d+)*[a-z]?", low):
        return token
    return token[:1].upper() + token[1:]


def _model_words(model_id: str) -> str:
    tail = model_id.rsplit("/", 1)[-1]
    if tail.lower().startswith("gpt-"):
        parts = tail.split("-")
        head = "GPT-" + parts[1] if len(parts) > 1 else "GPT"
        return " ".join([head] + [_word(p) for p in parts[2:]])
    parts = [p for p in re.split(r"[-_]", tail) if p]
    out: list[str] = []
    for part in parts:
        # Consecutive plain numbers are one version: claude-opus-4-8 -> 4.8.
        if part.isdigit() and out and re.fullmatch(r"\d+(\.\d+)*", out[-1]):
            out[-1] = out[-1] + "." + part
        else:
            out.append(_word(part))
    return " ".join(out) or model_id


def model_label(spec: object) -> str:
    """``openai:gpt-5.4`` -> ``GPT-5.4 · OpenAI``; ``claude-opus-4-8`` ->
    ``Claude Opus 4.8 · Anthropic``."""
    text = str(spec or "").strip()
    if not text:
        return ""
    provider, sep, model_id = text.partition(":")
    if not sep:
        provider, model_id = ("anthropic" if text.lower().startswith("claude") else ""), text
    words = _model_words(model_id)
    return f"{words} · {provider_name(provider)}" if provider else words


_SOURCE_LABELS = {
    "dashboard": "saved here in Settings",
    "config.toml": "set when Second Shift was installed",
    "operator overlay": "set by your organization's administrator",
    "tenant config": "set for this workspace",
}


def source_label(source: object) -> str:
    """Where a setting comes from, in words; never a file or variable name."""
    text = str(source or "").strip()
    if not text:
        return ""
    labels: list[str] = []
    for part in text.split(" + "):
        part = part.strip()
        if part.startswith("environment:"):
            label = "set on the computer running Second Shift"
        else:
            label = _SOURCE_LABELS.get(part, "set outside Second Shift")
        if label not in labels:
            labels.append(label)
    return " and ".join(labels)


CAPABILITY_LABELS = {
    "computer_use": "Control a desktop",
    "browser": "Browse websites",
    "web_search": "Search the web",
    "mobile_tools": "Use phones and tablets",
    "ros": "Work with connected robots",
    "code_exec": "Run code",
}

FEATURE_LABELS = {
    "employee_companions": "Employee companions",
    "workflow_readiness": "Workflow catalog",
    "project_reviews": "Project reviews",
    "deliverable_bundles": "Selected deliverable bundles",
    "project_workspaces": "Project workspaces",
    "task_handoffs": "Accepted task handoffs",
    "human_conversation_handoffs": "Human help in Chat",
    "outcome_measurement": "Outcome measurement",
    "commitment_viability": "Keep promises in view",
    "work_restructuring": "Share preparation safely",
    "portable_competence": "Share and qualify local rule structures",
    "private_task_computation": "Private task calculations",
    "semantic_rule_reuse": "Reuse complete rule-behavior evidence",
    "procedure_interactions": "Check local rules together",
    "operational_competence_acquisition": "Plan teaching questions",
    "request_program": "Prepare an answer for this request",
    "commitment_economic_alternatives": "Compare additional-work economics",
    "workflow_step_checks": "Try one workflow step",
    "applicability_regions": "Checked answer regions",
    "governed_rule_evolution": "Rewrite and check local rules",
    "recovery_visibility": "Understand a missing reply",
    "commitment_capability_learning": "Qualify additional work",
    "shared_decision_evidence": "Shared decision reviews",
    "guided_onboarding": "Guided first steps",
    "action_center": "Action center",
    "draft_recovery": "Recover unsaved drafts",
    "support_center": "Support reports",
    "record_search": "Search across records",
    "workspace_recovery": "Workspace backups",
    "signing_identity_transition": "Change of software publisher",
    "skills": "Skills library",
    "world_model": "Shared memory across tasks",
    "streaming": "Show replies as they are written",
    "pack_editing": "Edit agents and specialists",
    "role_editing": "Edit agent roles",
    "scheduling": "Scheduled workflows",
    "triggers": "Start workflows from other apps",
}

# The core agent roles, as a title and one line on what each does.
AGENT_ROLES = {
    "orchestrator": ("Planner", "Breaks a task into steps and hands each step to the right agent or specialist."),
    "researcher": ("Researcher", "Finds and reads sources, and gathers the facts a task needs."),
    "coder": ("Coder", "Writes and changes code."),
    "coding": ("Coding assistant", "Helps with smaller coding steps inside a larger task."),
    "writer": ("Writer", "Drafts documents, emails and reports."),
    "analyst": ("Analyst", "Works through numbers and data and explains what they show."),
    "revisor": ("Editor", "Improves a draft after feedback."),
    "verifier": ("Checker", "Checks finished work against what was asked before it is handed over."),
    "reviewer": ("Reviewer", "Reviews work and points out problems to fix."),
    "summarizer": ("Summarizer", "Writes short summaries of long material."),
    "skill_distiller": ("Skill builder", "Turns work that went well into reusable skills."),
    "vision": ("Image reader", "Reads screenshots, photos and scanned documents."),
    "translator": ("Translator", "Translates text between languages."),
}

EFFORT_LABELS = {"low": "Low", "medium": "Medium", "high": "High", "xhigh": "Very high", "max": "Maximum"}


def agent_role_title(role: object) -> str:
    key = str(role or "")
    return AGENT_ROLES.get(key, (key.replace("_", " ").capitalize(), ""))[0]


def agent_role_help(role: object) -> str:
    return AGENT_ROLES.get(str(role or ""), ("", ""))[1]


def capability_label(key: object) -> str:
    k = str(key or "")
    return CAPABILITY_LABELS.get(k) or k.replace("_", " ").capitalize()


def feature_label(key: object) -> str:
    k = str(key or "")
    return FEATURE_LABELS.get(k) or k.replace("_", " ").capitalize()


def day_text(day) -> str:
    """A calendar day the way browsers write it on English pages: "4 Oct 2026",
    "30 Sept 2026" (en-GB spells September "Sept")."""
    month = day.strftime("%b")
    return f"{day.day} {'Sept' if month == 'Sep' else month} {day.year}"


def datetime_text(value: object, *, seconds: bool = False, date_only: bool = False) -> str:
    """Epoch seconds as the shared server-side text: "4 Oct 2026, 14:01 UTC".

    The |datetime filter wraps this text in a <time> the browser rewrites in the
    viewer's zone; plain strings (option labels, chat replies, printed reports)
    use it directly. ``seconds`` adds ":05" where two moments a minute apart must
    stay distinct; ``date_only`` gives "4 Oct 2026". "" when unreadable.
    """
    if isinstance(value, bool):
        return ""
    try:
        when = datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return ""
    if date_only:
        return day_text(when)
    return f"{day_text(when)}, {when.strftime('%H:%M:%S' if seconds else '%H:%M')} UTC"


def money(value: object, decimals: int = 2, currency: str = "USD") -> str:
    """Money the way every page shows it (``mvMoney`` in second-shift-ui.js too):
    "$1,234.56" or "-$5.00", tiny non-zero amounts as "under $0.01".

    ``decimals=4`` is only for a labelled per-unit price ("$0.0030 per 1K
    tokens"). Another currency shows its code ("EUR 75.00").
    """
    try:
        amount = float(value or 0)
    except (TypeError, ValueError):
        amount = 0.0
    smallest = 10.0 ** -decimals
    if 0 < abs(amount) < smallest / 2:
        return "under " + money(smallest, decimals, currency)
    number = f"{abs(amount):,.{decimals}f}"
    sign = "-" if amount < 0 else ""
    code = str(currency or "USD").upper()
    return f"{sign}${number}" if code == "USD" else f"{sign}{code} {number}"


def percent(value: object) -> str:
    """A percentage with at most one decimal: 0 -> "0%", 37.46 -> "37.5%"."""
    try:
        amount = float(value or 0)
    except (TypeError, ValueError):
        amount = 0.0
    return f"{amount:,.1f}".removesuffix(".0") + "%"


def size(num_bytes: object) -> str:
    """Bytes as KB / MB / GB."""
    try:
        n = float(num_bytes or 0)
    except (TypeError, ValueError):
        return "0 KB"
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            if unit == "bytes":
                return f"{int(n)} bytes"
            return f"{n:,.1f} {unit}".replace(".0 ", " ")
        n /= 1024
    return f"{n:,.1f} TB"  # pragma: no cover


def risk_label(goal) -> dict | None:
    """``{"tier", "reasons"}`` when a task's wording looks medium or high risk.

    The same lexical check the task-start gate uses; it reads only the words,
    so the page calls it "looks ... risk" and never claims more."""
    try:
        from maverick.safety.goal_risk import classify_goal, plain_reasons
        found = classify_goal(getattr(goal, "title", "") or "", getattr(goal, "description", "") or "")
    except Exception:  # a label, never a reason for a page to fail
        return None
    if found.tier not in ("medium", "high"):
        return None
    return {"tier": found.tier, "reasons": plain_reasons(found.signals)}


def register(env) -> None:
    """Install the label filters on a Jinja environment (idempotent)."""
    env.filters.setdefault("risk_label", risk_label)
    env.filters.setdefault("model_label", model_label)
    env.filters.setdefault("source_label", source_label)
    env.filters.setdefault("capability_label", capability_label)
    env.filters.setdefault("feature_label", feature_label)
    env.filters.setdefault("money", money)
    env.filters.setdefault("percent", percent)
    env.filters.setdefault("agent_role", agent_role_title)
    env.filters.setdefault("agent_role_help", agent_role_help)
    env.filters.setdefault("effort_label", lambda v: EFFORT_LABELS.get(str(v or ""), str(v or "").capitalize()))
    env.filters.setdefault("filesize", size)
    env.filters.setdefault("fill_placeholders", fill_placeholders)
    env.filters.setdefault("pack_label", lambda d: pack_display_name(
        getattr(d, "name", ""), getattr(d, "persona", ""), getattr(d, "description", "")))


_PERSONA_TITLE = re.compile(
    r"^You are (?:the |an |a )?(?P<title>.+?)"
    r"(?=\s+for\s+(?:this|the|your|a|an)\b|\s+--|\s+—|:|,|\.|\s*\(|\s+(?:at|on|who|inside|within|in)\s)",
    re.DOTALL,
)


def _title_case(text: str) -> str:
    """Capitalise lowercase words; keep acronyms and brand casing as written."""
    small = {"and", "or", "of", "the", "for", "to", "in", "on", "a", "an", "&"}
    words = text.split()
    out = []
    for index, word in enumerate(words):
        if word.islower() and (index == 0 or word not in small):
            word = word[:1].upper() + word[1:]
        out.append(word)
    return " ".join(out)


def pack_display_name(name: object, persona: object = "", description: object = "") -> str:
    """Readable name for a specialist pack.

    ``aero_airworthiness`` -> ``Airworthiness Specialist``, read from the
    pack's own "You are the ... specialist" introduction when it has one,
    else its one-line description, else the humanized pack name.
    """
    match = _PERSONA_TITLE.match(str(persona or "").strip())
    if match:
        title = re.sub(r"\s+", " ", match.group("title")).strip(" -—")
        if 2 <= len(title) <= 60 and "_" not in title:
            return _title_case(title)
    summary = re.sub(r"\s+", " ", str(description or "")).strip().rstrip(".")
    if summary and len(summary) <= 60 and "_" not in summary:
        return _title_case(summary)
    return _title_case(str(name or "").replace("_", " ").replace("-", " ").strip()) or "Agent"


_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z0-9_\-]+)\s*\}\}")


def fill_placeholders(text: object) -> str:
    """Show template blanks as readable markers.

    ``Compare {{option_a}} vs {{option_b}}`` -> ``Compare [Option A] vs [Option B]``.
    """
    def label(match: re.Match) -> str:
        words = re.split(r"[_\-]+", match.group(1))
        return "[" + " ".join(w[:1].upper() + w[1:] for w in words if w) + "]"

    return _PLACEHOLDER.sub(label, str(text or ""))
