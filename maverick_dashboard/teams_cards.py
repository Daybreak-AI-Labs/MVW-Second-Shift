"""The Adaptive Cards the Microsoft Teams bot sends. Pure functions, no I/O.

Cards use Adaptive Cards 1.5 with Universal Actions (``Action.Execute``), which
Teams delivers back to the bot as an ``invoke`` activity named
``adaptiveCard/action``. Teams needs version 1.5 for ``Action.Execute``
(https://learn.microsoft.com/microsoftteams/platform/task-modules-and-cards/cards/universal-actions-for-adaptive-cards/work-with-universal-actions-for-adaptive-cards).

An approval card shows what is asked, how risky it is, who asked, when to
decide by and the request's fingerprint (its approval binding). Everything that
came from an agent, a person or a platform is escaped, so a request cannot dress
itself up as card formatting. The exact command of a request that carries one
stays on the Approvals page. This module does not decide anything.
"""
from __future__ import annotations

import datetime as _dt
import json
import re

SCHEMA = "http://adaptivecards.io/schemas/adaptive-card.json"
VERSION = "1.5"
CARD_CONTENT_TYPE = "application/vnd.microsoft.card.adaptive"
MAX_TEXT = 1200
# Teams refuses a bot message over 100 KB (413 MessageSizeTooBig) and advises
# staying under 80 KB
# (https://learn.microsoft.com/microsoftteams/platform/bots/how-to/format-your-bot-messages).
MAX_MESSAGE_BYTES = 80 * 1024
CONFIRM_RISKS = ("high", "critical")
AGENT_SAYS = "The agent says:"


def _escape_markdown(text: str) -> str:
    # A TextBlock renders Markdown: neutralise formatting and link characters in
    # anything that came from a request or an agent.
    return re.sub(r"([\\`*_\[\]()<>#!])", r"\\\1", text)


def _text(value: object, *, limit: int = MAX_TEXT) -> str:
    text = " ".join(str(value or "").split())
    return _escape_markdown(text[:limit])


def _block(text: str, *, weight: str = "default", size: str = "default", color: str = "default",
           spacing: str = "default") -> dict:
    block = {"type": "TextBlock", "text": text, "wrap": True}
    if weight != "default":
        block["weight"] = weight
    if size != "default":
        block["size"] = size
    if color != "default":
        block["color"] = color
    if spacing != "default":
        block["spacing"] = spacing
    return block


def _facts(rows: list[tuple[str, object]]) -> dict:
    return {"type": "FactSet", "facts": [{"title": title, "value": _text(value, limit=500) or "-"}
                                         for title, value in rows]}


def _card(body: list[dict], actions: list[dict] | None = None) -> dict:
    card = {"$schema": SCHEMA, "type": "AdaptiveCard", "version": VERSION, "body": body}
    if actions:
        card["actions"] = actions
    return card


def attachment(card: dict) -> dict:
    return {"contentType": CARD_CONTENT_TYPE, "content": card}


def fits_message(payload: dict) -> bool:
    """Whether ``payload`` stays within Teams' advised message size (counted as
    UTF-16, as Teams counts it)."""
    return len(json.dumps(payload).encode("utf-16-le")) <= MAX_MESSAGE_BYTES


def humanize(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.replace(".", " ").replace("_", " ").replace(":", " ") if " " not in text else text
    return text[:1].upper() + text[1:]


def when(timestamp: object) -> str:
    try:
        moment = _dt.datetime.fromtimestamp(float(timestamp), tz=_dt.timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return "Not stated"
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def _who(principal: object) -> str:
    try:
        from .identity_format import humanize_principal

        identity = humanize_principal(principal)
        return identity.name + (f" ({identity.kind.lower()})" if identity.kind else "")
    except Exception:  # noqa: BLE001 -- a name is decoration
        return str(principal or "")[:100]


def _bullets(items: object, *, show_detail: bool) -> list[dict]:
    """One block per line: a TextBlock does not keep a bare line break."""
    lines = [str(item) for item in items] if isinstance(items, (list, tuple)) else []
    if not show_detail:
        lines = [line for line in lines if not line.startswith(AGENT_SAYS)]
    if not lines:
        return [_block("None.")]
    return [_block(f"- {_text(line, limit=500)}") for line in lines[:12]]


def approval_card(view: dict, *, show_request_detail: bool = False, decided: dict | None = None,
                  note: str = "", dashboard_url: str = "") -> dict:
    """The approval request as a card.

    ``view`` is :func:`approval_decisions.approval_view`. A request that is no
    longer pending shows how it was decided and offers no buttons, whether the
    decision was made in Teams or on the Approvals page (``decided`` carries
    the result of a decision just made here). With ``show_request_detail`` the
    agent's own description of the action is shown; without it the card says
    only what Second Shift itself recorded."""
    approval = view["approval"]
    card = view.get("card")
    risk = str(approval.get("risk") or "medium").strip().lower()
    status = str(approval.get("status") or "pending")
    approval_id = int(approval["id"])
    heading = {"pending": "Approval needed"}.get(status, "Approval decided")
    body: list[dict] = [
        _block(heading, weight="bolder", size="large"),
        _block(_text(((card or {}).get("target") or {}).get("label")
                     or humanize(approval.get("action")) or "Reviewed action", limit=300),
               weight="bolder", size="medium"),
        _block(f"Risk: {_text(humanize(risk))}", weight="bolder",
               color="attention" if risk in CONFIRM_RISKS else "default"),
    ]
    if view.get("source_label"):
        body.append(_block(_text(view["source_label"], limit=200), color="attention"))
    if card:
        authority = card.get("authority") or {}
        body.append(_block(_text(card.get("summary")), spacing="medium"))
        body.append(_facts([
            ("Asked by", _who(authority.get("actor") or approval.get("requested_by"))),
            ("Applies to", (card.get("target") or {}).get("label") or approval.get("scope")),
            ("Decide by", when(card.get("expires_at"))),
            ("Request fingerprint", str(card.get("binding_sha256") or "")[:16]),
        ]))
        body.append(_block("What it will do", weight="bolder", spacing="medium"))
        body.extend(_bullets((card.get("parameters") or {}).get("summary"),
                             show_detail=show_request_detail))
        if card.get("display"):
            body.append(_block("The exact command is shown on the Approvals page."))
        consequences = card.get("consequences") or {}
        irreversible = bool(consequences.get("irreversible"))
        body.append(_block("What happens next" + (" - can't be undone" if irreversible else ""),
                           weight="bolder", spacing="medium",
                           color="attention" if irreversible else "default"))
        body.extend(_bullets(consequences.get("known_effects"), show_detail=True))
    else:
        body.append(_facts([("Asked by", _who(approval.get("requested_by"))),
                            ("Applies to", approval.get("scope"))]))
        body.append(_block(_text(approval.get("detail"))))
    if note:
        body.append(_block(_text(note, limit=500), color="attention", spacing="medium"))
    open_page = ([{"type": "Action.OpenUrl", "title": "Open in Second Shift",
                   "url": f"{dashboard_url.rstrip('/')}/approvals#approval-{approval_id}"}]
                 if dashboard_url else [])
    if status != "pending" or decided:
        outcome = str((decided or {}).get("status") or status)
        if outcome == "pending":
            label = (f"Approval recorded ({int(decided.get('approved_count') or 0)} of "
                     f"{int(decided.get('approvals_required') or 1)}); more approvers are needed.")
            body.append(_block(label, weight="bolder", spacing="medium"))
        else:
            word = {"approved": "Approved", "denied": "Rejected"}.get(outcome, humanize(outcome))
            who = (decided or {}).get("decided_by") or approval.get("decided_by")
            at = (decided or {}).get("decided_at") or approval.get("decided_at")
            line = f"{word} by {_who(who)}" if who else word
            if at:
                line += f" on {when(at)}"
            body.append(_block(_text(line, limit=300), weight="bolder", spacing="medium",
                               color="good" if outcome == "approved" else "attention"))
        if (decided or {}).get("audit") == "pending":
            body.append(_block("Saved, but not in effect yet while Second Shift finishes the "
                               "signed record.", color="warning"))
        return _card(body, open_page)
    if card is None:
        body.append(_block("This request is missing the details needed to approve it safely, or "
                           "its decide-by time has passed. Reject it and ask for a new request.",
                           color="attention", spacing="medium"))
    elif risk in CONFIRM_RISKS:
        body.append(_block("This is a " + _text(risk) + " risk action. Read what it will do, then "
                           "confirm below.", color="attention", spacing="medium"))
        body.append({"type": "Input.Toggle", "id": "acknowledged", "value": "false",
                     "valueOn": "true", "valueOff": "false",
                     "title": "I have read what this action will do."})
        if risk == "critical":
            body.append(_block("Type APPROVE to confirm this critical action.", weight="bolder"))
            body.append({"type": "Input.Text", "id": "confirmation", "placeholder": "APPROVE"})
    return _card(body, _decision_actions(approval_id, risk, card, open_page))


def _decision_actions(approval_id: int, risk: str, card: dict | None, open_page: list[dict]) -> list[dict]:
    data = {"approval_id": approval_id, "binding": str((card or {}).get("binding_sha256") or ""),
            "risk": risk}
    actions = list(open_page)
    if card:
        actions.append({"type": "Action.Execute", "title": "Approve", "verb": "approve",
                        "style": "positive", "data": data})
    # Rejecting never needs the acknowledgement, so it carries none of the inputs.
    actions.append({"type": "Action.Execute", "title": "Reject", "verb": "reject",
                    "style": "destructive", "data": data, "associatedInputs": "none"})
    return actions


def check_card() -> dict:
    """The card an administrator sends to check that Teams is set up."""
    return _card([
        _block("Second Shift test", weight="bolder", size="large"),
        _block("If you can read this, approval requests that need you will reach you here. "
               "Nothing is waiting for a decision, and this card has no buttons."),
    ])


def message_response(text: str) -> dict:
    """Invoke response that shows a message to the person who pressed a button."""
    return {"statusCode": 200, "type": "application/vnd.microsoft.activity.message",
            "value": _text(text, limit=1000)}


def card_response(card: dict) -> dict:
    """Invoke response that replaces the card in place."""
    return {"statusCode": 200, "type": CARD_CONTENT_TYPE, "value": card}


def welcome_text() -> str:
    return ("Hi, I'm Second Shift. I send you approval requests that need a decision and let "
            "you approve or reject them here. I do nothing else. If an administrator gave you a "
            "link code, send `link <code>` to connect this account.")


__all__ = ["AGENT_SAYS", "CARD_CONTENT_TYPE", "approval_card", "attachment", "card_response",
           "fits_message", "message_response", "check_card", "welcome_text", "when"]
