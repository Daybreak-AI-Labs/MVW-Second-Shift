"""Interface text. The interface is English; these helpers keep the template contract."""
from __future__ import annotations

DEFAULT_LANG = "en"

MESSAGES: dict[str, dict[str, str]] = {
    "nav.approvals": {"en": "Approvals"},
    "label.status": {"en": "Status"},
    "label.created": {"en": "Created"},
    "label.owner": {"en": "Owner"},
    "action.start": {"en": "Start"},
    "action.cancel": {"en": "Cancel"},
    "action.approve": {"en": "Approve"},
    "action.deny": {"en": "Deny"},
    "action.search": {"en": "Search"},
    "chrome.skip_to_content": {"en": "Skip to content"},
    "chrome.account": {"en": "Your account"},
    "chrome.sign_out": {"en": "Sign out"},
}


def t(key: str, lang: str = DEFAULT_LANG) -> str:
    row = MESSAGES.get(key)
    return row["en"] if row else key
