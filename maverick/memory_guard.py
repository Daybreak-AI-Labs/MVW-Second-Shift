"""Memory Guard -- governed reads/writes for agent memory (OWASP ASI06).

Persisting agent context creates a memory-poisoning surface: a malicious string
the agent ingested once (a web page, a tool result, an inbound message) can be
stored as "memory" and then replay as a standing instruction in every future
run. OWASP added this as **ASI06 -- Memory & Context Poisoning** to the 2026
Agentic Top 10. This module is Second Shift's screen between an agent and its memory
store. It does three things:

  1. **Provenance** -- stamp every memory write with who authored it
     (:class:`Provenance`: ``source`` + :class:`TrustTier` + :class:`Sensitivity`).
  2. **Write screening** -- run low-trust writes through an injection/poisoning
     tripwire (and the Shield, when wired) and quarantine the ones that look
     like smuggled instructions, so they never enter the store.
  3. **Trust-aware retrieval** -- keep low-trust memory out of the agent's
     standing brief (:func:`filter_facts`), with a stricter gate available for
     memory consulted right before an irreversible action
     (``filter_facts(high_risk=True)`` / :func:`allow_recall`).

Every decision is logged to the signed audit chain (:func:`audit_write`,
:func:`audit_recall`) so memory lineage is verifiable the same way tool calls
are. This is a *governance control*, not the whole defense: the deterministic,
LLM-free learning loops and the per-scope bulkheads are the structural defenses;
this is the ASI06 chokepoint on top.

OFF by default (``[memory_guard] enable`` / ``MAVERICK_MEMORY_GUARD=1``). When
off, writes are allowed unchanged and retrieval is unfiltered -- but provenance
columns are still recorded, so turning the guard on later governs existing
memory immediately.
"""
from __future__ import annotations

import re

# Injection / poisoning tripwire. These are the OWASP-ASI06 staples: smuggled
# role tags, "ignore previous instructions", instruction-override, secret
# exfiltration, and destructive-shell snippets. This is a deliberately small,
# high-signal list -- a heuristic that flags low-trust writes for quarantine,
# NOT a complete classifier. (label, pattern); matched case-insensitively
# across line breaks so splitting an instruction does not evade the tripwire.
_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (label, re.compile(rx, re.IGNORECASE | re.DOTALL))
    for label, rx in [
        ("ignore-previous",
         r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|earlier|"
         r"all)\b.{0,30}\b(instruction|message|context|prompt|rule)"),
        ("role-reassign", r"\byou\s+are\s+now\b"),
        ("from-now-on", r"\bfrom\s+now\s+on\b"),
        ("new-instructions",
         r"\bnew\s+(system\s+)?(instruction|prompt|directive|rule)"),
        ("fake-role-tag", r"</?\s*(system|assistant|developer)\s*>"),
        ("role-prefix-inject", r"\b(system|developer)\s*:\s*you\b"),
        ("reveal-secrets",
         r"\b(reveal|print|show|leak|exfiltrate)\b.{0,40}\b(system\s+prompt|"
         r"your\s+instruction|secret|api[\s_-]?key|password|token|credential)"),
        ("exfiltrate",
         r"\b(send|post|upload|exfiltrate|forward)\b.{0,40}"
         r"(https?://|ftp://|attacker|webhook)"),
        # curl/wget + a flag, a scheme, or a host.tld -- not prose like
        # "curl up on the couch".
        ("shell-fetch",
         r"\b(?:curl|wget)\s+(?:-{1,2}[a-z]|\w+://|[\w-]+\.[a-z]{2,})"),
        ("base64-decode", r"base64\b.{0,12}\b(decode|b64decode)"),
        # rm -rf, or an actual DROP TABLE/DATABASE ...; statement (terminated)
        # -- not a passing mention like "drop table talk and ship".
        ("destructive-shell",
         r"\brm\s+-rf\b|\bdrop\s+(?:table|database)\b[^;\n]{0,40};"),
        ("jailbreak", r"\b(jailbreak|dan\s+mode|developer\s+mode)\b"),
        ("conceal", r"\bdo\s*n[o']?t\s+(tell|inform|alert|notify)\b"),
        ("skip-approval",
         r"\bwithout\s+(asking|telling|notifying|approval|permission)\b"),
        ("override-safety",
         r"\boverride\b.{0,20}\b(safety|guard|shield|policy|governance)\b"),
    ]
]


def injection_markers(text: str) -> list[str]:
    """Tripwire labels that fired for ``text`` (empty = clean). Public so tests
    and other screens (knowledge ingest, fleet inbox) can reuse the same list."""
    if not text:
        return []
    return [label for label, rx in _INJECTION_PATTERNS if rx.search(text)]
