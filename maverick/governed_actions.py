"""Governed Actions -- typed, simulatable, lineage-tracked operations.

Borrowed from Palantir's ontology *Actions*, at agent scale: instead of an agent
running a free-form effect, a consequential operation is a declared ``Action``
with TYPED parameters and a risk class. Before it commits it is SIMULATED (a
preview of its effect with no side effects), gated by risk/approval, then
applied -- and every commit appends a tamper-evident LINEAGE link (hash-chained
exactly like :mod:`maverick.tools.provenance_chain`) so any outcome can be traced
back to the action, its inputs, and the skills/sources behind it.

Three Palantir borrows in one place:
  * **typed Actions** -- a registry of declared operations, not arbitrary calls;
  * **simulate-before-commit** -- preview the effect, gate the commit on risk;
  * **decision lineage** -- a verifiable chain from outcome to inputs.

Opt-in and fail-open per kernel rule 1: shipping this module changes nothing
(the kernel does not route through it by default); an operator/integration uses
it explicitly. Approval gating is enforced whenever ``commit`` is called;
``[actions] require_approval_at`` (default ``high``) sets the floor.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from time import time

_GENESIS = "0" * 64


def _safe_lineage_text(value: object, *, max_len: int = 4000) -> str:
    """Return bounded, redacted audit text without a raw-data fallback.

    Connector responses, effect previews, source labels, and even exception
    strings may contain credentials. If the redactor is unavailable, retain a
    content digest for correlation instead of writing the original value into
    the durable lineage ledger.
    """
    raw = str(value)
    try:
        from .safety.secret_detector import redact

        raw, _ = redact(raw)
    except Exception:  # pragma: no cover -- safe fallback is tested explicitly
        digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
        raw = f"<redaction unavailable; sha256={digest}>"
    return raw if len(raw) <= max_len else raw[:max_len] + "...(truncated)"


def _canonical(params: dict, *, max_len: int = 4000) -> str:
    """Stable redacted JSON for hashing/lineage, bounded before persistence."""
    try:
        raw = json.dumps(params, sort_keys=True, default=str)
    except Exception:  # pragma: no cover -- unserializable -> repr
        raw = repr(params)
    return _safe_lineage_text(raw, max_len=max_len)


def _link_hash(fields: dict, prev_hash: str) -> str:
    """Hash all lineage fields that consumers treat as verified audit data."""
    payload = dict(fields)
    payload["prev_hash"] = prev_hash
    payload.pop("hash", None)
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


__all__ = [
    "record_tool_lineage",
]


def _lineage_dir(store_dir: str | Path | None = None) -> Path:
    """Where per-goal lineage lives: ``data_dir("lineage")``, so an ACTIVE
    tenant's audit trail never mixes with another's and ``MAVERICK_HOME`` is
    honoured. A tenant binding that cannot be resolved raises rather than
    falling back to the shared directory."""
    if store_dir is not None:
        return Path(store_dir).expanduser()
    from .paths import data_dir
    return data_dir("lineage")


def record_tool_lineage(goal_id: int | None, action: str, params: object, *,
                        skills: tuple[str, ...] = (), sources: tuple[str, ...] = (),
                        actor: str = "", effect: str = "", result: str = "",
                        approver: str = "", transaction_id: str = "",
                        phase: str = "", force: bool = False,
                        strict: bool = False,
                        store_dir: str | Path | None = None) -> bool:
    """Append a tamper-evident lineage link for a CONSEQUENTIAL tool call
    (risk >= medium) to ``<store>/<goal_id>.ndjson``. Governed write callers can
    set ``force`` and ``strict`` so a PREPARE receipt is durable before an
    external effect occurs. Ordinary observability callers retain fail-soft
    behavior. Returns whether a receipt was persisted (or intentionally skipped
    because the action was low risk)."""
    try:
        from .safety.tool_risk import risk_rank, tool_risk
        if not force and risk_rank(tool_risk(str(action))) < risk_rank("medium"):
            return True  # only consequential actions are traced
        if goal_id is None:
            from .logging_config import current_goal_id
            goal_id = current_goal_id()
        f = _lineage_dir(store_dir)
        from .file_lock import (
            atomic_read_text,
            atomic_write_text,
            cross_process_lock,
            ensure_private_directory,
            ensure_private_file,
        )

        ensure_private_directory(f)
        basename = f"{int(goal_id)}.ndjson" if goal_id is not None else "standalone.ndjson"
        f = f / basename
        with cross_process_lock(f, strict=strict):
            prev = _GENESIS
            links: list[dict] = []
            if f.exists():
                ensure_private_file(f)
                for line in atomic_read_text(f, encoding="utf-8").splitlines():
                    if line.strip():
                        link = json.loads(line)
                        links.append(link)
                        prev = link.get("hash", prev)
            if strict and links and not _verify_links(links).startswith("VALID"):
                raise RuntimeError(
                    "existing governed-action lineage is not trustworthy"
                )
            pj = _canonical(params if isinstance(params, dict) else {"input": params})
            rec = {
                "ts": time(),
                "actor": _safe_lineage_text(actor, max_len=512),
                "action": _safe_lineage_text(action, max_len=512),
                "params_json": pj,
                "skills": [_safe_lineage_text(v, max_len=512) for v in skills],
                "sources": [_safe_lineage_text(v, max_len=1000) for v in sources],
                "effect": _safe_lineage_text(effect),
                "result": _safe_lineage_text(result),
                "approver": _safe_lineage_text(approver, max_len=512),
                "transaction_id": _safe_lineage_text(transaction_id, max_len=256),
                "phase": _safe_lineage_text(phase, max_len=128),
                "prev_hash": prev,
            }
            rec["hash"] = _link_hash(rec, prev)
            body = "".join(json.dumps(link) + "\n" for link in (*links, rec))
            atomic_write_text(f, body, mode=0o600, encoding="utf-8")
        return True
    except Exception:  # pragma: no cover -- strict callers exercise propagation
        if strict:
            raise
        return False


def _verify_links(links: list[dict]) -> str:
    expected = _GENESIS
    for i, link in enumerate(links):
        if not isinstance(link, dict):
            return f"BROKEN: link {i} is not an object"
        if link.get("prev_hash") != expected:
            return f"BROKEN: link {i} ({link.get('action')}) prev_hash mismatch"
        if link.get("hash") != _link_hash(link, expected):
            return f"BROKEN: link {i} ({link.get('action')}) content hash mismatch"
        expected = str(link.get("hash"))
    return f"VALID: {len(links)} link(s)" + (f", head {expected[:12]}..." if links else " (empty)")
