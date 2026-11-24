"""The client for Second Shift's external agent gateway, over HTTP only.

Routes used (all under ``{address}/api/v1/external``, bearer = the agent's key):
``POST /runs/start``, ``POST /runs/{goal_id}/heartbeat``, ``POST /screen``,
``GET /approvals/{approval_id}?binding_sha256=...`` and ``POST /runs/{goal_id}/finish``.

The client fails closed. If Second Shift cannot be reached, refuses, gives an answer this code cannot read, or says
``continue: false``, the action does not happen and the run stops with a plain reason.
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

log = logging.getLogger("second_shift_runtime.governance")

DEFAULT_HEARTBEAT_SECONDS = 15.0


#: Why Second Shift said no, as its screening answer's ``kind`` names it: ``denied`` (asking again will not change
#: it), ``approval_required`` (a person must decide), ``halted`` (the emergency stop), ``contained`` (held for
#: review), ``limit`` (a budget or backlog; try later) and ``unavailable`` (it could not decide; try later).
KINDS = ("denied", "approval_required", "halted", "contained", "limit", "unavailable")


def kind_from_reason(reason: str, *, default: str = "denied") -> str:
    """The kind for a refusal that came without one (an older Second Shift, or a refused run start), read from
    its plain-language reason. Anything not recognised is ``default``."""
    text = (reason or "").lower()
    if "emergency stop" in text:
        return "halted"
    if "contained" in text:
        return "contained"
    return default


class GovernanceError(Exception):
    """Second Shift could not be used. The message is plain and safe to show. ``kind`` says whether asking
    again later may help (``unavailable``, ``limit``) or not (``denied``, ``halted``, ``contained``)."""

    def __init__(self, message: str, kind: str = "unavailable"):
        super().__init__(message)
        self.kind = kind if kind in KINDS else "unavailable"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    kind: str = ""  # empty when allowed; otherwise one of KINDS


class Governance:
    def __init__(self, address: str, agent_key: str, *, transport: httpx.BaseTransport | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                 approval_wait: float = 300.0, poll_interval: float = 3.0,
                 max_retries: int = 3, max_retry_wait: float = 60.0, timeout: float = 20.0):
        parts = urlsplit(address.strip())
        local = parts.hostname in ("localhost", "127.0.0.1", "::1")
        if not parts.hostname or parts.username or (parts.scheme != "https" and not (parts.scheme == "http" and local)):
            raise GovernanceError("The Second Shift address must be a web address starting with https://.")
        self._base = address.strip().rstrip("/") + "/api/v1/external"
        self._headers = {"Authorization": f"Bearer {agent_key}", "Accept": "application/json"}
        self._client = httpx.Client(transport=transport, timeout=timeout, follow_redirects=False, trust_env=False)
        self._sleep, self._clock = sleep, clock
        self._approval_wait, self._poll = approval_wait, poll_interval
        self._max_retries, self._max_retry_wait = max_retries, max_retry_wait
        self.goal_id: int | None = None
        self.heartbeat_seconds = DEFAULT_HEARTBEAT_SECONDS
        self.stop_reason: str | None = None
        self._lock = threading.Lock()
        self._halt = threading.Event()
        self._thread: threading.Thread | None = None

    # -- transport -----------------------------------------------------------------------------------------

    def _call(self, method: str, path: str, *, body: dict[str, Any] | None = None, params: dict[str, str] | None = None) -> dict[str, Any]:
        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.request(method, self._base + path, json=body, params=params, headers=self._headers)
            except httpx.TimeoutException as exc:
                raise GovernanceError("Second Shift took too long to answer, so the action was not allowed.") from exc
            except httpx.HTTPError as exc:
                raise GovernanceError("Second Shift could not be reached, so the action was not allowed.") from exc
            if response.status_code == 429:
                wait = _retry_after(response.headers.get("retry-after"))
                if attempt < self._max_retries and wait <= self._max_retry_wait:
                    self._sleep(wait)
                    continue
                raise GovernanceError("Second Shift asked the agent to slow down and the wait was too long, so the action was not allowed.", "limit")
            return self._decode(response)
        raise GovernanceError("Second Shift kept asking the agent to slow down.")  # pragma: no cover

    @staticmethod
    def _decode(response: httpx.Response) -> dict[str, Any]:
        if len(response.content) > 1_000_000:
            raise GovernanceError("Second Shift sent an answer that was too large to use.")
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.status_code in (401, 403) and not isinstance(data, dict):
            raise GovernanceError("Second Shift did not accept the agent key.", "denied")
        if response.status_code >= 400:
            detail = data.get("detail") if isinstance(data, dict) else None
            reason = " ".join(detail.split())[:300] if isinstance(detail, str) else ""
            if response.status_code == 401:
                reason = "Second Shift did not accept the agent key."
            raise GovernanceError(reason or f"Second Shift refused the request (status {response.status_code}).",
                                  kind_from_reason(reason, default="unavailable" if response.status_code >= 500 else "denied"))
        if not isinstance(data, dict):
            raise GovernanceError("Second Shift sent an answer this agent could not read, so the action was not allowed.")
        return data

    # -- the run -------------------------------------------------------------------------------------------

    def start(self, title: str, summary: str = "", declared: dict[str, str] | None = None) -> int:
        """Open the run. ``declared`` (``version``, ``config_digest``, ``model``) tells Second Shift the agent's
        build before its first action."""
        body: dict[str, Any] = {"title": title[:500], "summary": summary[:4000]}
        if declared:
            body["declared"] = declared
        data = self._call("POST", "/runs/start", body=body)
        goal = data.get("goal_id")
        if isinstance(goal, bool) or not isinstance(goal, int):
            raise GovernanceError("Second Shift did not say which run was opened.")
        self.goal_id = goal
        seconds = data.get("heartbeat_seconds")
        if isinstance(seconds, (int, float)) and not isinstance(seconds, bool) and seconds > 0:
            self.heartbeat_seconds = float(seconds)
        return goal

    def beat(self) -> bool:
        """Tell Second Shift the run is alive. Returns False, and records why, when the run must stop."""
        with self._lock:
            if self.stop_reason:
                return False
            try:
                data = self._call("POST", f"/runs/{self.goal_id}/heartbeat")
                if not isinstance(data.get("continue"), bool):
                    raise GovernanceError("Second Shift sent a heartbeat answer this agent could not read.")
            except GovernanceError as exc:
                self.stop_reason = str(exc)
                return False
            if not data["continue"]:
                reason = data.get("reason")
                self.stop_reason = ("Second Shift told the agent to stop: " + reason.strip()) if isinstance(reason, str) and reason.strip() \
                    else "Second Shift told the agent to stop."
                return False
            return True

    def start_beating(self) -> None:
        """Keep beating in the background, so a slow model call or tool does not let the run be reclaimed."""
        def loop() -> None:
            while not self._halt.wait(self.heartbeat_seconds):
                if not self.beat():
                    return

        self._thread = threading.Thread(target=loop, name="second-shift-heartbeat", daemon=True)
        self._thread.start()

    def stop_beating(self) -> None:
        self._halt.set()
        if self._thread:
            self._thread.join(timeout=5)

    # -- before an action ----------------------------------------------------------------------------------

    def screen(self, tool: str, risk: str, detail: str) -> Decision:
        """Ask before one tool call; wait for a person when Second Shift says one must decide."""
        try:
            data = self._call("POST", "/screen", body={"tool": tool[:128], "risk": risk, "detail": detail[:4000]})
            allowed = data.get("allowed")
            if not isinstance(allowed, bool):
                raise GovernanceError("Second Shift sent a screening answer this agent could not read, so the action was not allowed.")
            if allowed:
                return Decision(True, "allowed")
            if data.get("requires_approval") is True:
                return self._wait_for_approval(data)
            reason = data.get("reason")
            kind = data.get("kind")
            if kind not in KINDS:  # an older Second Shift sends none
                kind = kind_from_reason(reason if isinstance(reason, str) else "")
            return Decision(False, reason.strip() if isinstance(reason, str) and reason.strip() else "Second Shift did not allow this action.", kind)
        except GovernanceError as exc:
            return Decision(False, str(exc), exc.kind)

    def _wait_for_approval(self, screened: dict[str, Any]) -> Decision:
        approval_id = screened.get("approval_id")
        binding = screened.get("approval_binding_sha256")
        if isinstance(approval_id, bool) or not isinstance(approval_id, int) or not isinstance(binding, str) or not binding:
            raise GovernanceError("Second Shift asked for an approval but did not say which one, so the action was not allowed.", "unavailable")
        deadline = self._clock() + self._approval_wait
        while True:
            data = self._call("GET", f"/approvals/{approval_id}", params={"binding_sha256": binding})
            if data.get("approval_binding_sha256") not in (None, binding):
                raise GovernanceError("The approval no longer matches the action that was asked about, so it was not allowed.", "denied")
            status = data.get("status")
            if status == "approved":
                return Decision(True, "approved by a person")
            if status == "denied":
                return Decision(False, "A person denied this action.", "denied")
            if status != "pending":
                return Decision(False, f"The approval request ended without an approval (status {status}).", "denied")
            if self.stop_reason:
                return Decision(False, self.stop_reason, kind_from_reason(self.stop_reason))
            if self._clock() + self._poll > deadline:
                return Decision(False, f"No one approved this action within {int(self._approval_wait)} seconds, so it was not run.", "approval_required")
            self._sleep(self._poll)

    # -- the end -------------------------------------------------------------------------------------------

    def finish(self, report: dict[str, Any]) -> dict[str, Any]:
        return self._call("POST", f"/runs/{self.goal_id}/finish", body=report)

    def close(self) -> None:
        self.stop_beating()
        self._client.close()


def _retry_after(value: str | None) -> float:
    try:
        return max(0.0, float(value)) if value else 5.0
    except ValueError:
        return 5.0
