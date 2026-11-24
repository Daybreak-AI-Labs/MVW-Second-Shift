import httpx
import pytest

from second_shift_runtime.governance import Governance, GovernanceError

from fakes import FakeSecondShift


class Clock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def make(fake, clock=None, **kw):
    clock = clock or Clock()
    return Governance("https://ss.example.com", "agent-secret-key", transport=fake.transport, sleep=clock.sleep, clock=clock, **kw), clock


def test_start_returns_the_run_and_the_heartbeat_interval_and_uses_the_bearer_key():
    fake = FakeSecondShift()
    gov, _ = make(fake)
    assert gov.start("Research helper") == 77 and gov.heartbeat_seconds == 1000.0
    assert fake.auth_headers == {"Bearer agent-secret-key"}
    assert fake.calls[0] == ("POST", "/runs/start", {"title": "Research helper", "summary": ""})


def test_start_refusal_and_unreachable_are_governance_errors():
    fake = FakeSecondShift()
    fake.start_status = 403
    with pytest.raises(GovernanceError, match="contained pending review"):
        make(fake)[0].start("x")
    fake = FakeSecondShift()
    fake.unreachable = True
    with pytest.raises(GovernanceError, match="could not be reached"):
        make(fake)[0].start("x")


def test_the_address_must_be_https_unless_local():
    with pytest.raises(GovernanceError, match="https"):
        Governance("http://ss.example.com", "k")
    Governance("http://127.0.0.1:8000", "k").close()


def test_a_screened_allowed_call_is_allowed_and_sends_tool_risk_and_detail():
    fake = FakeSecondShift()
    gov, _ = make(fake)
    gov.start("x")
    assert gov.screen("fetch_web_page", "low", "Fetch the page").allowed
    assert fake.screened == [{"tool": "fetch_web_page", "risk": "low", "detail": "Fetch the page"}]


@pytest.mark.parametrize("answer", [{"allowed": False, "rule": "halted", "reason": "the emergency stop is on"}, {"reason": "?"}, {"allowed": "yes"}])
def test_refusals_and_unreadable_answers_do_not_allow(answer):
    fake = FakeSecondShift()
    fake.screens = lambda tool, body: answer
    gov, _ = make(fake)
    decision = gov.screen("t", "low", "d")
    assert not decision.allowed and decision.reason


def test_the_refusal_reason_is_passed_on():
    fake = FakeSecondShift()
    fake.screens = lambda tool, body: {"allowed": False, "reason": "the emergency stop is on"}
    assert make(fake)[0].screen("t", "low", "d").reason == "the emergency stop is on"


def test_an_unreachable_or_non_json_second_shift_fails_closed():
    fake = FakeSecondShift()
    gov, _ = make(fake)
    fake.unreachable = True
    assert not gov.screen("t", "low", "d").allowed
    gov = Governance("https://ss.example.com", "k", transport=httpx.MockTransport(lambda r: httpx.Response(200, text="<html>")))
    assert "could not read" in gov.screen("t", "low", "d").reason
    gov = Governance("https://ss.example.com", "k", transport=httpx.MockTransport(lambda r: httpx.Response(401, json={"detail": "invalid credentials"})))
    assert "did not accept the agent key" in gov.screen("t", "low", "d").reason
    gov = Governance("https://ss.example.com", "k", transport=httpx.MockTransport(lambda r: httpx.Response(302, headers={"location": "https://x"})))
    assert not gov.screen("t", "low", "d").allowed


def test_retry_after_is_respected_a_bounded_number_of_times():
    fake = FakeSecondShift()
    fake.rate_limit_first = 2
    gov, clock = make(fake)
    assert gov.screen("t", "low", "d").allowed and clock.slept == [2.0, 2.0]
    fake = FakeSecondShift()
    fake.rate_limit_first = 99
    gov, clock = make(fake, max_retries=3)
    assert "slow down" in gov.screen("t", "low", "d").reason and clock.slept == [2.0, 2.0, 2.0]
    gov = Governance("https://ss.example.com", "k", max_retry_wait=60, sleep=lambda s: pytest.fail("must not wait"),
                     transport=httpx.MockTransport(lambda r: httpx.Response(429, headers={"Retry-After": "3600"}, json={})))
    assert not gov.screen("t", "low", "d").allowed


def approval_fake(*statuses):
    fake = FakeSecondShift()
    fake.screens = lambda tool, body: {"allowed": False, "requires_approval": True, "approval_id": 9, "approval_binding_sha256": "b" * 64}
    fake.approvals = [{"approval_id": 9, "status": s, "approval_binding_sha256": "b" * 64} for s in statuses]
    return fake


def test_approval_wait_approved():
    fake = approval_fake("pending", "pending", "approved")
    gov, clock = make(fake, poll_interval=3)
    assert gov.screen("t", "high", "d").allowed
    polls = [c for c in fake.calls if c[1] == "/approvals/9"]
    assert len(polls) == 3 and clock.slept == [3, 3]


def test_the_approval_poll_carries_the_binding():
    seen = []
    fake = approval_fake("approved")
    inner = fake.__call__
    fake_transport = httpx.MockTransport(lambda r: (seen.append(r.url.params.get("binding_sha256")), inner(r))[1])
    gov = Governance("https://ss.example.com", "k", transport=fake_transport)
    assert gov.screen("t", "high", "d").allowed and seen[-1] == "b" * 64


def test_approval_wait_denied_and_other_endings():
    assert make(approval_fake("pending", "denied"))[0].screen("t", "high", "d").reason == "A person denied this action."
    decision = make(approval_fake("expired"))[0].screen("t", "high", "d")
    assert not decision.allowed and "expired" in decision.reason


def test_approval_wait_times_out():
    gov, clock = make(approval_fake("pending"), approval_wait=10, poll_interval=3)
    decision = gov.screen("t", "high", "d")
    assert not decision.allowed and "within 10 seconds" in decision.reason and clock.now <= 10


def test_an_approval_whose_binding_changed_is_not_honoured():
    fake = approval_fake("approved")
    fake.approvals = [{"approval_id": 9, "status": "approved", "approval_binding_sha256": "c" * 64}]
    assert "no longer matches" in make(fake)[0].screen("t", "high", "d").reason


def test_an_approval_request_without_an_id_is_refused():
    fake = FakeSecondShift()
    fake.screens = lambda tool, body: {"allowed": False, "requires_approval": True}
    assert not make(fake)[0].screen("t", "high", "d").allowed


def test_waiting_for_approval_ends_when_the_run_is_told_to_stop():
    fake = approval_fake("pending")
    gov, _ = make(fake)
    gov.stop_reason = "Second Shift told the agent to stop: emergency stop"
    assert gov.screen("t", "high", "d").reason.endswith("emergency stop")


def test_heartbeat_continue_false_records_the_reason_and_stays_stopped():
    fake = FakeSecondShift()
    fake.heartbeats = [{"continue": True, "reason": "ok"}, {"continue": False, "reason": "the emergency stop is on"}]
    gov, _ = make(fake)
    gov.start("x")
    assert gov.beat() is True
    assert gov.beat() is False and "emergency stop" in gov.stop_reason
    n = len(fake.calls)
    assert gov.beat() is False and len(fake.calls) == n


def test_an_unreadable_or_failed_heartbeat_stops_the_run():
    fake = FakeSecondShift()
    fake.heartbeats = [{"nothing": 1}]
    gov, _ = make(fake)
    assert gov.beat() is False and gov.stop_reason
    fake = FakeSecondShift()
    gov, _ = make(fake)
    fake.unreachable = True
    assert gov.beat() is False


def test_background_beats_notice_a_stop():
    import time

    fake = FakeSecondShift()
    fake.heartbeat_seconds = 0.02
    fake.heartbeats = [{"continue": True, "reason": "ok"}, {"continue": False, "reason": "contained"}]
    gov, _ = Governance("https://ss.example.com", "k", transport=fake.transport), None
    gov.start("x")
    gov.start_beating()
    deadline = time.time() + 3
    while not gov.stop_reason and time.time() < deadline:
        time.sleep(0.01)
    gov.close()
    assert "contained" in gov.stop_reason


# --- refusal kinds and the build declared at start ------------------------------------------------------

@pytest.mark.parametrize("answer,kind", [
    ({"allowed": False, "kind": "limit", "reason": "over budget"}, "limit"),
    ({"allowed": False, "kind": "unavailable", "reason": "try later"}, "unavailable"),
    ({"allowed": False, "kind": "halted", "reason": "the emergency stop is on"}, "halted"),
    ({"allowed": False, "kind": "made-up", "reason": "no"}, "denied"),                      # an unknown kind is "no"
    ({"allowed": False, "reason": "the emergency stop is on"}, "halted"),                   # an older Second Shift: read the reason
    ({"allowed": False, "reason": "agent is contained pending review"}, "contained"),
    ({"allowed": False, "reason": "tool not permitted"}, "denied"),
])
def test_a_refusal_carries_its_kind(answer, kind):
    fake = FakeSecondShift()
    fake.screens = lambda tool, body: answer
    gov, _ = make(fake)
    decision = gov.screen("t", "low", "d")
    assert not decision.allowed and decision.kind == kind


def test_an_allowed_decision_has_no_kind_and_failures_to_decide_are_unavailable():
    fake = FakeSecondShift()
    gov, _ = make(fake)
    assert gov.screen("t", "low", "d").kind == ""
    fake.unreachable = True
    assert gov.screen("t", "low", "d").kind == "unavailable"


def test_an_approval_wait_that_runs_out_is_approval_required_and_a_person_saying_no_is_denied():
    from test_loop import approval_fake

    gov, _ = make(approval_fake("pending"), approval_wait=10.0, poll_interval=3.0)
    assert gov.screen("t", "low", "d").kind == "approval_required"
    gov, _ = make(approval_fake("denied"))
    assert gov.screen("t", "low", "d").kind == "denied"


def test_start_sends_the_declared_build_only_when_given():
    fake = FakeSecondShift()
    gov, _ = make(fake)
    gov.start("x", declared={"version": "1", "config_digest": "d", "model": "m"})
    assert fake.calls[0][2]["declared"] == {"version": "1", "config_digest": "d", "model": "m"}


def test_a_refused_start_keeps_the_kind():
    fake = FakeSecondShift()
    fake.start_status = 403
    with pytest.raises(GovernanceError) as seen:
        make(fake)[0].start("x")
    assert seen.value.kind == "contained"
