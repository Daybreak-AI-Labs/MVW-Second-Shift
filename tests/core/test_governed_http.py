"""The explicit transport checks policy before delegating network effects."""
import httpx
import pytest
from maverick.enterprise import EgressBlocked
from maverick.governed_http import guarded_sender


@pytest.mark.parametrize("url", ["/relative", "//other.example/path", "file:///secret", "http://"])
def test_relative_or_invalid_target_is_rejected_before_sending(monkeypatch, url):
    sent = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda target: sent.append(target))
    with pytest.raises(ValueError, match="absolute HTTP URL"):
        guarded_sender(lambda *args, **kwargs: sent.append(args))(url)
    assert not sent


def test_requests_style_redirect_flag_is_rejected(monkeypatch):
    seen = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: seen.append(url))
    with pytest.raises(ValueError, match="redirect"):
        guarded_sender(lambda *a, **kw: seen.append("sent"))(
            "https://api.example.com", allow_redirects=True,
        )
    assert not seen


@pytest.mark.parametrize("method", ["get", "post", "put", "patch", "delete", "head", "options"])
def test_migrated_httpx_sender_preserves_arguments_and_monkeypatch_seam(monkeypatch, method):
    events = []
    response = object()
    timeout = httpx.Timeout(2.5)

    def sender(*args, **kwargs):
        events.append(("send", args, kwargs))
        return response

    monkeypatch.setattr(httpx, method, sender)
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: events.append(("check", url)))
    result = guarded_sender(getattr(httpx, method))(
        "https://api.example.com/path", headers={"X-Test": "value"}, timeout=timeout,
        follow_redirects=False,
    )
    assert result is response
    assert events == [
        ("check", "https://api.example.com/path"),
        ("send", ("https://api.example.com/path",), {
            "headers": {"X-Test": "value"}, "timeout": timeout, "follow_redirects": False,
        }),
    ]


def test_sender_failure_is_not_retried_or_replaced(monkeypatch):
    calls = []
    failure = httpx.ConnectTimeout("upstream timeout")
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: None)

    def sender(url, **kwargs):
        calls.append(url)
        raise failure

    with pytest.raises(httpx.ConnectTimeout) as caught:
        guarded_sender(sender)("https://api.example.com", timeout=2)
    assert caught.value is failure
    assert calls == ["https://api.example.com"]


def test_policy_is_rechecked_each_time_a_sender_is_used(monkeypatch):
    checks = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: checks.append(url))
    sender = guarded_sender(lambda url: url)
    assert sender("https://one.example") == "https://one.example"
    assert sender("https://two.example") == "https://two.example"
    assert checks == ["https://one.example", "https://two.example"]


def test_pinned_client_checks_policy_before_resolving_dns(monkeypatch):
    from maverick.tools import _ssrf

    def deny(url):
        raise EgressBlocked("denied")

    def no_dns(*args, **kwargs):
        pytest.fail("a denied host must not be resolved")

    monkeypatch.setattr("maverick.egress_guard._check", deny)
    monkeypatch.setattr(_ssrf.socket, "getaddrinfo", no_dns)
    with pytest.raises(EgressBlocked):
        _ssrf.safe_client("https://example.com")
