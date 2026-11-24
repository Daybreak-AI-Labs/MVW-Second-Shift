"""The enterprise boundary, tested at the layer where requests leave.

``enterprise.py`` promises one property -- *"Sensitive data physically cannot
reach a third-party API"*. The guard wraps the HTTP client libraries, so
connectors that make direct outbound HTTP, such as ``gmail_tool``,
``salesforce_tool``, ``slack_bot``, ``replicate_tool`` and
``maverick_knowledge/embed.py``, are covered without calling a check
themselves.

A pure-policy test asserting ``egress_permitted(...)`` returns False, or a
per-tool test that calls one tool's ``_run`` and greps its returned error
string, cannot detect a bypass, because neither ever issues a request. A
connector added with raw ``httpx`` calls would keep both green.

So these tests make real calls through real client libraries and assert on what
the network layer does. The blocked cases never reach a socket -- the guard
raises above the transport -- and the permitted cases are asserted by their
*connection* failing, which proves the guard let them through.
"""

from __future__ import annotations

import urllib.request

import pytest

from maverick import egress_guard
from maverick.enterprise import EgressBlocked

httpx = pytest.importorskip("httpx")

#: Refused by DNS/connect rather than by policy, so a connection error proves
#: the guard permitted the request instead of blocking it.
UNROUTABLE = "http://127.0.0.1:9/probe"


@pytest.fixture(autouse=True)
def _leave_the_guard_installed():
    """Restore the process-wide guard after every test in this file.

    Several tests here uninstall it deliberately. Leaving it off would silently
    disarm the boundary for every later test in the session.
    """
    yield
    # Direct compatibility probes patch synthetic client classes while the
    # process guard is intentionally uninstalled.  They do not participate in
    # the runtime ``_patched`` registry, so discard their synthetic restore
    # entries before reinstalling the real libraries.
    egress_guard._originals.clear()
    egress_guard._compatibility.clear()
    egress_guard.install()


@pytest.fixture
def guarded(monkeypatch):
    """Enterprise mode on, guard installed, torn down cleanly."""
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    egress_guard.install()
    yield


@pytest.fixture
def unguarded_mode(monkeypatch):
    """Guard installed but enterprise mode OFF -- the default posture."""
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    egress_guard.install()
    yield


def _allowed(monkeypatch, *hosts):
    monkeypatch.setattr(
        "maverick.enterprise._allowed_egress_hosts", lambda: frozenset(hosts))


def test_a_raw_httpx_call_is_blocked(guarded) -> None:
    """No tool, no wrapper, no gate call. Just httpx, as 60 connectors use it.

    This is the assertion the suite never had. Before the guard it fails: the
    request goes out.
    """
    with pytest.raises(EgressBlocked):
        httpx.get("https://api.example.com/v1/customers", timeout=1.0)


def test_a_raw_httpx_client_is_blocked(guarded) -> None:
    with pytest.raises(EgressBlocked), httpx.Client(timeout=1.0) as c:
        c.post("https://api.example.com/upload", json={"pii": "x"})


@pytest.mark.asyncio
async def test_a_raw_async_httpx_client_is_blocked(guarded) -> None:
    async with httpx.AsyncClient(timeout=1.0) as c:
        with pytest.raises(EgressBlocked):
            await c.get("https://api.example.com/v1/me")


def test_a_raw_urllib_call_is_blocked(guarded) -> None:
    """Nine production modules use urllib, including http_fetch itself."""
    with pytest.raises(EgressBlocked):
        urllib.request.urlopen("https://api.example.com/data", timeout=1.0)


def test_a_urllib_opener_is_blocked(guarded) -> None:
    """build_opener bypasses urlopen, so the wrapper sits on OpenerDirector."""
    opener = urllib.request.build_opener()
    with pytest.raises(EgressBlocked):
        opener.open("https://api.example.com/data", timeout=1.0)


def test_a_urllib_request_object_is_blocked(guarded) -> None:
    """urlopen also accepts a Request, whose URL lives on .full_url."""
    req = urllib.request.Request(
        "https://api.example.com/data", headers={"X": "1"})
    with pytest.raises(EgressBlocked):
        urllib.request.urlopen(req, timeout=1.0)


def test_a_wrapped_urllib_string_is_checked_on_its_real_host(unguarded_mode, monkeypatch) -> None:
    """urllib unwraps `URL:http://h/` and `<http://h/>`; the guard must see
    `h`, not an empty host that skips the tenant egress plane."""
    monkeypatch.setattr("maverick.tenant.egress.host_allowed",
                        lambda host: host != "169.254.169.254")
    opener = urllib.request.build_opener()
    for url in ("URL:http://169.254.169.254/latest", "<http://169.254.169.254/latest>"):
        with pytest.raises(EgressBlocked):
            opener.open(url, timeout=1.0)


def test_a_raw_requests_call_is_blocked(guarded) -> None:
    requests = pytest.importorskip("requests")
    with pytest.raises(EgressBlocked):
        requests.get("https://api.example.com/data", timeout=1.0)


def test_the_guard_is_a_noop_when_enterprise_mode_is_off(unguarded_mode) -> None:
    """The load-bearing negative control.

    A guard that blocked by default would "pass" every test above while
    breaking every default install -- the zero-config path calls a cloud LLM.
    A connection error here proves the request was permitted and simply had
    nowhere to go.
    """
    with pytest.raises(httpx.HTTPError):
        httpx.get(UNROUTABLE, timeout=0.5)


def test_a_local_endpoint_is_permitted_under_enterprise_mode(guarded) -> None:
    """Local LLMs and sidecars must keep working inside the boundary."""
    with pytest.raises(httpx.HTTPError):
        httpx.get(UNROUTABLE, timeout=0.5)


def test_an_allowlisted_host_is_permitted(guarded, monkeypatch) -> None:
    _allowed(monkeypatch, "allowed.internal")
    try:
        httpx.get("https://allowed.internal/x", timeout=0.5)
    except EgressBlocked:  # pragma: no cover - the failure this pins
        pytest.fail("an allow-listed host must not be blocked")
    except Exception:
        pass  # DNS/connect failure is the expected outcome


def test_a_non_allowlisted_host_is_still_blocked(guarded, monkeypatch) -> None:
    """Negative control for the allow-list: it must not become allow-all."""
    _allowed(monkeypatch, "allowed.internal")
    with pytest.raises(EgressBlocked):
        httpx.get("https://other.example.com/x", timeout=0.5)


def test_a_redirect_to_a_denied_host_is_blocked(guarded, monkeypatch) -> None:
    """An allow-listed host must not be able to hand off to a denied one.

    The first endpoint is genuinely reached and returns a 302. The second URL
    is then checked as a new request and refused before DNS/connect.
    """
    import http.server
    import socketserver
    import threading

    ports: dict[str, int] = {}

    class _Redirector(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://denied.test:{ports['b']}/x")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), _Redirector)
    ports["a"] = srv.server_address[1]
    ports["b"] = 9
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # Permit the first hop only, and prove policy is invoked again with the
        # rebuilt redirect URL rather than reusing the first-hop decision.
        checked_urls = []

        def local_only_for_first_hop(url):
            checked_urls.append(url)
            return f":{ports['a']}" in url

        monkeypatch.setattr(
            "maverick.enterprise._is_local_endpoint",
            local_only_for_first_hop,
        )
        _allowed(monkeypatch)
        with pytest.raises(EgressBlocked):
            httpx.get(f"http://127.0.0.1:{ports['a']}/start",
                      follow_redirects=True, timeout=3.0)
        assert any(f":{ports['a']}/start" in url for url in checked_urls)
        assert any("denied.test" in url for url in checked_urls)
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_first_hop_is_still_permitted(guarded, monkeypatch) -> None:
    """Positive control for the test above.

    If the guard simply blocked everything once redirects were involved, the
    redirect test would pass while the feature was broken.
    """
    monkeypatch.setattr("maverick.enterprise._is_local_endpoint",
                        lambda url: True)
    with pytest.raises(httpx.HTTPError):
        httpx.get(UNROUTABLE, timeout=0.5)


@pytest.mark.asyncio
async def test_async_permitted_hop_preserves_async_stream_contract(
    guarded,
) -> None:
    """The async wrapper must delegate to AsyncClient's own one-hop method."""
    async with httpx.AsyncClient(timeout=0.5) as client:
        with pytest.raises(httpx.HTTPError) as caught:
            await client.get(UNROUTABLE)
    assert "sync Client instance" not in str(caught.value)


def test_a_mock_transport_is_not_blocked(guarded) -> None:
    def handler(request):
        return httpx.Response(200, text="ok")

    with httpx.Client(transport=httpx.MockTransport(handler)) as c:
        assert c.get("https://denied.example.com/x").status_code == 200


def test_an_unknown_sync_transport_is_checked_before_it_can_run(guarded) -> None:
    """A custom BaseTransport is network-capable unless explicitly proven not."""

    class SocketLikeTransport(httpx.BaseTransport):
        reached = False

        def handle_request(self, request):
            self.reached = True
            return httpx.Response(200, text="escaped", request=request)

    transport = SocketLikeTransport()
    with httpx.Client(transport=transport) as client:
        with pytest.raises(EgressBlocked):
            client.get("https://denied.example.com/x")
    assert transport.reached is False


def test_an_unknown_transport_redirect_is_checked_before_second_hop(
    guarded,
    monkeypatch,
) -> None:
    """Custom transports cannot use an allowed first hop to bypass policy."""
    calls = []

    class RedirectingTransport(httpx.BaseTransport):
        def handle_request(self, request):
            calls.append(str(request.url))
            return httpx.Response(
                302,
                headers={"location": "https://denied.example.com/steal"},
                request=request,
            )

    _allowed(monkeypatch, "allowed.example.com")
    with httpx.Client(transport=RedirectingTransport()) as client:
        with pytest.raises(EgressBlocked):
            client.get(
                "https://allowed.example.com/start",
                follow_redirects=True,
            )
    assert calls == ["https://allowed.example.com/start"]


@pytest.mark.asyncio
async def test_an_unknown_async_transport_is_checked_before_it_can_run(
    guarded,
) -> None:
    """The same fail-closed classification applies to AsyncBaseTransport."""

    class AsyncSocketLikeTransport(httpx.AsyncBaseTransport):
        reached = False

        async def handle_async_request(self, request):
            self.reached = True
            return httpx.Response(200, text="escaped", request=request)

    transport = AsyncSocketLikeTransport()
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(EgressBlocked):
            await client.get("https://denied.example.com/x")
    assert transport.reached is False


def test_a_custom_mock_subclass_is_not_allowed_to_claim_in_process(
    guarded,
) -> None:
    """Only the exact known mock type is exempt; overrides can perform I/O."""

    class SocketLikeMock(httpx.MockTransport):
        reached = False

        def handle_request(self, request):
            self.reached = True
            return httpx.Response(200, text="escaped", request=request)

    transport = SocketLikeMock(lambda request: httpx.Response(200))
    with httpx.Client(transport=transport) as client:
        with pytest.raises(EgressBlocked):
            client.get("https://denied.example.com/x")
    assert transport.reached is False


def test_a_wrapped_network_transport_is_still_checked(guarded, monkeypatch) -> None:
    """The negative control that makes the rule above safe.

    `tools/_ssrf._PinnedTransport` WRAPS an httpx network transport rather than
    being one, so a rule of "only HTTPTransport counts as network" would skip
    the check for exactly the requests most worth checking. Unknown transports
    fail closed, and this pins that behavior.
    """
    from maverick.tools import _ssrf

    inner = httpx.HTTPTransport()
    pinned = _ssrf._PinnedTransport("denied.example.com",
                                    "denied.example.com", "203.0.113.1", inner)
    from maverick.egress_guard import _is_network_transport
    assert _is_network_transport(pinned) is True
    assert _is_network_transport(httpx.MockTransport(lambda r: None)) is False


def test_an_unresolvable_transport_fails_closed() -> None:
    """"We cannot tell what this is" must mean "check it"."""
    from maverick.egress_guard import _reaches_the_network

    class _Odd:
        def _transport_for_url(self, url):
            raise RuntimeError("no idea")

    assert _reaches_the_network(_Odd(), type("R", (), {"url": "x"})()) is True


def test_the_guard_does_not_disable_ssrf_pinning(guarded, monkeypatch) -> None:
    """The pinned transport sits below the one-hop seam; both must still apply.

    If the guard had replaced the transport rather than wrapping the client
    method, this would silently drop SSRF protection.
    """
    from maverick.tools import _ssrf

    _allowed(monkeypatch, "localhost")
    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.safe_client("http://127.0.0.1/x")


def test_an_unevaluable_policy_blocks_rather_than_allows(guarded, monkeypatch) -> None:
    """"We cannot tell" must not resolve to "let it out"."""
    monkeypatch.setattr(
        "maverick.enterprise.egress_permitted",
        lambda url: (_ for _ in ()).throw(RuntimeError("config on fire")))
    with pytest.raises(EgressBlocked):
        httpx.get("https://api.example.com/x", timeout=0.5)


def test_host_parser_failure_blocks_even_without_enterprise_mode(guarded, monkeypatch) -> None:
    """Tenant checks cannot be skipped when host extraction is unavailable."""
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)

    def fail_host_parser(url):
        raise RuntimeError("host parser unavailable")

    monkeypatch.setattr("maverick.enterprise._host_of", fail_host_parser)
    with pytest.raises(EgressBlocked, match="could not be evaluated"):
        httpx.get("https://api.example.com/x", timeout=0.5)


def test_a_block_is_audited(guarded, monkeypatch) -> None:
    """A blocked exfiltration attempt is exactly what an auditor needs to see."""
    seen = []
    monkeypatch.setattr("maverick.audit.record",
                        lambda kind, **kw: seen.append((kind, kw)) or True)
    with pytest.raises(EgressBlocked):
        httpx.get("https://api.example.com/x", timeout=0.5)
    assert seen, "a blocked egress attempt must be recorded"
    assert any("api.example.com" in str(kw) for _, kw in seen), seen


def _tenant_denies(monkeypatch, *hosts):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"egress": {"deny": list(hosts)}},
    )


def test_tenant_plane_blocks_even_with_enterprise_mode_off(
    unguarded_mode, monkeypatch,
) -> None:
    """The load-bearing case: with enterprise mode off (the default posture),
    a tenant-denied host must still be refused at this seam -- not just when
    the one tool (http_fetch) that already called tenant.egress is used."""
    _tenant_denies(monkeypatch, "denied.example.com")
    with pytest.raises(EgressBlocked, match="egress policy"):
        httpx.get("https://denied.example.com/x", timeout=0.5)


def test_tenant_plane_with_enterprise_off_permits_a_host_not_denied(
    unguarded_mode, monkeypatch,
) -> None:
    """Negative control: a configured tenant deny-list must not become deny-all."""
    _tenant_denies(monkeypatch, "denied.example.com")
    with pytest.raises(httpx.HTTPError):
        httpx.get(UNROUTABLE, timeout=0.5)


def test_tenant_denial_applies_even_when_the_enterprise_allowlist_permits(
    guarded, monkeypatch,
) -> None:
    """The two planes compose with AND: passing the enterprise allow-list is
    not enough to bypass a tenant deny."""
    _allowed(monkeypatch, "denied.example.com")
    _tenant_denies(monkeypatch, "denied.example.com")
    with pytest.raises(EgressBlocked, match="egress policy"):
        httpx.get("https://denied.example.com/x", timeout=0.5)


def test_tenant_plane_unconfigured_falls_through_to_the_enterprise_decision(
    guarded,
) -> None:
    """No [egress] / [tenancy.egress.<t>] configured -> the tenant plane is
    allow-all, so the enterprise allow-list alone still decides (no
    regression for a deployment that only uses enterprise mode)."""
    with pytest.raises(EgressBlocked, match="enterprise mode"):
        httpx.get("https://api.example.com/x", timeout=0.5)


def test_an_unevaluable_tenant_policy_blocks_rather_than_allows(
    guarded, monkeypatch,
) -> None:
    """"We cannot tell" must not resolve to "let it out", for the tenant plane
    exactly like it already doesn't for the enterprise one. Allow-list the
    host under enterprise first, so only the tenant-policy exception -- not
    enterprise's own independent default-deny -- can explain the block."""
    _allowed(monkeypatch, "api.example.com")
    monkeypatch.setattr(
        "maverick.tenant.egress.host_allowed",
        lambda host, **k: (_ for _ in ()).throw(RuntimeError("config on fire")))
    with pytest.raises(EgressBlocked):
        httpx.get("https://api.example.com/x", timeout=0.5)


def test_httpx2_exact_in_process_transports_are_exempt() -> None:
    """The new family keeps exact-type local transports off the egress path."""
    import sys

    class MockTransport:
        pass

    class ASGITransport:
        pass

    class WSGITransport:
        pass

    fake_httpx2 = type(
        "FakeHttpx2",
        (),
        {
            "MockTransport": MockTransport,
            "ASGITransport": ASGITransport,
            "WSGITransport": WSGITransport,
        },
    )
    missing = object()
    previous = sys.modules.get("httpx2", missing)
    sys.modules["httpx2"] = fake_httpx2
    try:
        assert egress_guard._is_network_transport(MockTransport()) is False
        assert egress_guard._is_network_transport(ASGITransport()) is False
        assert egress_guard._is_network_transport(WSGITransport()) is False

        class SocketCapableSubclass(MockTransport):
            pass

        assert (
            egress_guard._is_network_transport(SocketCapableSubclass()) is True
        )
    finally:
        if previous is missing:
            sys.modules.pop("httpx2", None)
        else:
            sys.modules["httpx2"] = previous
