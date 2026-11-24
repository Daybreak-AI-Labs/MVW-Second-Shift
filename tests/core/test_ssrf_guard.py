"""SSRF consolidation: skill install and catalog fetch now go through the
same ``guarded_urlopen`` host check the http_fetch tool already uses, so a
user/model-supplied URL can't be pointed at a private/loopback/metadata
address. Loopback literals resolve without DNS, so these stay hermetic.
"""
from __future__ import annotations

import httpx
import pytest


def test_request_host_matches_reconciles_idn_forms():
    from maverick.tools._ssrf import _request_host_matches
    req = httpx.Request("GET", "https://xn--e1afmkfd.xn--p1ai/x")  # punycode URL
    # httpx decodes url.host to Unicode; the validated host is the punycode form.
    assert _request_host_matches(req, "xn--e1afmkfd.xn--p1ai")
    assert not _request_host_matches(req, "evil.example.com")


def test_pinned_transport_refuses_mismatched_host():
    from maverick.tools._ssrf import BlockedHost, _PinnedTransport

    class _Inner:
        def handle_request(self, r):
            raise AssertionError("must not reach the inner transport on a mismatch")

    t = _PinnedTransport("good.example.com", "good.example.com", "1.2.3.4", _Inner())
    with pytest.raises(BlockedHost):
        t.handle_request(httpx.Request("GET", "https://evil.example.com/x"))
