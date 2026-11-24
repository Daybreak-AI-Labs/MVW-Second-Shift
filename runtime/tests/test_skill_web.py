import httpx
import pytest

from second_shift_runtime.skills import SkillContext, SkillError
from second_shift_runtime.skills.web import FetchWebPage, html_to_text, refused_reason, system_resolver

PUBLIC = "93.184.216.34"


@pytest.mark.parametrize("address", [
    "127.0.0.1", "127.255.255.254", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1",
    "0.0.0.0", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", "192.0.2.1", "198.18.0.1", "198.51.100.7", "203.0.113.9",
    "192.0.0.1", "::1", "::", "fe80::1", "fe80::1%eth0", "fc00::1", "fd12:3456::1", "ff02::1", "ff0e::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
    "::ffff:7f00:1", "::ffff:169.254.169.254", "64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b:1::1", "2002:7f00:1::", "2002:c0a8:101::",
    "2001:db8::1", "::127.0.0.1", "::a00:1", "100::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "fec0::1", "not an address",
])
def test_every_private_loopback_link_local_multicast_and_reserved_form_is_refused(address):
    assert refused_reason(address) is not None


@pytest.mark.parametrize("address", [PUBLIC, "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946", "::ffff:8.8.8.8", "64:ff9b::808:808"])
def test_public_addresses_are_allowed(address):
    assert refused_reason(address) is None


def context(handler, resolver=lambda host: [PUBLIC], tmp_path=None):
    return SkillContext(output_dir=tmp_path or None, transport=httpx.MockTransport(handler), resolver=resolver)


def page(handler_body=b"<html><title>T</title><body><p>Hi there</p></body></html>", ctype="text/html"):
    return lambda request: httpx.Response(200, headers={"content-type": ctype}, content=handler_body)


def fetch(url, ctx, **settings):
    return FetchWebPage(settings).run({"url": url}, ctx)


@pytest.mark.parametrize("host", ["2130706433", "0x7f000001", "127.1", "0177.0.0.1", "localhost"])
def test_odd_ways_of_writing_loopback_are_refused_through_the_real_resolver(host):
    ctx = SkillContext(output_dir=None, transport=httpx.MockTransport(lambda r: pytest.fail("must not connect")))
    with pytest.raises(SkillError, match="not a public address|could not be found"):
        fetch(f"http://{host}/", ctx)


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://10.1.2.3/x", "http://169.254.169.254/latest/meta-data/",
                                 "http://[fe80::1]/", "http://[fd00::1]/", "http://[64:ff9b::a00:1]/"])
def test_literal_private_addresses_are_refused_without_a_request(url):
    ctx = context(lambda r: pytest.fail("must not connect"))
    with pytest.raises(SkillError, match="not a public address"):
        fetch(url, ctx)


def test_a_name_that_resolves_to_a_private_address_or_a_mix_is_refused():
    for answer in (["10.0.0.5"], [PUBLIC, "127.0.0.1"], ["::1"]):
        ctx = context(lambda r: pytest.fail("must not connect"), resolver=lambda host, a=answer: a)
        with pytest.raises(SkillError, match="not a public address"):
            fetch("http://internal.example/", ctx)
    with pytest.raises(SkillError, match="could not be found"):
        fetch("http://nowhere.example/", context(lambda r: pytest.fail("no"), resolver=lambda host: []))


@pytest.mark.parametrize("url,fragment", [
    ("ftp://example.com/", "Only http and https"), ("file:///etc/passwd", "Only http and https"), ("javascript:alert(1)", "Only http and https"),
    ("http:///nohost", "no host"), ("http://user:pw@example.com/", "user name or password"), ("http://example.com:8080/", "standard port"),
    ("https://example.com:80/", "standard port"), ("http://example.com:abc/", "not a valid web address"), ("", "must be text"),
])
def test_only_plain_public_http_addresses_are_accepted(url, fragment):
    with pytest.raises(SkillError, match=fragment):
        fetch(url, context(lambda r: pytest.fail("must not connect")))


def test_the_connection_goes_to_the_checked_address_with_the_original_host_for_tls():
    seen = []

    def handler(request):
        seen.append(request)
        return page()(request)

    fetch("https://example.com/a/b?x=1", context(handler))
    req = seen[0]
    assert req.url.host == PUBLIC and req.headers["host"] == "example.com" and req.extensions["sni_hostname"] == "example.com"
    assert req.url.path == "/a/b" and req.url.query == b"x=1" and req.url.scheme == "https"
    fetch("http://example.com/", context(handler, resolver=lambda h: ["2606:2800:220:1:248:1893:25c8:1946"]))
    assert seen[1].url.host == "2606:2800:220:1:248:1893:25c8:1946" and seen[1].headers["host"] == "example.com"


def test_html_becomes_readable_text():
    result = fetch("https://example.com/", context(page(
        b"<html><head><title>My &amp; page</title><style>p{}</style></head><body><script>evil()</script>"
        b"<h1>Head</h1><p>One   two</p><ul><li>a</li><li>b</li></ul><noscript>no</noscript></body></html>")))
    assert result.text.startswith("Page: https://example.com/\nTitle: My & page")
    assert "Head\nOne two\na\nb" in result.text and "evil" not in result.text and "p{}" not in result.text and "no\n" not in result.text


def test_plain_text_is_returned_as_is_and_long_text_is_shortened():
    result = fetch("https://example.com/", context(page(b"x" * 5000, "text/plain")), max_text_chars=1000)
    assert result.text.endswith("[shortened]") and "x" * 1000 in result.text and "x" * 1001 not in result.text


@pytest.mark.parametrize("ctype", ["application/pdf", "image/png", "application/json", "application/octet-stream", ""])
def test_other_content_types_are_not_read(ctype):
    with pytest.raises(SkillError, match="not text/html or text/plain"):
        fetch("https://example.com/", context(page(b"data", ctype)))


def test_status_size_and_time_limits():
    with pytest.raises(SkillError, match="status 404"):
        fetch("https://example.com/", context(lambda r: httpx.Response(404, text="no")))
    with pytest.raises(SkillError, match="larger than the 10000 byte limit"):
        fetch("https://example.com/", context(page(b"y" * 30_000, "text/plain")), max_bytes=10_000)

    def slow(request):
        raise httpx.ReadTimeout("slow")

    with pytest.raises(SkillError, match="too long"):
        fetch("https://example.com/", context(slow))
    with pytest.raises(SkillError, match="could not be reached"):
        fetch("https://example.com/", context(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x"))))


def test_a_redirect_to_a_private_address_is_refused_and_never_followed():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})

    with pytest.raises(SkillError, match="not a public address"):
        fetch("http://example.com/", context(handler))
    assert seen == [f"http://{PUBLIC}/"]


def test_a_redirect_to_a_name_that_resolves_privately_is_refused():
    def resolver(host):
        return ["10.0.0.9"] if host == "internal.example" else [PUBLIC]

    def handler(request):
        return httpx.Response(301, headers={"location": "https://internal.example/secret"})

    with pytest.raises(SkillError, match="not a public address"):
        fetch("https://example.com/", context(handler, resolver=resolver))


def test_redirects_to_public_pages_are_followed_up_to_three_hops():
    def chain(n):
        def handler(request):
            if request.url.path == "/start":
                return httpx.Response(302, headers={"location": "/1"})
            i = int(request.url.path[1:])
            if i < n:
                return httpx.Response(307, headers={"location": f"/{i + 1}"})
            return page(b"<p>arrived</p>")(request)
        return handler

    assert "arrived" in fetch("http://example.com/start", context(chain(2))).text  # start->1->2->3: three redirects
    with pytest.raises(SkillError, match="more than 3 times"):
        fetch("http://example.com/start", context(chain(10)))
    with pytest.raises(SkillError, match="without saying where"):
        fetch("http://example.com/", context(lambda r: httpx.Response(302)))
    with pytest.raises(SkillError, match="Only http and https"):
        fetch("http://example.com/", context(lambda r: httpx.Response(302, headers={"location": "ftp://example.com/x"})))


def test_describe_leaves_out_the_query_string_and_settings_are_checked():
    skill = FetchWebPage({})
    assert skill.describe({"url": "https://example.com/p?token=SECRET"}) == "Fetch the web page https://example.com/p (query string not shown)."
    assert "SECRET" not in skill.describe({"url": "https://example.com/p?token=SECRET"})
    from second_shift_runtime.definition import DefinitionError

    with pytest.raises(DefinitionError, match="between"):
        FetchWebPage({"max_bytes": 1})
    with pytest.raises(DefinitionError, match="unknown setting"):
        FetchWebPage({"follow": True})


def test_html_to_text_handles_broken_markup():
    title, text = html_to_text("<p>unclosed <b>bold<p>next &lt;tag&gt;")
    assert title == "" and "next <tag>" in text


def test_system_resolver_reports_unknown_names(monkeypatch):
    import socket

    def nothing(*a, **k):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", nothing)
    with pytest.raises(SkillError, match="could not be found"):
        system_resolver("no-such-host.invalid")
