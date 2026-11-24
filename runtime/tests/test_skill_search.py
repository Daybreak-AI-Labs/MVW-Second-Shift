import httpx
import pytest

from second_shift_runtime.definition import DefinitionError
from second_shift_runtime.skills import SkillContext, SkillError
from second_shift_runtime.skills.search import PROVIDERS, WebSearch, parse_brave

BRAVE = {"query": {"original": "x"}, "web": {"type": "search", "results": [
    {"title": "First <strong>hit</strong>", "url": "https://one.example/a", "description": "About <strong>the</strong> thing &amp; more",
     "extra_snippets": ["ignored"], "profile": {"name": "ignored"}},
    {"title": "Second", "url": "https://two.example/", "description": ""},
    {"title": "Bad scheme", "url": "javascript:alert(1)", "description": "x"},
    "garbage",
]}}


def ctx(handler, env=None):
    return SkillContext(output_dir=None, env=env if env is not None else {"BRAVE_SEARCH_API_KEY": "brave-secret"},
                        transport=httpx.MockTransport(handler))


def test_brave_request_and_parsing():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=BRAVE)

    result = WebSearch({"max_results": 3}).run({"query": "  cats   and dogs "}, ctx(handler))
    req = seen[0]
    assert req.url.scheme == "https" and req.url.host == "api.search.brave.com" and req.url.path == "/res/v1/web/search"
    assert req.url.params["q"] == "cats and dogs" and req.url.params["count"] == "3"
    assert req.headers["x-subscription-token"] == "brave-secret" and req.headers["accept"] == "application/json"
    assert result.text.splitlines() == ["1. First hit", "   https://one.example/a", "   About the thing & more",
                                        "2. Second", "   https://two.example/", "   "]
    assert result.files == []


def test_parse_brave_keeps_titles_addresses_and_snippets_only():
    hits = parse_brave(__import__("json").dumps(BRAVE).encode())
    assert [(h.title, h.url) for h in hits] == [("First hit", "https://one.example/a"), ("Second", "https://two.example/")]
    assert parse_brave(b'{"web": {}}') == [] and parse_brave(b'{}') == []
    for bad in (b"nope", b'{"web": {"results": 5}}', b"[]"):
        with pytest.raises(SkillError, match="could not be read"):
            parse_brave(bad)


def test_no_results_and_failures_are_plain():
    assert WebSearch({}).run({"query": "x"}, ctx(lambda r: httpx.Response(200, json={"web": {"results": []}}))).text == "No results."
    for status, fragment in [(401, "refused the key"), (403, "refused the key"), (429, "too many searches"), (500, "status 500")]:
        with pytest.raises(SkillError, match=fragment):
            WebSearch({}).run({"query": "x"}, ctx(lambda r, s=status: httpx.Response(s, json={})))

    def slow(request):
        raise httpx.ReadTimeout("slow")

    with pytest.raises(SkillError, match="too long"):
        WebSearch({}).run({"query": "x"}, ctx(slow))
    with pytest.raises(SkillError, match="could not be reached"):
        WebSearch({}).run({"query": "x"}, ctx(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x"))))


def test_a_missing_key_or_bad_query_is_explained_and_the_key_is_never_in_an_error():
    with pytest.raises(SkillError, match="BRAVE_SEARCH_API_KEY is empty"):
        WebSearch({}).run({"query": "x"}, ctx(lambda r: pytest.fail("no"), env={"OTHER": "1"}))
    with pytest.raises(SkillError, match="non-empty text"):
        WebSearch({}).run({"query": " "}, ctx(lambda r: pytest.fail("no")))
    with pytest.raises(SkillError) as err:
        WebSearch({}).run({"query": "x"}, ctx(lambda r: httpx.Response(401, json={})))
    assert "brave-secret" not in str(err.value)


def test_the_key_variable_name_is_configurable_and_providers_are_pluggable():
    result = WebSearch({"api_key_env": "MY_KEY"}).run({"query": "q"}, ctx(lambda r: httpx.Response(200, json=BRAVE), env={"MY_KEY": "k"}))
    assert "First hit" in result.text
    assert set(PROVIDERS) == {"brave"}
    with pytest.raises(DefinitionError, match="NAME of an environment variable"):
        WebSearch({"api_key_env": "sk-123 456"})


def test_a_new_provider_needs_only_a_search_method(monkeypatch):
    from second_shift_runtime.skills.search import SearchHit

    class Fake:
        name = "fake"

        def __init__(self, key):
            self.key = key

        def search(self, query, count, client):
            return [SearchHit("T", "https://t.example/", f"{query}:{count}:{self.key}")]

    monkeypatch.setitem(PROVIDERS, "fake", Fake)
    out = WebSearch({"provider": "fake", "max_results": 2}).run({"query": "q"}, ctx(lambda r: pytest.fail("no")))
    assert out.text.endswith("q:2:brave-secret")


def test_the_summary_for_second_shift_is_short_and_plain():
    assert WebSearch({}).describe({"query": "<b>weather</b>  today"}) == "Search the web for: weather today"
