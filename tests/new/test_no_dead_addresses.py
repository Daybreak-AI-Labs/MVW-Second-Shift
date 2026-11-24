"""Every address a page links to or its scripts call is one the app serves.

Reads the page templates and the shipped scripts, collects each ``href`` and
form ``action`` that is a path on this site, each ``src`` under ``/static/``
and each literal path given to ``fetch(`` or ``mvFetchJSON(``, and checks it
against the routes the app registers (a path parameter matches one segment).
It also checks that nothing a browser can be served carries another product's
name. It does not follow addresses built entirely at run time.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from maverick_dashboard.app import app

PACKAGE = Path(__file__).resolve().parents[2] / "maverick_dashboard"
TEMPLATES = sorted((PACKAGE / "templates").glob("*.html"))
SCRIPTS = sorted((PACKAGE / "static").glob("*.js"))
STATIC = PACKAGE / "static"

_ATTRIBUTE = re.compile(r"""\b(?:href|action|src)\s*=\s*(["'])(.*?)\1""", re.S)
_ASSET = re.compile(r"""\b(?:asset|static_url)\(\s*(["'])(.*?)\1\s*\)""")
_CALL = re.compile(r"""\b(?:fetch|mvFetchJSON)\(\s*(["'])(/[^"']*)\1(\s*\+)?""")
_JS_HREF = re.compile(r"""\.(?:href|action)\s*=\s*(["'])(/[^"']*)\1(\s*\+)?""")
_SERVER_TAG = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.S)
_OTHER_NAMES = re.compile(r"lightwork|daybreak", re.I)


def _served_paths() -> list[str]:
    from maverick_dashboard.route_identity import _effective_routes

    return sorted({route.path for route in _effective_routes(app) if route.path})


def _route_patterns() -> list[re.Pattern[str]]:
    patterns = []
    for path in _served_paths():
        regex = re.sub(r"\{[^}/]+:path\}", ".+", re.escape(path).replace(r"\{", "{").replace(r"\}", "}"))
        regex = re.sub(r"\{[^}/]+\}", "[^/]+", regex)
        patterns.append(re.compile("^" + regex + "$"))
    return patterns


def _served(path: str, patterns: list[re.Pattern[str]], *, prefix: bool = False) -> bool:
    path = re.split(r"[?#]", path, maxsplit=1)[0] or "/"
    if prefix:  # the literal ends where a run-time value is appended
        path = path.rstrip("/")
        return any(p.match(path + "/x") or p.match(path + "x") or p.match(path) for p in patterns)
    return any(p.match(path) for p in patterns)


def _without_comments(text: str, path: Path) -> str:
    if path.suffix == ".html":
        return re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", re.sub(r"/\*.*?\*/", "", text, flags=re.S))


def _page_addresses(text: str) -> list[tuple[str, bool]]:
    found: list[tuple[str, bool]] = []
    for match in _ATTRIBUTE.finditer(text):
        value = match.group(2).strip()
        if not value.startswith("/") or value.startswith("//"):
            continue
        dynamic = bool(_SERVER_TAG.search(value))
        found.append((_SERVER_TAG.sub("x", value), dynamic and value.rstrip().endswith(("}}", "%}"))))
    for match in _ASSET.finditer(text):
        found.append(("/static/" + match.group(2), False))
    return found


def _script_addresses(text: str) -> list[tuple[str, bool]]:
    found = [(m.group(2), bool(m.group(3))) for m in _CALL.finditer(text)]
    found += [(m.group(2), bool(m.group(3))) for m in _JS_HREF.finditer(text)]
    for match in _ATTRIBUTE.finditer(text):  # markup written by a script
        value = match.group(2).strip()
        if value.startswith("/") and not value.startswith("//") and "'" not in value:
            found.append((value, False))
    return found


def test_the_checks_see_the_addresses_pages_use():
    assert sum(len(_page_addresses(_without_comments(p.read_text(encoding="utf-8"), p))) for p in TEMPLATES) > 30
    assert sum(len(_script_addresses(_without_comments(p.read_text(encoding="utf-8"), p))) for p in SCRIPTS) > 5


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_template_links_and_forms_reach_served_addresses(path):
    patterns = _route_patterns()
    missing = [address for address, prefix in _page_addresses(_without_comments(path.read_text(encoding="utf-8"), path))
               if not _served(address, patterns, prefix=prefix)]
    assert not missing, f"{path.name} points at addresses the app does not serve: {sorted(set(missing))}"


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_script_calls_reach_served_addresses(path):
    patterns = _route_patterns()
    missing = [address for address, prefix in _script_addresses(_without_comments(path.read_text(encoding="utf-8"), path))
               if not _served(address, patterns, prefix=prefix)]
    assert not missing, f"{path.name} calls addresses the app does not serve: {sorted(set(missing))}"


def test_every_static_file_is_served_and_every_served_file_exists():
    served = {path for path in _served_paths() if path.startswith("/static/")}
    on_disk = {"/static/" + p.relative_to(STATIC).as_posix() for p in STATIC.rglob("*") if p.is_file()}
    assert served == on_disk
    from maverick_dashboard.auth import PUBLIC_STATIC_PATHS

    assert PUBLIC_STATIC_PATHS <= on_disk


def test_nothing_a_browser_is_served_carries_another_products_name():
    offenders = []
    for path in [*TEMPLATES, *SCRIPTS, *STATIC.glob("*.css"), *STATIC.glob("*.svg")]:
        if _OTHER_NAMES.search(path.name) or _OTHER_NAMES.search(path.read_text(encoding="utf-8")):
            offenders.append(path.name)
    for path in STATIC.rglob("*"):
        if path.is_file() and _OTHER_NAMES.search(path.name):
            offenders.append(path.name)
    assert not offenders
