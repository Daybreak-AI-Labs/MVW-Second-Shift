"""Product-copy helpers for templates: ``ut`` (text), ``ui`` (an escaped region), ``ul`` (its language)."""
from __future__ import annotations

from markupsafe import Markup, escape


def text(source, lang="en", /, **values):
    return source.format_map(values) if values else source


def region(source, lang="en", /, **values):
    """A product-copy region, with caller-supplied content escaped and isolated."""
    safe = escape(source)
    if values:
        safe = safe.format_map({name: Markup('<bdi lang="und" dir="auto">{}</bdi>').format(escape(str(value)))
                                for name, value in values.items()})
    return Markup('<span lang="en" dir="ltr" data-product-copy>{}</span>').format(safe)


def context(request, lang):
    metadata = {"language": "en", "locale": "en", "review_status": "source"}
    return {"ui": lambda source, /, **values: region(source, lang, **values),
            "ut": lambda source, /, **values: text(source, lang, **values),
            "ul": lambda source: "en",
            "journey_i18n": metadata,
            "journey_i18n_bootstrap": metadata,
            "journey_i18n_asset": ""}
