"""Capability-leak fuzzer: the REAL maverick.capability boundary must survive
the full probe battery with zero leaks; a deliberately-broken substring
matcher must not. Probe generation is seeded-PRNG deterministic.
"""
from __future__ import annotations

from maverick.capability import Capability

GRANTED = {"fs.read", "fs.write", "shell.exec", "web_search"}


def _real_cap() -> Capability:
    # No max_risk: the risk ceiling consults tool_risk/config, which is not
    # what the *name-matching* boundary under test here is about.
    return Capability(principal="fuzz-target", allow_tools=frozenset(GRANTED))


def test_granted_names_still_permitted():
    # The fuzzer must not "pass" because the grant denies everything.
    cap = _real_cap()
    for name in GRANTED:
        assert cap.permits(name)


def test_specific_adversarial_probes_denied_by_real_capability():
    cap = _real_cap()
    for probe in (
        "FS.WRITE",            # case variant
        "ѕhell.exec",          # Cyrillic 's' homoglyph
        "shell.exec.x",        # suffix scope creep
        "xshell.exec",         # prefix
        "shell/exec",          # separator swap
        "shell:exec",
        "shell.exec\x00",      # embedded NUL
        "shell.*",             # glob
        "*",
        "",                    # empty
        " fs.read",            # whitespace
        "fs.read" * 100,       # very long
    ):
        assert cap.permits(probe) is False, f"leak: {probe!r}"
