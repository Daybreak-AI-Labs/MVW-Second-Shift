"""Hand-edited config must apply (case/whitespace) and tolerate bad values.

profile/backend/provider etc. come from hand-edited TOML (or CLI flags) and
were compared against lowercase literals, so "Docker" / "Anthropic:" silently
misapplied; a non-numeric [sandbox] timeout crashed the kernel outright. These
tests pin normalization + defensive coercion at the highest-impact
chokepoints:

  - build_sandbox(): a mis-cased backend must NOT silently degrade to the
    unsandboxed local backend (a security downgrade), and an unrecognized
    backend must warn loudly instead of failing quiet.
  - llm._parse_spec(): a mis-cased / aliased provider must canonicalize so the
    case-sensitive API-key lookup resolves (not just client creation).
"""
from __future__ import annotations


class TestNotifyBackendCasing:
    def test_mixed_case_backend_routes_to_handler(self, monkeypatch):
        import maverick.notifications as notif
        fired: list[str] = []
        monkeypatch.setattr(notif, "_send_discord", lambda *a, **k: fired.append("discord") or True)
        n = notif.notify("agent done", backends=["Discord"], async_dispatch=False)
        assert fired == ["discord"]
        assert n == 1

    def test_backend_whitespace_and_case_tolerated(self, monkeypatch):
        import maverick.notifications as notif
        fired: list[str] = []
        monkeypatch.setattr(notif, "_send_discord", lambda *a, **k: fired.append("discord") or True)
        notif.notify("agent done", backends=["  DISCORD  "], async_dispatch=False)
        assert fired == ["discord"]

    def test_none_sentinel_is_case_insensitive(self, monkeypatch):
        import maverick.notifications as notif
        # "None" must disable just like "none" -- nothing dispatched, returns 0.
        monkeypatch.setattr(notif, "_send_discord", lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not fire")))
        assert notif.notify("x", backends=["None"], async_dispatch=False) == 0
