"""Budget tracking. Long-horizon agents need hard caps.

Cost correctness:
  - record_tokens() takes the actual model id (default falls back to
    Sonnet rate for back-compat), so an Opus orchestrator call is billed
    at the Opus rate and max_dollars caps real spend.
  - Cache tokens are priced separately. Anthropic charges 0.1x for
    cache reads and 1.25x for cache writes, so they are not folded into
    ``input_tokens`` at full price.
"""
from __future__ import annotations


class BudgetExceeded(Exception):
    pass


class UsageAccountingError(RuntimeError):
    """A provider reported malformed usage accounting -- a missing, non-finite
    or negative token count -- for a call that was already paid for.

    Fail closed: the spend cannot be billed against the cap, so the run stops.
    Deliberately NOT a :class:`BudgetExceeded` subclass:
    reporting a broken gateway as "budget exceeded" sent operators to raise
    ``max_dollars`` instead of fixing the gateway, hid the real cause from the
    dashboard and CLI, and made provider failover treat it as a budget control
    signal. It is still non-retryable (another model cannot repair a gateway's
    accounting), and it counts as a provider failure for the circuit breaker.
    """
