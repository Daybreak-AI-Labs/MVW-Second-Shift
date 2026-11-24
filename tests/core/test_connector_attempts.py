"""Physical connector retries, accounting, mutation uncertainty and admission."""
from __future__ import annotations
import pytest
from maverick import connector_attempts as attempts


@pytest.mark.parametrize("value", ["NaN", "inf", "bad\r\nheader", "x" * 129])
def test_untrusted_retry_after_is_not_retained(value):
    assert attempts.retry_after_seconds(value) is None
