"""Shared, presentation-independent contracts for configuration values.

The installer and dashboard must accept the same syntax for a setting.  Keep
these patterns in the kernel, which both packages already depend on; contextual
checks such as secret handling and provider-specific validation stay with the
caller that has that context.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class TextSettingContract:
    """Shared syntax and defaults for one text setting.

    The dashboard's display default can intentionally be empty when the
    reader supplies a runtime fallback. Installer and dashboard validation
    may add contextual checks (for example a provider-specific key format).
    """

    setting: str
    pattern: str
    default: str = ""
    runtime_default: str = ""
    dashboard_max_length: int = 200
    dashboard_env: tuple[str, ...] = ()

    def matches(self, value: str) -> bool:
        """Check syntax alone; the caller owns optional-value rules."""
        return re.fullmatch(self.pattern, value) is not None


HTTPS = r"https://[^\s\"'<>?#]{1,300}"
COLLECTOR_ADDRESS = (r"(" + HTTPS + r"|http://(localhost|127\.0\.0\.1|\[::1\])"
                     r"(:[0-9]{1,5})?(/[^\s\"'<>?#]{0,300})?)?")
KEY_ID = r"[A-Za-z0-9:/._-]{1,300}"
REGION = r"[a-z]{2}(-[a-z]+)+-[0-9]{1,2}"
VAULT_MOUNT = r"[A-Za-z0-9._-]{1,64}"
SIEM_ADDRESS = r"(https?|tcp|udp|datadog|sentinel)://[^\s\"'<>]{1,300}"

_CONTRACTS = (
    TextSettingContract("observability.otel_endpoint", COLLECTOR_ADDRESS,
                        runtime_default="http://localhost:4318/v1/traces",
                        dashboard_max_length=320, dashboard_env=("MAVERICK_OTEL_ENDPOINT",)),
    TextSettingContract("kms.key_id", KEY_ID, dashboard_max_length=300,
                        dashboard_env=("MAVERICK_KMS_KEY_ID",)),
    TextSettingContract("kms.region", REGION),
    TextSettingContract("kms.address", HTTPS, dashboard_max_length=300),
    TextSettingContract("kms.mount", VAULT_MOUNT, default="transit", runtime_default="transit"),
    TextSettingContract("audit.siem_dest", SIEM_ADDRESS, dashboard_max_length=300,
                        dashboard_env=("MAVERICK_SIEM_DEST",)),
)
TEXT_SETTINGS: Mapping[str, TextSettingContract] = MappingProxyType(
    {contract.setting: contract for contract in _CONTRACTS}
)
