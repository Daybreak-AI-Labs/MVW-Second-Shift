"""The ``[factory]`` settings: which model drafts and tests agents, and the bounds on a test run.

A key or an address is never stored here; ``endpoint_env`` and ``api_key_env`` are the NAMES of environment
variables. Prices are the customer's own figures: without them no cost can be estimated, and a test run that
has a cost bound is refused rather than run unbounded.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

PROVIDERS = ("foundry_openai", "foundry_anthropic")
DEFAULT_ENDPOINT_ENV = "SECOND_SHIFT_FACTORY_MODEL_ENDPOINT"
DEFAULT_KEY_ENV = "SECOND_SHIFT_FACTORY_MODEL_KEY"
#: The names the agent's definition gives for Second Shift's address and the agent's key. They are names, not values.
GOVERNANCE_ADDRESS_ENV = "SECOND_SHIFT_URL"
GOVERNANCE_KEY_ENV = "SECOND_SHIFT_AGENT_KEY"


@dataclass(frozen=True)
class FactorySettings:
    provider: str
    endpoint_env: str
    api_key_env: str
    deployment: str
    max_output_tokens: int
    input_price_per_million: float | None
    output_price_per_million: float | None
    max_test_cases: int
    max_case_seconds: float
    max_test_run_seconds: float
    max_test_run_cost_dollars: float

    def model_block(self) -> dict[str, Any]:
        block: dict[str, Any] = {
            "provider": self.provider, "endpoint_env": self.endpoint_env, "api_key_env": self.api_key_env,
            "deployment": self.deployment, "max_output_tokens": self.max_output_tokens,
        }
        if self.input_price_per_million is not None and self.output_price_per_million is not None:
            block["input_price_per_million"] = self.input_price_per_million
            block["output_price_per_million"] = self.output_price_per_million
        return block

    @property
    def has_prices(self) -> bool:
        return self.input_price_per_million is not None and self.output_price_per_million is not None


def _section() -> dict:
    try:
        from ..config import load_config

        table = (load_config() or {}).get("factory")
    except Exception:
        return {}
    return table if isinstance(table, dict) else {}


def _number(raw: Any, default: float, low: float, high: float) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw != raw or not (low <= raw <= high):
        return default
    return float(raw)


def _price(raw: Any) -> float | None:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw != raw or not (0 <= raw <= 1_000_000):
        return None
    return float(raw)


def _name(raw: Any, default: str) -> str:
    return raw.strip() if isinstance(raw, str) and raw.strip() else default


def load() -> FactorySettings:
    cfg = _section()
    provider = cfg.get("provider")
    in_price, out_price = _price(cfg.get("input_price_per_million")), _price(cfg.get("output_price_per_million"))
    if in_price is None or out_price is None:  # both or neither, as the runtime requires
        in_price = out_price = None
    deployment = cfg.get("deployment")
    return FactorySettings(
        provider=provider.strip() if isinstance(provider, str) else "",
        endpoint_env=_name(cfg.get("endpoint_env"), DEFAULT_ENDPOINT_ENV),
        api_key_env=_name(cfg.get("api_key_env"), DEFAULT_KEY_ENV),
        deployment=deployment.strip() if isinstance(deployment, str) else "",
        max_output_tokens=int(_number(cfg.get("max_output_tokens"), 2000, 16, 200_000)),
        input_price_per_million=in_price,
        output_price_per_million=out_price,
        max_test_cases=int(_number(cfg.get("max_test_cases"), 20, 1, 200)),
        max_case_seconds=_number(cfg.get("max_case_seconds"), 120.0, 1, 3600),
        max_test_run_seconds=_number(cfg.get("max_test_run_seconds"), 900.0, 1, 86_400),
        max_test_run_cost_dollars=_number(cfg.get("max_test_run_cost_dollars"), 2.0, 0.0, 100_000),
    )


def problems(settings: FactorySettings | None = None, env: dict[str, str] | None = None) -> list[str]:
    """What stops the model being used, in plain words. Empty when it can be."""
    s = settings or load()
    env = os.environ if env is None else env
    found: list[str] = []
    if s.provider not in PROVIDERS:
        found.append("Choose the model service in the [factory] settings: provider must be foundry_openai or foundry_anthropic.")
    if not s.deployment:
        found.append("Name the model deployment in the [factory] settings (deployment).")
    if not env.get(s.endpoint_env, "").strip():
        found.append(f"The model address is not set: the environment variable {s.endpoint_env} is empty.")
    if not env.get(s.api_key_env, "").strip():
        found.append(f"The model key is not set: the environment variable {s.api_key_env} is empty.")
    return found
