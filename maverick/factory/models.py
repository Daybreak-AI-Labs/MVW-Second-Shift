"""The one place the factory makes a model client, so tests can replace it and nothing else calls a model.

The address and key are read from the environment variables the ``[factory]`` settings name, at the moment a client
is made. They are never stored, logged, shown or put in an error message here.
"""
from __future__ import annotations

import os
from typing import Any

from . import FactoryError
from . import definitions as defs
from .settings import FactorySettings, problems


def model_settings(settings: FactorySettings):
    """The runtime's ModelSettings for the configured model."""
    definition, _loop, _models, _skills = defs.runtime()
    return definition.ModelSettings(
        provider=settings.provider, endpoint_env=settings.endpoint_env, api_key_env=settings.api_key_env,
        deployment=settings.deployment, max_output_tokens=settings.max_output_tokens,
        input_price_per_million=settings.input_price_per_million,
        output_price_per_million=settings.output_price_per_million)


def build_client(model: Any):
    """A runtime model client for ``model`` (a runtime ModelSettings). Raises FactoryError, in plain words, when the
    model is not set up."""
    _definition, _loop, models, _skills = defs.runtime()
    try:
        return models.build_model(model, os.environ)
    except models.ModelError as exc:
        raise FactoryError(str(exc), 409) from exc


def require_ready(settings: FactorySettings) -> None:
    found = problems(settings)
    if found:
        raise FactoryError(" ".join(found), 409)
