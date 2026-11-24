"""Governed connectors -- act on external systems of record through typed,
audited Actions (NOT a data-integration platform).

Agents must read and write systems of record (CRM, ticketing, ERP) -- but every such operation should be a typed,
risk-classed, lineage-tracked :class:`~maverick.governed_actions.ActionSpec`,
never a raw call. A :class:`Connector` adapts one external system into governed
Actions named ``<connector>.read`` (low risk) and ``<connector>.write`` (high
risk, so it hits the approval floor): each previews its effect before commit and
records a lineage link after.

This ships the FRAMEWORK + a reference in-memory connector; a real connector
(Salesforce, ServiceNow, SAP, ...) implements the same tiny surface against a
live system. Opt-in/additive -- registering a connector is an explicit choice.
"""
from __future__ import annotations


class Connector:
    """Adapts an external system of record into governed read/write Actions.

    Subclasses set ``name`` + the typed param schemas and implement ``read`` /
    ``write`` / ``preview_write`` (the simulator -- it must have NO side
    effects)."""
    name: str = "connector"
    read_params: dict[str, type] = {"key": str}
    write_params: dict[str, type] = {"key": str, "value": str}

    def read(self, params: dict) -> str:  # pragma: no cover -- abstract
        raise NotImplementedError

    def preview_write(self, params: dict) -> str:  # pragma: no cover -- abstract
        raise NotImplementedError

    def write(self, params: dict) -> str:  # pragma: no cover -- abstract
        raise NotImplementedError


__all__ = [
    "Connector",
]
