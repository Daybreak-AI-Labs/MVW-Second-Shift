"""Pydantic request/response models for the dashboard REST API.

Extracted verbatim from api.py to keep that module focused on routing.
Importing here changes no behavior: these are pure data schemas.
"""
from __future__ import annotations
from pydantic import BaseModel, Field


class TrustRevokeIn(BaseModel):
    """Revoke (or restore) a managed external agent without deleting it."""
    revoked: bool = True


class ExternalAgentIn(BaseModel):
    """Enroll (or re-enroll) a bring-your-own agent: one call writes the trust
    entry (inbound, with ceilings + expiry), the fleet-memory roster, and the
    platform/ownership metadata the /external-agents console shows."""
    id: str = Field(..., min_length=1, max_length=64)
    platform: str = Field(..., min_length=1, max_length=32)
    description: str = Field(default="", max_length=500)
    owner: str = Field(default="", max_length=200)
    department: str = Field(default="", max_length=100)
    allow_tools: list[str] = Field(default_factory=list, max_length=128)
    deny_tools: list[str] = Field(default_factory=list, max_length=128)
    max_risk: str | None = Field(default=None, pattern="^(low|medium|high)$")
    max_dollars: float | None = Field(default=None, ge=0)
    max_wall_seconds: float | None = Field(default=None, ge=0)
    data_scopes: list[str] = Field(default_factory=list, max_length=64)
    expires_days: float | None = Field(default=None, gt=0, le=3650)
    # "monthly" resets the spend meter each calendar month (UTC); "total"
    # is a lifetime cap. allow_tools entries may carry the operator's risk
    # rating as "name:risk", which floors whatever the agent declares.
    # None keeps the agent's current period on re-enrollment ("monthly" for a new one).
    budget_period: str | None = Field(default=None, pattern="^(monthly|total)$")
    # The agent's record on its home platform, "<platform check>:<id>". None keeps
    # the stored link on re-enrollment and "" removes it.
    external_ref: str | None = Field(default=None, max_length=300)


class ExternalCredentialIn(BaseModel):
    """Mint (or rotate) one per-surface bearer for an enrolled external agent.
    The response carries the token exactly once; it is never readable again.
    ``approval_id`` replays a step-up mint approval when ``[external_agents]
    mint_approval`` gates the mint (one approval mints exactly one token)."""
    surface: str = Field(default="rest", pattern="^(rest|a2a|grpc|mcp)$")
    approval_id: int | None = None


class HaltIn(BaseModel):
    reason: str = Field("manual via dashboard", max_length=200)
