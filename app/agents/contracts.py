from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AgentFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(min_length=1, max_length=64)
    finding_type: str = Field(min_length=1, max_length=80)
    severity: Literal["critical", "high", "medium", "low", "informational"]
    description: str = Field(min_length=1, max_length=3_000)
    evidence: str = Field(min_length=1, max_length=2_000)
    file: str | None = Field(default=None, max_length=120)
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    network: str | None = Field(default=None, max_length=80)
    reference: str | None = Field(default=None, max_length=500)
    source_agent: str = Field(min_length=1, max_length=80)
    verification_method: str = Field(min_length=1, max_length=120)
    validation_status: Literal["confirmed", "rejected", "pending", "inconclusive"]
    limitations: list[str] = Field(max_length=10)
    observed_at: datetime

    @model_validator(mode="after")
    def validate_lines(self) -> AgentFinding:
        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise ValueError("line_end must not precede line_start")
        return self
