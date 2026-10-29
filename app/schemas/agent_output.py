"""The AgentOutput schema: what the agent loop produces for one Finding."""

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.enums import (
    APPROVAL_REQUIRED_VERDICTS,
    Confidence,
    FieldSource,
    MisconfigVerdict,
    Severity,
)


class AgentOutput(BaseModel):
    """Validated result for one finding, ready for the approval gate."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1)
    misconfig_type: MisconfigVerdict
    severity: Optional[Severity] = None
    control_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    explanation: str
    remediation_steps: list[str] = Field(default_factory=list)
    fix_snippet: Optional[str] = None
    side_effects: Optional[str] = None
    confidence: Confidence
    requires_approval: bool
    field_sources: dict[str, FieldSource] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _enforce_approval_gate(self) -> "AgentOutput":
        """Hard rule 3: High/Critical and IAM-adjacent verdicts must require approval."""
        if self.misconfig_type in APPROVAL_REQUIRED_VERDICTS and not self.requires_approval:
            raise ValueError(
                f"{self.misconfig_type.value} must have requires_approval=True"
            )
        return self
