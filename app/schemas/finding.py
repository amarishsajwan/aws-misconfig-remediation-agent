"""The Finding schema: a normalised scanner finding, before the agent sees it."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import FindingSource, MisconfigLabel, ResourceType


class Finding(BaseModel):
    """One normalised finding produced by app/parser/ from raw scanner input."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    resource_type: ResourceType
    region: str = Field(min_length=1)
    config: dict[str, Any] = Field(default_factory=dict)
    tags: dict[str, Any] = Field(default_factory=dict)
    source: FindingSource
    label: MisconfigLabel
