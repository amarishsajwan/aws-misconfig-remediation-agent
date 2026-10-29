"""Shared enums for the Finding and AgentOutput schemas."""

from enum import Enum


class ResourceType(str, Enum):
    S3 = "S3"
    EC2 = "EC2"
    IAM = "IAM"
    RDS = "RDS"
    CLOUDTRAIL = "CloudTrail"
    EBS = "EBS"


class FindingSource(str, Enum):
    SYNTHETIC = "synthetic"
    TRIVY = "trivy"


class MisconfigLabel(str, Enum):
    """Ground-truth label on a Finding. Never shown to the agent."""

    M01 = "M01"
    M02 = "M02"
    M03 = "M03"
    M04 = "M04"
    M05 = "M05"
    M06 = "M06"
    M07 = "M07"
    M08 = "M08"
    M09 = "M09"
    M10 = "M10"
    COMPLIANT = "COMPLIANT"


class MisconfigVerdict(str, Enum):
    """Verdict set by check_misconfig and surfaced in AgentOutput."""

    M01 = "M01"
    M02 = "M02"
    M03 = "M03"
    M04 = "M04"
    M05 = "M05"
    M06 = "M06"
    M07 = "M07"
    M08 = "M08"
    M09 = "M09"
    M10 = "M10"
    COMPLIANT = "COMPLIANT"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FieldSource(str, Enum):
    """Tags each AgentOutput field with where its value came from."""

    RULE = "Rule"
    RETRIEVED = "Retrieved"
    LLM = "LLM"


# Misconfig types that CLAUDE.md's hard rule 3 requires a human to approve
# (every High/Critical finding, plus the IAM-adjacent M06), and NEEDS_REVIEW
# since it means check_misconfig could not reach a verdict on its own.
APPROVAL_REQUIRED_VERDICTS = frozenset(
    {
        MisconfigVerdict.M01,
        MisconfigVerdict.M03,
        MisconfigVerdict.M04,
        MisconfigVerdict.M05,
        MisconfigVerdict.M06,
        MisconfigVerdict.M07,
        MisconfigVerdict.M08,
        MisconfigVerdict.NEEDS_REVIEW,
    }
)
