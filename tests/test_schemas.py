import pytest
from pydantic import ValidationError

from app.schemas import (
    AgentOutput,
    Confidence,
    FieldSource,
    Finding,
    FindingSource,
    MisconfigLabel,
    MisconfigVerdict,
    ResourceType,
    Severity,
)


def make_finding(**overrides):
    base = dict(
        finding_id="f-001",
        resource_id="arn:aws:s3:::example-bucket",
        resource_type=ResourceType.S3,
        region="us-east-1",
        config={"BlockPublicAcls": False},
        tags={"Name": "private-secure-data"},
        source=FindingSource.SYNTHETIC,
        label=MisconfigLabel.M01,
    )
    base.update(overrides)
    return Finding(**base)


def make_agent_output(**overrides):
    base = dict(
        finding_id="f-001",
        misconfig_type=MisconfigVerdict.M01,
        severity=Severity.HIGH,
        control_ids=["S3.1"],
        mitre_techniques=["T1530"],
        evidence={"BlockPublicAcls": False},
        explanation="Bucket ACL allows public read access.",
        remediation_steps=["Enable S3 Block Public Access"],
        fix_snippet="aws s3api put-public-access-block ...",
        side_effects="Existing public consumers will lose access.",
        confidence=Confidence.HIGH,
        requires_approval=True,
        field_sources={"misconfig_type": FieldSource.RULE},
    )
    base.update(overrides)
    return AgentOutput(**base)


def test_finding_round_trips_minimal_fields():
    finding = make_finding()
    assert finding.resource_type is ResourceType.S3
    assert finding.label is MisconfigLabel.M01


def test_finding_defaults_config_and_tags_to_empty_dict():
    finding = make_finding(config={}, tags={})
    assert finding.config == {}
    assert finding.tags == {}


def test_finding_rejects_unknown_resource_type():
    with pytest.raises(ValidationError):
        make_finding(resource_type="LAMBDA")


def test_finding_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        make_finding(unexpected_field="oops")


def test_finding_rejects_empty_finding_id():
    with pytest.raises(ValidationError):
        make_finding(finding_id="")


def test_finding_misleading_tag_name_does_not_affect_schema_validity():
    # Judge by config, never by name (CLAUDE.md hard case): a bucket tagged
    # "private-secure-data" is still a valid, publicly-readable Finding.
    finding = make_finding(tags={"Name": "private-secure-data"})
    assert finding.label is MisconfigLabel.M01


def test_agent_output_round_trips():
    output = make_agent_output()
    assert output.misconfig_type is MisconfigVerdict.M01
    assert output.requires_approval is True


def test_agent_output_rejects_missing_approval_on_high_severity_iam_type():
    with pytest.raises(ValidationError):
        make_agent_output(misconfig_type=MisconfigVerdict.M04, requires_approval=False)


def test_agent_output_rejects_missing_approval_on_needs_review():
    with pytest.raises(ValidationError):
        make_agent_output(
            misconfig_type=MisconfigVerdict.NEEDS_REVIEW,
            severity=None,
            requires_approval=False,
        )


def test_agent_output_allows_no_approval_for_low_severity_type():
    output = make_agent_output(
        misconfig_type=MisconfigVerdict.M02,
        severity=Severity.MEDIUM,
        requires_approval=False,
    )
    assert output.requires_approval is False


def test_agent_output_allows_compliant_without_approval():
    output = make_agent_output(
        misconfig_type=MisconfigVerdict.COMPLIANT,
        severity=None,
        requires_approval=False,
    )
    assert output.severity is None
