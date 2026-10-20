"""
Property-based tests using Hypothesis.
Verifies that scanning rules never produce invalid severities or crash.
"""
import sys

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from analyzers.ec2_rules import analyze_security_group
from analyzers.s3_rules import analyze_s3_bucket
from models import (
    AclGrant,
    EncryptionConfig,
    InboundRule,
    PublicAccessBlockConfig,
    S3BucketConfig,
    SecurityGroupConfig,
    Severity,
)

VALID_SEVERITIES = {s.value for s in Severity}

# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

@st.composite
def s3_bucket_strategy(draw):
    """Generate arbitrary S3BucketConfig instances."""
    name = draw(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("Ll", "Nd"), whitelist_characters="-")))
    if not name:
        name = "test-bucket"

    block = PublicAccessBlockConfig(
        block_public_acls=draw(st.booleans()),
        ignore_public_acls=draw(st.booleans()),
        block_public_policy=draw(st.booleans()),
        restrict_public_buckets=draw(st.booleans()),
    )

    public_grantee_uris = [
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        "http://acs.amazonaws.com/groups/global/LogDelivery",
    ]
    permissions = ["READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"]

    acl_grants = draw(st.lists(
        st.builds(
            AclGrant,
            grantee_uri=st.sampled_from(public_grantee_uris),
            permission=st.sampled_from(permissions),
        ),
        min_size=0,
        max_size=3,
    ))

    encryption = draw(st.one_of(
        st.none(),
        st.builds(EncryptionConfig, sse_algorithm=st.sampled_from(["AES256", "aws:kms"])),
    ))

    versioning_enabled = draw(st.one_of(st.none(), st.booleans()))
    logging_enabled = draw(st.one_of(st.none(), st.booleans()))

    return S3BucketConfig(
        name=name or "fallback-bucket",
        public_access_block=block,
        acl_grants=acl_grants,
        is_public_policy=draw(st.booleans()),
        encryption=encryption,
        versioning_enabled=versioning_enabled,
        logging_enabled=logging_enabled,
    )


@st.composite
def inbound_rule_strategy(draw):
    """Generate arbitrary InboundRule instances."""
    protocol = draw(st.sampled_from(["tcp", "udp", "-1"]))
    cidrs = ["0.0.0.0/0", "::/0", "10.0.0.0/8", "192.168.1.0/24", None]

    if protocol == "-1":
        from_port = None
        to_port = None
    else:
        from_port = draw(st.one_of(st.none(), st.integers(min_value=0, max_value=65535)))
        to_port = from_port  # single port for simplicity

    return InboundRule(
        protocol=protocol,
        from_port=from_port,
        to_port=to_port,
        cidr_ipv4=draw(st.sampled_from([c for c in cidrs if c != "::/0"])),
        cidr_ipv6=draw(st.sampled_from([c for c in cidrs if c != "0.0.0.0/0"])),
    )


@st.composite
def security_group_strategy(draw):
    """Generate arbitrary SecurityGroupConfig instances."""
    return SecurityGroupConfig(
        group_id=f"sg-prop-{draw(st.integers(min_value=1, max_value=9999))}",
        group_name="prop-test-sg",
        description="Property test security group",
        inbound_rules=draw(st.lists(inbound_rule_strategy(), min_size=0, max_size=5)),
    )


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------

@given(s3_bucket_strategy())
@settings(max_examples=150)
def test_s3_severity_always_valid(bucket: S3BucketConfig):
    """For all valid S3 bucket inputs, analyzer never crashes and
    all returned findings have valid Severity values."""
    findings = analyze_s3_bucket(bucket)
    for finding in findings:
        assert finding.severity.value in VALID_SEVERITIES, (
            f"Invalid severity '{finding.severity}' for bucket '{bucket.name}'"
        )


@given(s3_bucket_strategy())
@settings(max_examples=150)
def test_s3_findings_always_have_required_fields(bucket: S3BucketConfig):
    """All S3 findings always have non-empty required fields."""
    findings = analyze_s3_bucket(bucket)
    for f in findings:
        assert f.resource_type == "S3Bucket"
        assert f.resource_name
        assert f.title
        assert f.risk_explanation
        assert f.remediation
        assert isinstance(f.evidence, dict)
        assert f.simulated is True


@given(security_group_strategy())
@settings(max_examples=150)
def test_ec2_severity_always_valid(sg: SecurityGroupConfig):
    """For all valid security group inputs, analyzer never crashes and
    all returned findings have valid Severity values."""
    findings = analyze_security_group(sg)
    for finding in findings:
        assert finding.severity.value in VALID_SEVERITIES, (
            f"Invalid severity '{finding.severity}' for sg '{sg.group_id}'"
        )


@given(security_group_strategy())
@settings(max_examples=150)
def test_ec2_findings_always_have_required_fields(sg: SecurityGroupConfig):
    """All EC2 findings always have non-empty required fields."""
    findings = analyze_security_group(sg)
    for f in findings:
        assert f.resource_type == "SecurityGroup"
        assert f.resource_name
        assert f.title
        assert f.risk_explanation
        assert f.remediation
        assert isinstance(f.evidence, dict)
        assert f.simulated is True


def test_simulated_provider_no_boto3():
    """SimulatedScannerProvider must not actually import boto3.

    The docstring of simulated.py says 'Does NOT import boto3' — so string
    search would falsely match. We use AST parsing to check for actual import
    statements only.
    """
    import ast
    import inspect
    import providers.simulated as sim_mod
    source = inspect.getsource(sim_mod)
    tree = ast.parse(source)
    boto3_imports = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        and any(
            (isinstance(node, ast.Import) and alias.name == "boto3")
            or (isinstance(node, ast.ImportFrom) and node.module == "boto3")
            for alias in node.names
        )
    ]
    assert boto3_imports == [], (
        "SimulatedScannerProvider must not import boto3. "
        "It must load data from JSON fixtures only, never call real AWS APIs."
    )
