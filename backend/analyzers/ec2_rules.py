"""
EC2 security group inbound rule misconfiguration detection rules.

Rules apply deterministic severity classification per the ordered lookup
table in Requirement 4, criterion 2. Findings are consolidated to avoid
duplicate findings for the same port-severity combination per group.

All findings include simulated=True and explicitly state this finding
is based on simulated configuration data.
"""
from __future__ import annotations

from collections import defaultdict

from models import Finding, InboundRule, SecurityGroupConfig, Severity

# Ports that are Critical when open to the world
CRITICAL_PORTS: frozenset[int] = frozenset({
    22,     # SSH
    3389,   # RDP
    3306,   # MySQL
    5432,   # PostgreSQL
    1433,   # MSSQL
    27017,  # MongoDB
})

# Ports that are Informational (expected public web traffic)
INFORMATIONAL_PORTS: frozenset[int] = frozenset({80, 443})

# Descriptions for well-known ports
_PORT_NAMES: dict[int, str] = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    80: "HTTP",
    443: "HTTPS",
    6379: "Redis",
    11211: "Memcached",
    9200: "Elasticsearch",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}


def _port_label(port: int) -> str:
    name = _PORT_NAMES.get(port)
    return f"{port} ({name})" if name else str(port)


def is_world_open(rule: InboundRule) -> bool:
    """Return True if the rule source is 0.0.0.0/0 (IPv4) or ::/0 (IPv6)."""
    return rule.cidr_ipv4 == "0.0.0.0/0" or rule.cidr_ipv6 == "::/0"


def is_all_ports(rule: InboundRule) -> bool:
    """Return True if the rule covers all ports (protocol -1 or 0-65535)."""
    if rule.protocol == "-1":
        return True
    if rule.from_port == 0 and rule.to_port == 65535:
        return True
    return False


def classify_rule(rule: InboundRule) -> Severity | None:
    """Classify a single inbound rule's severity.

    Returns None if the rule is not world-open (i.e., not a finding).
    Priority order matches Requirement 4, criterion 2.
    """
    if not is_world_open(rule):
        return None

    # All-ports rules are Critical regardless of other conditions
    if is_all_ports(rule):
        return Severity.Critical

    # Determine the effective port for classification
    port = rule.from_port

    # Single-port rules: use from_port
    if port is None:
        return Severity.High  # Can't determine port — flag as High

    if port in CRITICAL_PORTS:
        return Severity.Critical

    if port in INFORMATIONAL_PORTS:
        return Severity.Informational

    return Severity.High


def _rule_to_evidence_dict(rule: InboundRule) -> dict:
    """Convert a rule to a concise evidence dict."""
    return {
        "protocol": rule.protocol,
        "from_port": rule.from_port,
        "to_port": rule.to_port,
        "cidr_ipv4": rule.cidr_ipv4,
        "cidr_ipv6": rule.cidr_ipv6,
        "description": rule.description,
    }


def analyze_security_group(sg: SecurityGroupConfig) -> list[Finding]:
    """Run security rules against a single security group configuration.

    Consolidation logic:
    1. If any all-ports Critical rule exists, emit only one all-ports Finding
       for the group — suppress all individual-port findings.
    2. Otherwise, group world-open rules by (severity, port).
       Emit one consolidated Finding per unique (severity, port) group.
    """
    # Step 1: check for all-ports rules
    all_ports_rules = [
        r for r in sg.inbound_rules
        if is_world_open(r) and is_all_ports(r)
    ]

    if all_ports_rules:
        # Emit a single all-ports Critical finding; suppress individual findings
        return [_make_all_ports_finding(sg, all_ports_rules)]

    # Step 2: classify each world-open rule
    # Group by (severity, port) for consolidation
    groups: dict[tuple[Severity, int | None], list[InboundRule]] = defaultdict(list)

    for rule in sg.inbound_rules:
        severity = classify_rule(rule)
        if severity is None:
            continue  # Not world-open — not a finding
        port = rule.from_port
        groups[(severity, port)].append(rule)

    # Step 3: emit one Finding per group
    findings = []
    for (severity, port), rules in groups.items():
        findings.append(_make_port_finding(sg, severity, port, rules))

    # Sort findings by severity order for consistent output
    severity_order = {
        Severity.Critical: 0,
        Severity.High: 1,
        Severity.Medium: 2,
        Severity.Low: 3,
        Severity.Informational: 4,
    }
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))
    return findings


def _make_all_ports_finding(sg: SecurityGroupConfig, rules: list[InboundRule]) -> Finding:
    """Create the single consolidated all-ports Critical finding."""
    sources = list({r.cidr_ipv4 or r.cidr_ipv6 for r in rules if r.cidr_ipv4 or r.cidr_ipv6})
    return Finding(
        resource_type="SecurityGroup",
        resource_name=sg.group_name,
        severity=Severity.Critical,
        title=f"Security Group '{sg.group_name}' allows all inbound traffic from the internet",
        evidence={
            "group_id": sg.group_id,
            "group_name": sg.group_name,
            "vpc_id": sg.vpc_id,
            "matching_rules": [_rule_to_evidence_dict(r) for r in rules],
            "source_cidrs": sources,
        },
        risk_explanation=(
            f"This finding is based on simulated configuration data. "
            f"Security group '{sg.group_name}' ({sg.group_id}) has an inbound rule that "
            "allows ALL traffic (protocol -1 or port range 0-65535) from the public internet "
            f"({', '.join(sources)}). This exposes every port on associated instances to "
            "internet-accessible attackers. Configuration risk — not confirmed exploitation."
        ),
        remediation=(
            f"Remove the allow-all inbound rule from security group '{sg.group_name}'. "
            "Replace with specific rules that allow only required ports from trusted sources: "
            "1. Delete the 0.0.0.0/0 all-traffic rule. "
            "2. Add rules for each required port (e.g., 443 for HTTPS). "
            "3. Restrict source CIDRs to known IP ranges or VPC CIDR blocks. "
            "4. Use security group references for inter-service communication."
        ),
    )


def _make_port_finding(
    sg: SecurityGroupConfig,
    severity: Severity,
    port: int | None,
    rules: list[InboundRule],
) -> Finding:
    """Create a consolidated Finding for a specific port-severity combination."""
    sources = list({r.cidr_ipv4 or r.cidr_ipv6 for r in rules if r.cidr_ipv4 or r.cidr_ipv6})
    port_label = _port_label(port) if port is not None else "unknown"

    if severity == Severity.Critical:
        title = (
            f"Security Group '{sg.group_name}' allows world-open inbound access "
            f"on port {port_label}"
        )
        risk = (
            f"This finding is based on simulated configuration data. "
            f"Security group '{sg.group_name}' ({sg.group_id}) has an inbound rule "
            f"permitting traffic on port {port_label} from the public internet "
            f"({', '.join(sources)}). "
            f"Port {port_label} is a high-value attack target commonly exploited for "
            "unauthorized access. Configuration risk — not confirmed exploitation."
        )
        remediation = (
            f"Restrict inbound access on port {port_label} in security group "
            f"'{sg.group_name}': "
            f"1. Remove or edit the rule permitting 0.0.0.0/0 or ::/0 on port {port_label}. "
            "2. Replace with a rule permitting only specific trusted CIDR ranges "
            "(e.g., your corporate IP range or VPN endpoint). "
            "3. Consider using AWS Systems Manager Session Manager instead of direct SSH/RDP."
        )
    elif severity == Severity.High:
        title = (
            f"Security Group '{sg.group_name}' allows unrestricted inbound access "
            f"on port {port_label}"
        )
        risk = (
            f"This finding is based on simulated configuration data. "
            f"Security group '{sg.group_name}' ({sg.group_id}) has an inbound rule "
            f"permitting traffic on port {port_label} from any IP address "
            f"({', '.join(sources)}). "
            "Unrestricted access on non-standard ports may expose services to unauthorized "
            "access or scanning. Configuration risk — not confirmed exploitation."
        )
        remediation = (
            f"Restrict the source CIDR for port {port_label} in security group "
            f"'{sg.group_name}': "
            "1. Replace 0.0.0.0/0 with specific CIDR ranges for trusted sources. "
            "2. Use VPC Security Group references for internal service communication. "
            "3. If this port should not be internet-facing, consider placing the service "
            "behind a load balancer."
        )
    else:  # Informational
        title = (
            f"Security Group '{sg.group_name}' allows public inbound access "
            f"on port {port_label} (expected)"
        )
        risk = (
            f"This finding is based on simulated configuration data. "
            f"Security group '{sg.group_name}' ({sg.group_id}) allows inbound traffic "
            f"on port {port_label} from the public internet. "
            f"Port {port_label} is expected to be publicly accessible for web services. "
            "Informational — noted for completeness, not a vulnerability."
        )
        remediation = (
            f"No immediate action required for port {port_label}. "
            "Best practices: ensure the service on this port has TLS configured (for port 80, "
            "redirect to 443), keep software patched, and use AWS WAF for additional protection."
        )

    return Finding(
        resource_type="SecurityGroup",
        resource_name=sg.group_name,
        severity=severity,
        title=title,
        evidence={
            "group_id": sg.group_id,
            "group_name": sg.group_name,
            "vpc_id": sg.vpc_id,
            "port": port,
            "port_label": port_label,
            "matching_rules": [_rule_to_evidence_dict(r) for r in rules],
            "source_cidrs": sources,
        },
        risk_explanation=risk,
        remediation=remediation,
    )
