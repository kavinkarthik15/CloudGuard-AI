# Technical Design Document

## Overview

CloudGuard AI is structured as a React + TypeScript + Vite frontend communicating with a Python + FastAPI backend over HTTP. In Session 1, the backend scans simulated resource configurations loaded from JSON fixtures. Scanning rules are deterministic and independent of the data source. A `ScannerProvider` interface separates data loading from rule evaluation, so the `SimulatedScannerProvider` used in Session 1 can be replaced with a `Boto3ScannerProvider` in Session 2 without modifying any Analyzer or API logic.

---

## System Architecture

```
┌──────────────────────────────────────────────────┐
│                    Browser                        │
│  React + TypeScript + Vite + Tailwind CSS         │
│                                                   │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │  Dashboard  │  │   Findings   │  │  Scan    │ │
│  │  Overview   │  │   Page       │  │  Controls│ │
│  └──────┬──────┘  └──────┬───────┘  └────┬─────┘ │
│         └────────────────┴───────────────┘        │
│                     API Client                    │
└────────────────────────┬─────────────────────────┘
                         │ HTTP / JSON
┌────────────────────────▼─────────────────────────┐
│                  FastAPI Backend                   │
│                                                   │
│  ┌──────────────────────────────────────────────┐ │
│  │               API Layer                       │ │
│  │  POST /api/scan   GET /api/findings           │ │
│  │  GET /api/export/json   GET /api/export/csv   │ │
│  └──────────────────┬───────────────────────────┘ │
│                     │                             │
│  ┌──────────────────▼───────────────────────────┐ │
│  │              Analyzer                         │ │
│  │  s3_rules.py   ec2_rules.py   models.py       │ │
│  └──────────────────┬───────────────────────────┘ │
│                     │ ScannerProvider interface    │
│  ┌──────────────────▼───────────────────────────┐ │
│  │         SimulatedScannerProvider              │ │
│  │   Loads JSON fixtures — no network calls      │ │
│  │                                               │ │
│  │   [Session 2: Boto3ScannerProvider here]      │ │
│  └──────────────────────────────────────────────┘ │
│                                                   │
│  backend/fixtures/s3_buckets.json                 │
│  backend/fixtures/security_groups.json            │
└──────────────────────────────────────────────────┘
```

---

## Backend Design

### Directory Structure

```
backend/
├── main.py                    # FastAPI app, startup, provider injection
├── config.py                  # Settings (SCANNER_PROVIDER env var, CORS origins)
├── models.py                  # Pydantic models: Finding, ScanResult, Warning
├── providers/
│   ├── __init__.py
│   ├── base.py                # ScannerProvider Protocol / ABC
│   └── simulated.py           # SimulatedScannerProvider (loads fixtures)
├── analyzers/
│   ├── __init__.py
│   ├── s3_rules.py            # S3 misconfiguration rules
│   └── ec2_rules.py           # EC2 inbound rule severity rules
├── scanner.py                 # Orchestrates provider + analyzer, returns ScanResult
├── report_generator.py        # JSON and CSV export logic
├── fixtures/
│   ├── s3_buckets.json        # Simulated S3 bucket configurations
│   └── security_groups.json   # Simulated EC2 security group configurations
└── tests/
    ├── test_s3_rules.py       # Unit tests for S3 Analyzer rules
    ├── test_ec2_rules.py      # Unit tests for EC2 Analyzer rules
    ├── test_scanner.py        # Integration tests using SimulatedScannerProvider
    ├── test_report_generator.py
    └── test_properties.py     # Hypothesis property-based tests
```

### ScannerProvider Interface

```python
# backend/providers/base.py
from typing import Protocol
from models import S3BucketConfig, SecurityGroupConfig

class ScannerProvider(Protocol):
    def list_s3_buckets(self) -> list[S3BucketConfig]: ...
    def list_security_groups(self, region: str) -> list[SecurityGroupConfig]: ...
```

The `Analyzer` receives a `ScannerProvider` instance at construction time and calls only these two methods. It has no knowledge of whether the provider is simulated or real.

### Data Models

```python
# backend/models.py (representative — not exhaustive)

class S3BucketConfig(BaseModel):
    name: str
    public_access_block: PublicAccessBlockConfig  # 4 boolean fields
    acl_grants: list[AclGrant]                    # grantee URI + permission
    is_public_policy: bool
    encryption: EncryptionConfig | None           # None = no encryption
    versioning_enabled: bool | None               # None = not checked
    logging_enabled: bool | None                  # None = not checked

class SecurityGroupConfig(BaseModel):
    group_id: str
    group_name: str
    description: str
    inbound_rules: list[InboundRule]

class InboundRule(BaseModel):
    protocol: str          # "tcp", "udp", "-1" (all)
    from_port: int | None
    to_port: int | None
    cidr_ipv4: str | None
    cidr_ipv6: str | None

class Finding(BaseModel):
    id: str                # uuid4
    resource_type: str     # "S3Bucket" | "SecurityGroup"
    resource_name: str
    severity: Severity     # Enum: Critical | High | Medium | Low | Informational
    title: str
    evidence: dict         # The specific config values that triggered the rule
    risk_explanation: str
    remediation: str
    simulated: bool = True

class ScanResult(BaseModel):
    scan_id: str
    timestamp: str         # ISO 8601
    simulated: bool
    findings: list[Finding]
    warnings: list[Warning]
    summary: dict[str, int]  # {"Critical": 3, "High": 5, ...}
```

### S3 Scanning Rules (s3_rules.py)

Rules are pure functions: `def check_*(bucket: S3BucketConfig) -> Finding | None`. The Analyzer calls each check in sequence for every bucket and collects non-None results.

| Rule function | Condition | Severity |
|---|---|---|
| `check_effective_public_acl_or_policy` | Block disabled AND (ACL public OR policy public) | Critical |
| `check_partial_public_access_block` | Any block setting disabled AND not Critical | High |
| `check_no_encryption` | No default encryption rule | High |
| `check_sse_s3_only` | Encryption = SSE-S3 (not SSE-KMS) | Informational |
| `check_versioning_disabled` *(optional)* | Versioning not enabled | Low |
| `check_logging_disabled` *(optional)* | Logging not enabled | Informational |

### EC2 Scanning Rules (ec2_rules.py)

The Analyzer iterates inbound rules per Security Group. Severity is assigned by the ordered lookup table defined in Requirement 4, criterion 2. After per-rule classification, findings are consolidated:

1. Group rules by `(security_group_id, severity, port)`.
2. If an all-ports Critical rule exists, suppress all individual-port findings for that group.
3. Emit one Finding per unique `(security_group_id, severity, port)` group with all matching rules listed in `evidence`.

### API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Liveness check — returns `{"status": "ok", "simulated": true}` |
| `POST` | `/api/scan` | Triggers a Scan_Session; returns `ScanResult` |
| `GET` | `/api/findings` | Returns the most recent `ScanResult` (or 404 if none) |
| `GET` | `/api/export/json` | Returns the most recent findings as a downloadable JSON file |
| `GET` | `/api/export/csv` | Returns the most recent findings as a downloadable CSV file |

The `POST /api/scan` body accepts an optional `region` string. In Session 1 this is stored in the `ScanResult` metadata but has no effect on fixture loading.

### Error Response Schema

All Backend error responses use:
```json
{
  "code": "ERROR_CODE",
  "message": "Human-readable description safe for display"
}
```

Defined codes: `INTERNAL_ERROR`, `FIXTURE_LOAD_ERROR`, `NO_SCAN_RESULT`.

Session 2 will add: `INVALID_CREDENTIALS`, `CREDENTIAL_VALIDATION_UNAVAILABLE`, `INSUFFICIENT_PERMISSIONS`, `AWS_UNREACHABLE`, `S3_ENUM_DENIED`, `EC2_ENUM_DENIED`.

### Fixture Format

`backend/fixtures/s3_buckets.json` — array of `S3BucketConfig`-compatible objects:
```json
[
  {
    "name": "simulated-bucket-prod",
    "public_access_block": {
      "block_public_acls": false,
      "ignore_public_acls": false,
      "block_public_policy": false,
      "restrict_public_buckets": false
    },
    "acl_grants": [
      { "grantee_uri": "http://acs.amazonaws.com/groups/global/AllUsers", "permission": "READ" }
    ],
    "is_public_policy": false,
    "encryption": null,
    "versioning_enabled": false,
    "logging_enabled": false
  }
]
```

`backend/fixtures/security_groups.json` — array of `SecurityGroupConfig`-compatible objects:
```json
[
  {
    "group_id": "sg-sim-0042",
    "group_name": "simulated-web-sg",
    "description": "Simulated web tier security group",
    "inbound_rules": [
      { "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ipv4": "0.0.0.0/0", "cidr_ipv6": null },
      { "protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_ipv4": "0.0.0.0/0", "cidr_ipv6": null }
    ]
  }
]
```

---

## Frontend Design

### Directory Structure

```
frontend/
├── index.html
├── vite.config.ts
├── tailwind.config.ts
├── tsconfig.json
├── src/
│   ├── main.tsx
│   ├── App.tsx                    # Router setup, SimulatedMode banner
│   ├── api/
│   │   └── client.ts              # Typed fetch wrappers, timeout logic
│   ├── types/
│   │   └── findings.ts            # TypeScript types matching backend models
│   ├── pages/
│   │   ├── DashboardPage.tsx      # Overview stats, chart, recent findings
│   │   ├── FindingsPage.tsx       # Full findings table with filter + search
│   │   └── ScanPage.tsx           # Scan trigger, status, region selector
│   ├── components/
│   │   ├── layout/
│   │   │   ├── AppShell.tsx       # Nav sidebar/header + outlet
│   │   │   └── SimulatedBanner.tsx # Persistent "Demo Mode — Simulated Data"
│   │   ├── dashboard/
│   │   │   ├── StatsPanel.tsx     # Severity count cards
│   │   │   ├── SeverityChart.tsx  # Bar/donut chart
│   │   │   └── RecentFindings.tsx # Last 5 findings list
│   │   ├── findings/
│   │   │   ├── FindingsTable.tsx  # Table with expandable rows
│   │   │   ├── FindingRow.tsx     # Single row + expanded detail
│   │   │   ├── SeverityFilter.tsx # Multi-select severity checkboxes
│   │   │   └── SearchInput.tsx    # Debounced text search
│   │   ├── export/
│   │   │   └── ExportButton.tsx   # Format picker + download trigger
│   │   └── shared/
│   │       ├── SeverityBadge.tsx  # Colored label chip
│   │       ├── LoadingSpinner.tsx
│   │       ├── ErrorBanner.tsx    # Dismissible error notification
│   │       └── EmptyState.tsx
│   ├── hooks/
│   │   ├── useScan.ts             # Scan trigger, polling, state
│   │   ├── useFindings.ts         # Findings fetch + filter/search logic
│   │   └── useExport.ts           # Export trigger + download
│   └── store/
│       └── scanStore.ts           # Zustand (or React context) scan state
├── tests/
│   ├── components/
│   │   ├── StatsPanel.test.tsx
│   │   ├── FindingsTable.test.tsx
│   │   ├── SeverityFilter.test.tsx
│   │   ├── SearchInput.test.tsx
│   │   └── ExportButton.test.tsx
│   └── properties/
│       └── filterExport.property.test.ts  # fast-check property tests
```

### State Management

A lightweight Zustand store (or React context if simpler) holds:
```typescript
interface ScanState {
  status: 'idle' | 'scanning' | 'complete' | 'error';
  scanResult: ScanResult | null;
  error: string | null;
  lastScanAt: string | null;
}
```

Filter and search state is local to `FindingsPage` — it is derived from `scanResult.findings`, not stored globally.

### API Client

`src/api/client.ts` wraps `fetch` with:
- Base URL from `VITE_API_BASE_URL` (defaults to `http://localhost:8000`)
- 120-second `AbortController` timeout
- Typed response parsing against the backend models
- Uniform error extraction: reads `{ code, message }` from error responses

### Routing

```
/                → redirect → /dashboard
/dashboard       → DashboardPage
/findings        → FindingsPage
/scan            → ScanPage
```

Uses React Router v6 with a persistent `AppShell` layout that wraps all routes, keeping the `SimulatedBanner` and navigation visible at all times.

### Severity Color Mapping

Consistent across all components:

| Severity | Tailwind classes (bg / text / border) |
|---|---|
| Critical | `bg-red-100 text-red-800 border-red-300` |
| High | `bg-orange-100 text-orange-800 border-orange-300` |
| Medium | `bg-yellow-100 text-yellow-800 border-yellow-300` |
| Low | `bg-blue-100 text-blue-800 border-blue-300` |
| Informational | `bg-gray-100 text-gray-600 border-gray-300` |

### Export Implementation

Both JSON and CSV exports are triggered via `GET /api/export/json` and `GET /api/export/csv`. The frontend receives the response body, creates a `Blob`, and triggers a programmatic `<a>` download without navigating away. Filenames are timestamped: `cloudguard-findings-{ISO-date}.json` / `.csv`.

---

## Testing Strategy

### Backend (pytest + Hypothesis)

- **Unit tests** (`test_s3_rules.py`, `test_ec2_rules.py`): One test per rule, using inline fixture dicts. Cover the positive case (rule fires), the negative case (rule does not fire), and boundary cases (e.g., partial block settings, consolidated findings).
- **Integration tests** (`test_scanner.py`): Instantiate `SimulatedScannerProvider` with the real fixture files, run the full `Scanner.run()`, assert findings list is non-empty, all Finding fields are populated, all Severity values are valid.
- **Property-based tests** (`test_properties.py`): Use `hypothesis` strategies to generate arbitrary `S3BucketConfig` instances and assert Analyzer output Severity is always a member of the valid set.
- **Provider isolation test**: Assert `SimulatedScannerProvider` module has no reference to `boto3` at import time.

### Frontend (Vitest + React Testing Library + fast-check)

- **Component tests**: Render each component with mock data, assert visible output. Simulate user interactions (click to expand row, change filter, type in search).
- **State tests**: Assert `useScan` hook transitions through `idle → scanning → complete` on a successful API mock.
- **Property-based tests** (`fast-check`): Generate arbitrary arrays of `Finding` objects, apply severity filter, assert result is a subset. Generate arbitrary search strings, assert result is a subset.
- **Export consistency test**: Generate a findings list, call both export formatters, assert every finding in the list appears in the output with correct field values.

---

## Session 2 Extension Points

The following components are designed specifically to make Session 2 integration straightforward:

1. **`ScannerProvider` protocol** — Session 2 adds `Boto3ScannerProvider` in `backend/providers/boto3_provider.py`. No changes to `Analyzer`, `Scanner`, or API layer required.
2. **`SCANNER_PROVIDER` env var** — `config.py` reads this at startup. Setting `SCANNER_PROVIDER=boto3` switches providers.
3. **`ScanResult.simulated` field** — Set to `False` by the `Boto3ScannerProvider`. Frontend uses this flag to conditionally display/suppress the `SimulatedBanner` and to label exports.
4. **`POST /api/scan` region parameter** — Already wired through in Session 1 (stored in metadata). Session 2 passes it to `Boto3ScannerProvider.list_security_groups(region)`.
5. **Error codes** — `INVALID_CREDENTIALS`, `CREDENTIAL_VALIDATION_UNAVAILABLE`, `INSUFFICIENT_PERMISSIONS`, `AWS_UNREACHABLE`, `S3_ENUM_DENIED`, `EC2_ENUM_DENIED` are defined and documented but not raised in Session 1 (no code paths reach them).
6. **IAM policy file** — `docs/iam-policy.json` can be added in Session 2 without touching any Session 1 code.

---

## Constraints and Non-Goals (Session 1)

- No real AWS API calls of any kind.
- No Boto3 import in any Session 1 code path.
- No AWS credential input in the Frontend.
- No STS validation.
- No database or persistent storage — scan results live in memory for the lifetime of the backend process.
- No Amazon Bedrock.
- No AWS deployment artifacts (CDK, SAM, Terraform).
- No fake/mock authentication system.
- Simulated results SHALL never be described as live AWS findings in any UI text, export file, or API response.
