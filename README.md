# CloudGuard AI

**AWS Security Misconfiguration Auditor** â€” Build on AWS Challenge Â· Competition MVP v1

CloudGuard AI scans AWS resource configurations for security misconfigurations, explains the risk in plain language, and provides specific remediation guidance. It runs entirely on a local machine and makes only read-only calls to AWS APIs.

---

## What It Does

| Capability | Status |
|---|:---:|
| Demo Mode â€” simulated findings with no AWS credentials | âœ… |
| Live AWS Mode â€” real Boto3 scanning with profile selection | âœ… |
| AWS CLI profile discovery and dropdown selection | âœ… |
| AWS identity verification before scan | âœ… |
| S3 bucket security rule analysis | âœ… |
| EC2 security group inbound rule analysis | âœ… |
| Findings dashboard with severity chart and stats | âœ… |
| Expandable findings with evidence and remediation | âœ… |
| JSON and CSV export (keyed to a specific scan) | âœ… |
| Region selector for EC2 scanning | âœ… |
| AccessDenied surfaced as a warning, not a clean result | âœ… |

---

## Security Rules

### S3 Bucket Rules

| Rule | Severity |
|---|:---:|
| Effectively public bucket (block disabled + ACL or policy public) | Critical |
| Incomplete public access block (any of 4 settings disabled) | High |
| No default server-side encryption configured | High |
| AuthenticatedUsers ACL grant (any AWS account can read) | Medium |
| SSE-S3 only â€” KMS recommended | Informational |
| Versioning not enabled | Low |
| Access logging not enabled | Informational |

The four S3 Block Public Access settings checked individually:
`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`.

### EC2 Security Group Rules

| Rule | Severity |
|---|:---:|
| Critical port open to 0.0.0.0/0 or ::/0 â€” SSH (22), RDP (3389), MySQL (3306), PostgreSQL (5432), MSSQL (1433), MongoDB (27017) | Critical |
| All ports open to internet (protocol -1 or 0â€“65535) | Critical |
| Non-standard port open to internet | High |
| IPv6 ::/0 world-open rule | Critical / High |
| HTTP/HTTPS (80, 443) open to internet | Informational |
| Secure restricted security group | No finding |

> **Coverage note:** CloudGuard AI currently covers S3 buckets and EC2 security groups only. IAM policies, CloudTrail, RDS, Lambda, and other AWS services are not scanned in this version.

---

## Demo Mode vs Live AWS Mode

| | Demo Mode | Live AWS Mode |
|---|---|---|
| Data source | Simulated fixture data (`providers/simulated.py`) | Real AWS APIs via Boto3 |
| AWS credentials required | **No** | **Yes** â€” valid AWS CLI SSO session |
| Findings represent real vulnerabilities | **No** | Yes â€” in the scanned account |
| UI label | Amber "Simulated Data" banner | "Live Mode" label |
| `simulated` flag in exports | `true` | `false` |
| `sts:GetCallerIdentity` called | No | Yes, before scan |

> Demo Mode findings are for demonstration purposes only. They do not represent real AWS vulnerabilities in any account.

---

## Architecture

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  React Frontend  (Vite Â· TypeScript)     â”‚
â”‚  localhost:5173                          â”‚
â”‚                                          â”‚
â”‚  Pages: Dashboard Â· Findings Â· Scan      â”‚
â”‚  State: Zustand scan store               â”‚
â”‚  Charts: Recharts                        â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                â”‚  REST JSON API
                â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  FastAPI Backend  (Python Â· Uvicorn)     â”‚
â”‚  127.0.0.1:8001  (local only)            â”‚
â”‚                                          â”‚
â”‚  POST /api/scan      GET /api/profiles   â”‚
â”‚  GET /api/identity   GET /api/regions    â”‚
â”‚  GET /api/export/{scan_id}/json          â”‚
â”‚  GET /api/export/{scan_id}/csv           â”‚
â”‚                                          â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”     â”‚
â”‚  â”‚  Provider Abstraction Layer     â”‚     â”‚
â”‚  â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚     â”‚
â”‚  â”‚  â”‚  Simulated   â”‚ â”‚  Boto3   â”‚  â”‚     â”‚
â”‚  â”‚  â”‚  Provider    â”‚ â”‚  Providerâ”‚  â”‚     â”‚
â”‚  â”‚  â”‚ (Demo Mode)  â”‚ â”‚(Live AWS)â”‚  â”‚     â”‚
â”‚  â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚     â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜     â”‚
â”‚                                          â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”     â”‚
â”‚  â”‚  Rules Engine                   â”‚     â”‚
â”‚  â”‚  s3_rules.py Â· ec2_rules.py     â”‚     â”‚
â”‚  â”‚  (pure functions, provider-     â”‚     â”‚
â”‚  â”‚   independent)                  â”‚     â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜     â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                â”‚  Read-only AWS API calls
                â”‚  (Live Mode only)
                â–¼
          AWS APIs (Boto3)
          sts Â· s3 Â· ec2
```

**Design principles:**
- Backend binds to `127.0.0.1` only â€” not reachable from the network.
- AWS credentials are never logged, stored, or returned in API responses.
- The rules engine is independent of the provider â€” adding a new cloud provider requires no changes to detection logic.
- Exports are keyed by `scan_id`, preventing mismatched or stale results.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite 6, Tailwind CSS, Recharts, Zustand |
| Backend | Python 3.11+, FastAPI 0.143, Uvicorn, Pydantic v2 |
| AWS SDK | Boto3 1.38, Botocore |
| Testing (backend) | pytest 9.1, Hypothesis 6.169, httpx |
| Testing (frontend) | Vitest 2.1, Testing Library, fast-check |
| Python environment | venv (`.venv/` in `backend/`) |

---

## Prerequisites

- **Python** â‰¥ 3.11
- **Node.js** â‰¥ 18 and **npm** â‰¥ 8
- **AWS CLI v2** (for Live Mode â€” profile discovery and SSO login)

---

## Installation and Startup

> All commands are for **Windows CMD**. The workspace path contains a space (`D:\CloudGuard AI`) â€” use `cd /d` with quotes.

### 1. Start the Backend

```cmd
cd /d "D:\CloudGuard AI\backend"
.venv\Scripts\activate
python -m uvicorn main:app --host 127.0.0.1 --port 8001 --reload
```

Wait for:
```
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8001
```

Health check: http://127.0.0.1:8001/api/health
API docs: http://127.0.0.1:8001/docs

> **Do not use `start_backend.bat` directly without verifying the port.** The correct port is `8001` and the correct host is `127.0.0.1`. If you need to use a different port, also update `VITE_API_BASE_URL` in `frontend/.env.local`.

### 2. Start the Frontend

Open a second terminal:

```cmd
cd /d "D:\CloudGuard AI\frontend"
npm install
npm run dev
```

Open **http://localhost:5173** in a browser.

The app opens in Demo Mode automatically. No AWS credentials are needed to explore the dashboard, findings, and exports.

---

## Live AWS Mode â€” Setup

### AWS CLI Profiles

List configured profiles:

```cmd
aws configure list-profiles
```

If no profiles are configured, set one up:

```cmd
aws configure
```

Or for AWS SSO:

```cmd
aws configure sso
```

### AWS SSO Login

Before using Live Mode, log in with your SSO profile:

```cmd
aws sso login --profile your-profile-name
```

Verify credentials are valid:

```cmd
aws sts get-caller-identity --profile your-profile-name
```

### Required AWS Permissions (read-only)

CloudGuard AI requires only the following read-only actions:

| Action | Purpose |
|---|---|
| `sts:GetCallerIdentity` | Verify identity before scan |
| `s3:ListAllMyBuckets` | Enumerate S3 buckets |
| `s3:GetBucketLocation` | Discover each bucket's actual AWS region (Phase 4D) |
| `s3:GetBucketPublicAccessBlock` | Read Block Public Access settings |
| `s3:GetBucketPolicyStatus` | Check if bucket policy is public |
| `s3:GetBucketAcl` | Read ACL grants |
| `s3:GetBucketEncryption` | Check encryption configuration |
| `s3:GetBucketVersioning` | Check versioning status |
| `s3:GetBucketLogging` | Check access logging |
| `ec2:DescribeSecurityGroups` | Read security group inbound rules |
| `ec2:DescribeRegions` | Discover enabled regions for All-Enabled scan mode (Phase 4E; gracefully degraded if denied) |

No write, create, delete, or IAM permissions are required or used.

If a permission is denied for a specific resource, CloudGuard AI surfaces a warning for that resource rather than treating it as secure.

### Profile and Region Selection

In the Scan page, select your AWS CLI profile from the dropdown and choose a region. CloudGuard AI calls `sts:GetCallerIdentity` to verify the identity before the scan starts.

> **Note:** S3 scanning is global (all buckets in the account). EC2 security group scanning is scoped to the selected region.

---

## Scan Execution and Export Workflow

1. Open http://localhost:5173
2. Navigate to **Scan**
3. Select **Demo Mode** (no credentials) or **Live AWS** (requires SSO session)
4. For Live Mode: select a profile and region, then click **Verify AWS Identity**
5. Click **Run Scan**
6. Navigate to **Findings** to review results
7. Use the severity filter and search to explore findings
8. Click any finding row to expand evidence and remediation
9. Click **Export Report** â†’ **Download JSON** or **Download CSV**

> Exports are keyed to the specific scan that produced them. If the backend restarts and the scan expires, the export returns `SCAN_NOT_FOUND` â€” re-run the scan and export immediately.

---

## Tests

### Backend (pytest + Hypothesis)

```cmd
cd /d "D:\CloudGuard AI\backend"
.venv\Scripts\activate
python -m pytest --tb=short -q
```

**Verified result:** `175 passed, 0 failed` (as of competition-mvp-v1)

```
...............................................................................
...............................................................................
...............................
175 passed, 1 warning in 3.55s
```

The 1 warning is a deprecation notice from the `httpx`/`starlette` test client â€” non-functional, no action required.

### Frontend (Vitest + fast-check)

```cmd
cd /d "D:\CloudGuard AI\frontend"
npm run test
```

**Verified result:** `68 passed, 0 failed` (as of competition-mvp-v1)

> `npm run test` runs Vitest in single-pass mode (equivalent to `vitest run`).

### Frontend Production Build

```cmd
cd /d "D:\CloudGuard AI\frontend"
npm run build
```

**Verified result:** Exit 0, `dist/` artifacts generated successfully.

### Test Classification

- **All 175 backend tests** use mocked Boto3 responses and fixture data â€” no live AWS calls are made during testing.
- **`test_boto3_provider.py`** tests the live provider plumbing and requires real credentials to run fully against AWS.
- **Real-world vulnerability detection** (finding actual misconfigurations in a live account) was not performed during testing â€” no insecure AWS resources were created.

---

## Security Model

- **Local development:** By default the backend binds to `127.0.0.1` so it is only reachable from the same machine. This is a development convenience, not a security control. A production or shared deployment must configure its own network controls (firewall, reverse proxy, authentication) appropriate to the hosting environment.
- **Demo-Only production mode:** Public or shared deployments must set `ALLOW_LIVE_AWS_SCANS=false` on the backend. This rejects all live AWS operations (identity verification, live scans, credential-based region enrichment) with HTTP 403 `LIVE_AWS_DISABLED` before any Boto3 session is created. Demo Mode continues to work. See `backend/.env.example` for the exact configuration.
- **Read-only AWS access:** When live scanning is enabled, the application calls only read-only AWS APIs (`s3:List*`, `s3:Get*`, `ec2:Describe*`, `sts:GetCallerIdentity`). No write, create, delete, or IAM actions are called. AWS IAM policies enforce this restriction; the application does not.
- **Credential handling for live scans:** In local development, AWS credentials (Access Key ID, Secret Access Key, optional Session Token) are supplied by the user through the Scan page form for each live scan. Credentials are held transiently for the duration of the request, forwarded to the backend over the local connection, used to create a request-scoped Boto3 session, and then discarded. Credentials are never stored in browser storage, Zustand state, application databases, scan results, or exports. Credential values must never appear in logs, API responses, error messages, or generated reports.
- **No credential exposure in exports:** JSON and CSV exports contain findings only. The `simulated` flag in every export distinguishes demo from live results.
- **AccessDenied is not a clean result:** If CloudGuard AI cannot retrieve a security attribute due to missing permissions, it surfaces a warning for that resource rather than treating it as secure.
- **S3 bucket policies:** CloudGuard AI checks whether a bucket policy is public via `s3:GetBucketPolicyStatus` (the `IsPublic` field). It does **not** analyze or display the full contents of S3 bucket policies. A bucket with a complex policy that `GetBucketPolicyStatus` reports as non-public will not produce a finding for policy contents, even if the policy contains permissive statements.
- **Secret scanning:** Gitleaks v8.30.1 was run against the full git history. Zero genuine secrets found. See [PRE_COMPETITION_VERIFICATION.md](PRE_COMPETITION_VERIFICATION.md).

### Scanner Scope

CloudGuard AI scans **S3 buckets** and **EC2 security groups** only. It does not provide comprehensive AWS account security coverage. The following are **not** scanned:

- IAM policies, users, roles, and permission boundaries
- CloudTrail configuration and logging
- RDS, Lambda, VPC Flow Logs, CloudWatch, Route 53
- S3 bucket policies (only `IsPublic` status via `GetBucketPolicyStatus`)
- Network ACLs, route tables, and VPC configuration
- AWS Config rules and Security Hub findings

Adding coverage for additional services is documented in the Future Roadmap.

---

## Limitations

- **Single region per scan:** EC2 security groups are scanned in the selected region only. Multi-region scanning is not implemented.
- **Single account per scan:** One AWS account per scan invocation. Multi-account scanning is not implemented.
- **In-memory scan store:** Scans are stored in memory only. The backend stores up to 20 recent scans; scans are lost on restart.
- **Services covered:** S3 buckets and EC2 security groups only. IAM policies, CloudTrail, RDS, Lambda, VPC Flow Logs, and other services are not scanned.
- **No persistent database:** There is no database backend in this version.
- **Local application:** There is no production deployment, SaaS infrastructure, or public endpoint.
- **Live credential requirement:** Live Mode requires a valid AWS CLI SSO session. Expired sessions return a 401 error with a clear message.

---

## Future Roadmap

- **Multi-region scanning** â€” the provider abstraction already supports iteration; orchestration changes only
- **Additional service coverage** â€” IAM policy analysis, CloudTrail configuration, RDS public access, Lambda function URLs, S3 bucket website hosting
- **CI/CD integration** â€” scan as part of a deployment pipeline; fail builds on Critical findings
- **Suppression lists** â€” mark accepted risks to reduce noise on known-acceptable configurations
- **Persistent scan history** â€” database backend for historical trend analysis
- **Multi-account support** â€” assumed-role credentials per account, organization-level scanning
- **Remediation tracking** â€” mark findings as remediated and re-verify

---

## Demonstration

For jury demonstration instructions, startup commands, AWS SSO setup, demo fallback, and prepared jury Q&A, see:

ðŸ“‹ **[DEMO_GUIDE.md](DEMO_GUIDE.md)**

For the complete pre-competition security scan, detection test matrix, test results, and final readiness verdict, see:

ðŸ” **[PRE_COMPETITION_VERIFICATION.md](PRE_COMPETITION_VERIFICATION.md)**

---

## Project Structure

```
D:\CloudGuard AI\
â”œâ”€â”€ backend\
â”‚   â”œâ”€â”€ main.py                    FastAPI app, all endpoints
â”‚   â”œâ”€â”€ models.py                  Pydantic v2 models
â”‚   â”œâ”€â”€ config.py                  Provider factory, CORS, defaults
â”‚   â”œâ”€â”€ scanner.py                 Scan orchestration
â”‚   â”œâ”€â”€ report_generator.py        JSON and CSV export
â”‚   â”œâ”€â”€ providers\
â”‚   â”‚   â”œâ”€â”€ base.py                ScannerProvider Protocol
â”‚   â”‚   â”œâ”€â”€ simulated.py           Demo Mode â€” JSON fixture data
â”‚   â”‚   â””â”€â”€ boto3_provider.py      Live Mode â€” real AWS APIs
â”‚   â”œâ”€â”€ analyzers\
â”‚   â”‚   â”œâ”€â”€ s3_rules.py            S3 misconfiguration rules (7 rules)
â”‚   â”‚   â””â”€â”€ ec2_rules.py           EC2 security group rules
â”‚   â”œâ”€â”€ fixtures\
â”‚   â”‚   â”œâ”€â”€ s3_buckets.json        Simulated S3 configurations
â”‚   â”‚   â””â”€â”€ security_groups.json   Simulated EC2 SG configurations
â”‚   â”œâ”€â”€ tests\                     175 pytest tests
â”‚   â”œâ”€â”€ requirements.txt
â”‚   â””â”€â”€ pytest.ini
â”œâ”€â”€ frontend\
â”‚   â”œâ”€â”€ src\
â”‚   â”‚   â”œâ”€â”€ api\client.ts          API client (base URL from .env.local)
â”‚   â”‚   â”œâ”€â”€ App.tsx                Router and layout
â”‚   â”‚   â”œâ”€â”€ components\            Dashboard, findings, export, layout
â”‚   â”‚   â””â”€â”€ ...
â”‚   â”œâ”€â”€ .env.local                 VITE_API_BASE_URL=http://127.0.0.1:8001
â”‚   â””â”€â”€ package.json
â”œâ”€â”€ run_server.py                  Alternative backend launcher
â”œâ”€â”€ DEMO_GUIDE.md                  Jury demonstration script
â””â”€â”€ PRE_COMPETITION_VERIFICATION.md  Security and test verification report
```

---

*competition-mvp-v1 Â· commit d8847c9 Â· main branch*
