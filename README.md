# CloudGuard AI

**AWS Security Misconfiguration Auditor** — Build on AWS Challenge

> **Session 1 — Simulated Data.** All findings are generated from JSON fixture configurations. No real AWS API calls are made. A persistent "Demo Mode — Simulated Data" banner appears on every page.

---

## What It Does

CloudGuard AI scans AWS resource configurations for security misconfigurations, explains risks in plain language, and provides actionable remediation guidance. The professional security dashboard shows severity summaries, charts, searchable findings, expandable evidence, and JSON/CSV exports.

**Detected misconfigurations (Session 1):**

| Resource | Rule | Severity |
|---|---|---|
| S3 Bucket | Effectively public (block disabled + ACL/policy public) | Critical |
| S3 Bucket | Partial public access block misconfiguration | High |
| S3 Bucket | No default encryption configured | High |
| S3 Bucket | SSE-S3 only (KMS recommended) | Informational |
| EC2 Security Group | World-open SSH, RDP, DB ports (22, 3389, 3306, 5432, 1433, 27017) | Critical |
| EC2 Security Group | All-ports open (protocol -1) | Critical |
| EC2 Security Group | World-open non-standard port | High |
| EC2 Security Group | World-open port 80 or 443 | Informational |

---

## Architecture

```
frontend/  (React + TypeScript + Vite + Tailwind CSS)
  └── src/
      ├── api/client.ts           API client with 120s timeout
      ├── store/scanStore.ts      Zustand global scan state
      ├── pages/                  Dashboard, Findings, Scan
      ├── components/             Layout, dashboard, findings, export, shared
      ├── hooks/                  useFindings, useExport
      └── types/findings.ts       TypeScript types mirroring backend models

backend/   (Python + FastAPI)
  ├── main.py                     FastAPI app, endpoints
  ├── models.py                   Pydantic v2 models
  ├── config.py                   SCANNER_PROVIDER env var
  ├── scanner.py                  Scanner orchestrator
  ├── providers/
  │   ├── base.py                 ScannerProvider Protocol
  │   └── simulated.py            SimulatedScannerProvider (JSON fixtures)
  ├── analyzers/
  │   ├── s3_rules.py             S3 misconfiguration rules
  │   └── ec2_rules.py            EC2 inbound rule rules
  ├── report_generator.py         JSON and CSV export
  └── fixtures/
      ├── s3_buckets.json         12 simulated S3 configurations
      └── security_groups.json    11 simulated EC2 SG configurations
```

### Session 1 vs Session 2

- **Session 1 (this build):** `SimulatedScannerProvider` loads JSON fixtures. No Boto3, no AWS credentials, no real API calls.
- **Session 2 (future):** `Boto3ScannerProvider` will implement the same `ScannerProvider` interface using real AWS read-only APIs. Set `SCANNER_PROVIDER=boto3` to activate it. No changes to `Analyzer`, `Scanner`, or API layer required.

---

## Prerequisites

- **Node.js** ≥ 18 (tested with 24.x)
- **Python** ≥ 3.11 (tested with 3.13.x)
- **npm** ≥ 8

---

## Local Setup — Backend

```cmd
cd /d "D:\CloudGuard AI\backend"
.venv\Scripts\activate.bat
python -m uvicorn main:app --host 127.0.0.1 --port 8001 --reload
```

The backend will be available at `http://127.0.0.1:8001`.

API docs (auto-generated): `http://127.0.0.1:8001/docs`

> **Note:** Port 8001 is used because port 8000 may be occupied by other local services. The port is configured in `run_server.py` and must match `VITE_API_BASE_URL` in `frontend/.env.local`.

---

## Local Setup — Frontend

```cmd
cd /d "D:\CloudGuard AI\frontend"
npm install
npm run dev
```

Open `http://localhost:5173` — it redirects to `/dashboard` and auto-triggers a simulated scan.

> **Ensure the backend is running first** so the auto-scan on dashboard load succeeds.

---

## Running Tests

**Backend tests (pytest + Hypothesis):**
```cmd
cd /d "D:\CloudGuard AI"
backend\.venv\Scripts\python.exe run_tests.py
```

**Frontend tests (Vitest + fast-check):**
```cmd
cd /d "D:\CloudGuard AI\frontend"
npm run test
```

**Expected results:** 82 backend tests pass, 32 frontend tests pass.

---

## Production Build

```cmd
cd /d "D:\CloudGuard AI\frontend"
npm run build
npm run preview
```

---

## Demo Mode

The application always shows a **"Demo Mode — Simulated Data"** banner. All findings originate from deterministic rule evaluation of the fixture files in `backend/fixtures/`. No finding is hardcoded into the frontend.

Exports (JSON and CSV) include a `simulated: true` field/column to prevent confusion with real scan results.

---

## Extending to Real AWS (Session 2)

1. Implement `Boto3ScannerProvider` in `backend/providers/boto3_provider.py` following the `ScannerProvider` Protocol in `backend/providers/base.py`.
2. Set the environment variable `SCANNER_PROVIDER=boto3` before starting the backend.
3. Configure AWS credentials via the standard Boto3 credential chain (env vars, `~/.aws/credentials`, IAM instance role).
4. The required read-only IAM permissions are documented in `docs/iam-policy.json` (to be added in Session 2).

No changes to `Analyzer`, `Scanner`, `main.py`, or any frontend code are required.
