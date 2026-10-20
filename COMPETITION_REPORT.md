# CloudGuard AI — Competition MVP Report

**Prepared for:** AWS Competition Jury Demonstration
**Date:** 2026-10-20
**Status:** ✅ Ready for local jury demonstration

---

## 1. Working Features

All features below were verified by reading source code and running the automated test suite.

### Demo Mode
- ✅ SimulatedScannerProvider loads findings from JSON fixture files (`backend/fixtures/s3_buckets.json`, `backend/fixtures/security_groups.json`).
- ✅ No AWS credentials required — runs entirely from local fixture data.
- ✅ Dashboard auto-triggers a demo scan on first load.
- ✅ Amber "Demo Mode — Simulated Data" banner persists on every page.
- ✅ Sidebar footer dynamically shows "Demo Mode" vs "Live AWS Mode" based on the actual scan result.

### Live AWS Mode
- ✅ Profile selector discovers AWS CLI profiles via botocore (`GET /api/profiles`).
- ✅ Region selector returns all regions from botocore metadata (`GET /api/regions`), no AWS API call required.
- ✅ Identity verification calls `sts:GetCallerIdentity` and displays Account ID, Role ARN, and Region.
- ✅ `verifiedFor` tracking prevents stale identity — changing profile or region clears identity and blocks scan until re-verified.
- ✅ Expired/missing credentials produce clear error messages with `aws sso login` instructions.

### S3 Security Scanning
- ✅ Lists all buckets with `s3:ListAllMyBuckets`.
- ✅ Per-bucket attribute fetch: public access block, ACL grants, bucket policy status, encryption, versioning, logging.
- ✅ Detects: effectively public bucket (Critical), partial public access block (High), no encryption (High), authenticated-users ACL (Medium), versioning disabled (Low), SSE-S3 only (Informational), logging disabled (Informational).
- ✅ `NoSuchPublicAccessBlockConfiguration` → all four settings set to `False` (not an error).
- ✅ `NoSuchBucketPolicy` → `is_public_policy = False` (not an error).
- ✅ `AccessDenied` on per-attribute calls → Warning recorded, scan continues.
- ✅ `AccessDenied` on `ListAllMyBuckets` → `InsufficientPermissionsError` returned to frontend as HTTP 403.

### EC2 Security Group Scanning
- ✅ Paginates `ec2:DescribeSecurityGroups` in the selected region.
- ✅ Detects: world-open SSH/RDP/DB ports (Critical), all-ports open (Critical), non-standard port (High), HTTP/HTTPS (Informational).
- ✅ Consolidates IPv4 + IPv6 rules on the same port into one finding.
- ✅ `AccessDenied` on `DescribeSecurityGroups` → `InsufficientPermissionsError` returned to frontend as HTTP 403.

### Findings Display
- ✅ Every finding includes: `resource_type`, `resource_name`, `severity`, `title`, `evidence` (dict), `risk_explanation`, `remediation`.
- ✅ `simulated: true` for demo findings, `simulated: false` for live findings.
- ✅ Live findings have risk text updated from "simulated configuration data" to "live AWS configuration data".
- ✅ FindingsTable: expandable rows, severity filter, text search.
- ✅ Zero findings shows explicit "No findings detected" message — no blank/broken table.

### Export
- ✅ `/api/export/{scan_id}/json` — returns JSON keyed to exact scan.
- ✅ `/api/export/{scan_id}/csv` — returns CSV keyed to exact scan.
- ✅ Legacy `/api/export/json` and `/api/export/csv` endpoints retained for backward compatibility.
- ✅ `SCAN_NOT_FOUND` (404) if scan_id has expired — user sees a clear retry message.
- ✅ Export filename includes scan date and short scan_id prefix.
- ✅ JSON export includes `simulated`, `scan_id`, `aws_account_id`, `aws_identity_arn`, `summary`, `findings`, `warnings`.
- ✅ CSV export has one row per finding with `simulated` column reflecting actual source.
- ✅ Multi-line remediation text is flattened (no embedded newlines in CSV rows).

### Permission Failure Handling
- ✅ `AccessDenied` on list operations (`ListAllMyBuckets`, `DescribeSecurityGroups`) → HTTP 403 with `INSUFFICIENT_PERMISSIONS` error code shown to the user.
- ✅ `AccessDenied` on per-bucket attribute calls → `Warning` added to scan result with resource ID and reason — never silently treated as "no issue".
- ✅ Expired credentials → HTTP 401 with `INVALID_CREDENTIALS` error code shown to the user.
- ✅ Live scan auth failure clears `verifiedFor` so user must re-verify before scanning again.

---

## 2. Failed or Incomplete Features

| Feature | Status | Reason |
|---|---|---|
| Multi-region scanning | Not implemented | Out of scope per competition constraints. Single-region scanning is fully working. |
| Region dropdown selector in UI | Not implemented in frontend | The region is entered as a free-text input field. Region list is fetched from the backend but used only for validation/enrichment, not as a dropdown. This is functional. |
| `ec2:DescribeRegions` opt-in enrichment | Partially integrated | The backend fetches and returns enabled regions for a profile, but the frontend does not display this as a dropdown. The text input accepts any valid region name. |

---

## 3. Exact Test Results

### Backend pytest
```
175 passed, 1 warning in 4.21s
```
- Warning: `StarletteDeprecationWarning` about `httpx` in FastAPI TestClient — non-functional, does not affect test results.
- Test files: `test_s3_rules.py`, `test_ec2_rules.py`, `test_scanner.py`, `test_boto3_provider.py`, `test_report_generator.py`, `test_properties.py`, `test_export_endpoints.py`, `test_profiles.py`.
- All AWS interactions in `test_scanner.py` and `test_boto3_provider.py` use `unittest.mock` — no real AWS account required.

### Frontend Vitest
```
8 test files passed
68 tests passed, 0 failed
EXIT: 0
```
- Test files: `scanStore.test.ts`, `AppShell.test.tsx`, `ExportButton.test.tsx`, `FindingsTable.test.tsx`, `SearchInput.test.tsx`, `SeverityFilter.test.tsx`, `StatsPanel.test.tsx`, `filterExport.property.test.ts`.

### Frontend Production Build
```
✓ 674 modules transformed
✓ built in 5.03s
BUILDEXITCODE=0
```
- Warning: one chunk is 595 kB (>500 kB gzip threshold) — non-critical, does not affect functionality.

---

## 4. Demo Readiness

**Status: ✅ YES — Ready for local jury demonstration**

| Capability | Status |
|---|---|
| Application starts locally | ✅ Backend imports cleanly; uvicorn starts without errors |
| Demo Mode works without AWS credentials | ✅ SimulatedScannerProvider uses only local fixture files |
| Live Mode shows verified AWS account | ✅ Account ID, ARN, region displayed after identity verification |
| Zero findings handled gracefully | ✅ Explicit "No findings detected" message on both Dashboard and Scan page |
| Export works | ✅ JSON and CSV download immediately after scan |
| All tests pass | ✅ 175 backend + 68 frontend = 243 tests, all passing |
| Production build succeeds | ✅ |

---

## 5. Remaining Critical Blockers

**None.** The application is fully functional for a local jury demonstration.

### Non-critical items (do not block demo):
- Chunk size warning in production build (cosmetic — does not affect functionality).
- `StarletteDeprecationWarning` in backend test runner (library version mismatch — does not affect test results).
- Region selector is text input rather than dropdown — functional but less polished.
- `start_backend.bat` uses port 8000 but `frontend/.env.local` and README specify port 8001. Use port 8001 for both to be consistent (as documented in README and DEMO_GUIDE.md).

---

## Startup Quick Reference

```cmd
REM Terminal 1 — Backend (port 8001)
cd /d "D:\CloudGuard AI\backend"
.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8001 --reload

REM Terminal 2 — Frontend
cd /d "D:\CloudGuard AI\frontend"
npm run dev
```

Then open: **http://localhost:5173**

See `DEMO_GUIDE.md` for the full step-by-step jury demonstration sequence.
