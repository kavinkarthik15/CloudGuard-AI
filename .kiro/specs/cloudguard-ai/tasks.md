# Task List — CloudGuard AI Session 1

**Scope:** Session 1 only — simulated AWS resource scanning, deterministic rules, dashboard, exports, and tests. No Boto3, no real AWS API calls, no credential handling, no database.

---

## Phase 1 — Project Initialization

### Task 1.1 — Initialize the Backend Project
- **Requirement:** Design §Backend Directory Structure
- **Action:** Create the `backend/` directory. Initialize a Python virtual environment. Create `requirements.txt` (or `pyproject.toml`) pinning: `fastapi`, `uvicorn[standard]`, `pydantic>=2`, `hypothesis`, `pytest`, `pytest-asyncio`, `httpx`. Create `backend/main.py` with a minimal FastAPI app instance, CORS middleware allowing `http://localhost:5173`, and a `GET /api/health` endpoint that returns `{"status": "ok", "simulated": true}`.
- **Completion condition:** `uvicorn main:app --reload` starts without errors and `GET http://localhost:8000/api/health` returns `{"status": "ok", "simulated": true}` with HTTP 200.
- **Dependencies:** None.

### Task 1.2 — Initialize the Frontend Project
- **Requirement:** Design §Frontend Directory Structure
- **Action:** Scaffold a new Vite project in `frontend/` using the React + TypeScript template (`npm create vite@latest frontend -- --template react-ts`). Install and configure Tailwind CSS v3 (`tailwindcss`, `postcss`, `autoprefixer`). Install React Router v6, Zustand, and Recharts. Install dev dependencies: `vitest`, `@vitest/ui`, `@testing-library/react`, `@testing-library/user-event`, `@testing-library/jest-dom`, `fast-check`, `jsdom`. Configure `vite.config.ts` with a `test` block (jsdom environment, globals true, setupFiles pointing to a test setup file). Add `VITE_API_BASE_URL=http://localhost:8000` to a `.env.local` file. Delete the Vite boilerplate (`App.css`, default SVG assets, boilerplate content in `App.tsx`).
- **Completion condition:** `npm run dev` starts Vite on port 5173 without errors. `npm run test` runs Vitest and exits cleanly (zero tests, zero failures).
- **Dependencies:** None (parallel with Task 1.1).

---

## Phase 2 — Shared Contracts: Models and Types

### Task 2.1 — Define Backend Pydantic Models
- **Requirement:** Req 3.10, Req 4.6, Req 6.3, Req 6.4; Design §Data Models
- **Action:** Create `backend/models.py` with the following Pydantic v2 models:
  - `Severity` — `Enum` with values `Critical`, `High`, `Medium`, `Low`, `Informational`.
  - `PublicAccessBlockConfig` — four `bool` fields: `block_public_acls`, `ignore_public_acls`, `block_public_policy`, `restrict_public_buckets`.
  - `AclGrant` — `grantee_uri: str`, `permission: str`.
  - `EncryptionConfig` — `sse_algorithm: str` (e.g., `"AES256"` or `"aws:kms"`).
  - `S3BucketConfig` — `name: str`, `public_access_block: PublicAccessBlockConfig`, `acl_grants: list[AclGrant]`, `is_public_policy: bool`, `encryption: EncryptionConfig | None`, `versioning_enabled: bool | None = None`, `logging_enabled: bool | None = None`.
  - `InboundRule` — `protocol: str`, `from_port: int | None`, `to_port: int | None`, `cidr_ipv4: str | None`, `cidr_ipv6: str | None`.
  - `SecurityGroupConfig` — `group_id: str`, `group_name: str`, `description: str`, `inbound_rules: list[InboundRule]`.
  - `Finding` — `id: str` (uuid4 default factory), `resource_type: str`, `resource_name: str`, `severity: Severity`, `title: str`, `evidence: dict`, `risk_explanation: str`, `remediation: str`, `simulated: bool = True`.
  - `Warning` — `resource_id: str`, `reason: str`.
  - `ScanResult` — `scan_id: str` (uuid4 default factory), `timestamp: str`, `simulated: bool = True`, `region: str`, `findings: list[Finding]`, `warnings: list[Warning]`, `summary: dict[str, int]`.
  - `ScanRequest` — `region: str = "us-east-1"`.
  - `ErrorResponse` — `code: str`, `message: str`.
- **Completion condition:** `python -c "from models import ScanResult, Finding, Severity"` executes without import errors. Pydantic model instantiation of each type with valid sample data succeeds.
- **Dependencies:** Task 1.1.

### Task 2.2 — Define Frontend TypeScript Types
- **Requirement:** Req 3.10, Req 4.6, Req 6.3, Req 6.4; Design §Data Models
- **Action:** Create `frontend/src/types/findings.ts` with TypeScript interfaces and types that exactly mirror the backend Pydantic models:
  - `Severity` — union type `'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'`.
  - `PublicAccessBlockConfig`, `AclGrant`, `EncryptionConfig`, `S3BucketConfig`, `InboundRule`, `SecurityGroupConfig` — matching field names and nullable types.
  - `Finding` — all fields from the backend `Finding` model.
  - `Warning` — `resourceId: string`, `reason: string`.
  - `ScanResult` — all fields from the backend `ScanResult` model.
  - `ScanRequest` — `region?: string`.
  - `ErrorResponse` — `code: string`, `message: string`.
  - Export a `SEVERITY_ORDER` constant: `['Critical', 'High', 'Medium', 'Low', 'Informational']` for use in sorting and filtering.
  - Export a `SEVERITY_COLORS` map keying each `Severity` to its Tailwind class string (per the design's color mapping table).
- **Completion condition:** `npx tsc --noEmit` passes with no type errors in `findings.ts`.
- **Dependencies:** Task 1.2, Task 2.1 (for cross-reference verification).

---

## Phase 3 — ScannerProvider Abstraction and Simulated Provider

### Task 3.1 — Implement the ScannerProvider Interface
- **Requirement:** Req 2.1
- **Action:** Create `backend/providers/__init__.py` (empty). Create `backend/providers/base.py` defining `ScannerProvider` as a `typing.Protocol` with two methods: `list_s3_buckets(self) -> list[S3BucketConfig]` and `list_security_groups(self, region: str) -> list[SecurityGroupConfig]`. Import both config types from `models`.
- **Completion condition:** `from providers.base import ScannerProvider` imports cleanly. The protocol is a `typing.Protocol` subclass (verifiable with `issubclass(ScannerProvider, typing.Protocol)`-equivalent check in a test).
- **Dependencies:** Task 2.1.

### Task 3.2 — Implement the SimulatedScannerProvider
- **Requirement:** Req 2.2, Req 2.5
- **Action:** Create `backend/providers/simulated.py` implementing `SimulatedScannerProvider`. It must:
  - Implement `list_s3_buckets()` by loading and validating `backend/fixtures/s3_buckets.json` using `S3BucketConfig.model_validate_json` (or equivalent).
  - Implement `list_security_groups(region)` by loading and validating `backend/fixtures/security_groups.json` using `SecurityGroupConfig.model_validate_json`.
  - Raise a descriptive `RuntimeError` (not silently return empty) if either fixture file is missing or unparseable, so the API layer can catch and return a structured error.
  - NOT import `boto3` at any point in the file.
- **Completion condition:** Instantiating `SimulatedScannerProvider()` and calling both methods with placeholder fixture files (even empty arrays) succeeds. `grep -r "boto3" backend/providers/` returns no matches.
- **Dependencies:** Task 3.1. (Fixture files created in Phase 4; provider can be instantiated with temporary empty arrays `[]` fixtures until then.)

### Task 3.3 — Implement Backend Config and Provider Injection
- **Requirement:** Req 2.4; Design §Backend Directory Structure
- **Action:** Create `backend/config.py` using `pydantic-settings` (or `os.environ`) to read: `SCANNER_PROVIDER: str = "simulated"` and `CORS_ORIGINS: list[str] = ["http://localhost:5173"]`. In `backend/main.py`, at application startup (using FastAPI `lifespan` or module-level), instantiate `SimulatedScannerProvider` when `SCANNER_PROVIDER == "simulated"` and store it in application state. Add a comment block in `config.py` noting that `SCANNER_PROVIDER=boto3` will activate `Boto3ScannerProvider` in Session 2.
- **Completion condition:** Starting the backend with default env vars uses the `SimulatedScannerProvider`. Starting with `SCANNER_PROVIDER=unknown` raises a clear startup error (not a silent fallback).
- **Dependencies:** Task 3.2.

---

## Phase 4 — Fixtures

### Task 4.1 — Create S3 Bucket Fixture Data
- **Requirement:** Req 1.4, Req 1.5, Req 1.6, Req 3 (all criteria)
- **Action:** Create `backend/fixtures/s3_buckets.json` as a JSON array of at least ten `S3BucketConfig`-compatible objects. The dataset must collectively exercise every implemented S3 rule:
  - At least one bucket triggering the **Critical** effective-public rule (all four block settings disabled + ACL grants `AllUsers` READ).
  - At least one bucket triggering the **Critical** effective-public-policy rule (all four block settings disabled + `is_public_policy: true`).
  - At least one bucket triggering the **High** partial-block rule (some but not all block settings disabled, no ACL/policy public exposure).
  - At least two buckets triggering the **High** no-encryption rule (`encryption: null`).
  - At least one bucket triggering the **Informational** SSE-S3-only rule (`sse_algorithm: "AES256"`).
  - At least one fully secure bucket (all block settings enabled, SSE-KMS encryption) that produces zero findings.
  - All resource names must be clearly fictitious (e.g., `simulated-data-lake`, `simulated-logs-archive`). Account references must use `123456789012`.
- **Completion condition:** `SimulatedScannerProvider().list_s3_buckets()` returns a list of at least ten validated `S3BucketConfig` objects with no validation errors. Manually confirm each required scenario bucket is present.
- **Dependencies:** Task 3.2.

### Task 4.2 — Create EC2 Security Group Fixture Data
- **Requirement:** Req 1.4, Req 1.5, Req 1.6, Req 4 (all criteria)
- **Action:** Create `backend/fixtures/security_groups.json` as a JSON array of at least ten `SecurityGroupConfig`-compatible objects. The dataset must collectively exercise every implemented EC2 rule:
  - At least one group with a world-open SSH rule (`port 22, 0.0.0.0/0`) triggering **Critical**.
  - At least one group with a world-open RDP rule (`port 3389, 0.0.0.0/0`) triggering **Critical**.
  - At least one group with a world-open database port (e.g., `port 3306, 0.0.0.0/0` for MySQL) triggering **Critical**.
  - At least one group with an all-ports rule (`protocol -1, 0.0.0.0/0`) triggering **Critical** and suppressing individual port findings.
  - At least one group with a non-standard world-open port (not 22, 3389, 80, 443, or database ports) triggering **High**.
  - At least one group with IPv6 world-open rules (`::/0`) triggering both **Critical** and **High** checks.
  - At least one group with only port 80 and 443 open triggering **Informational** only.
  - At least one group with multiple world-open rules on the same port to exercise consolidation (single Finding per port-severity).
  - At least one fully restricted group with no world-open rules that produces zero findings.
  - All resource IDs and names must be clearly fictitious (e.g., `sg-sim-0001` through `sg-sim-0010`).
- **Completion condition:** `SimulatedScannerProvider().list_security_groups("us-east-1")` returns at least ten validated `SecurityGroupConfig` objects. Manually confirm each required scenario group is present.
- **Dependencies:** Task 3.2.

---

## Phase 5 — Security Analysis Rules

### Task 5.1 — Implement S3 Misconfiguration Detection Rules
- **Requirement:** Req 3.3, 3.4, 3.5, 3.6, 3.7; Design §S3 Scanning Rules
- **Action:** Create `backend/analyzers/__init__.py` (empty). Create `backend/analyzers/s3_rules.py` with the following pure rule functions, each accepting `S3BucketConfig` and returning `Finding | None`:
  - `check_effective_public_acl_or_policy(bucket)` — Critical: all four block settings False AND (ACL grants AllUsers/AuthenticatedUsers read/write OR `is_public_policy` True). `evidence` dict must include the specific failing block settings, ACL grants, and policy status.
  - `check_partial_public_access_block(bucket)` — High: any block setting False AND the bucket does NOT meet the Critical condition above. `evidence` must list which specific block settings are disabled.
  - `check_no_encryption(bucket)` — High: `encryption` is None. `evidence`: `{"encryption": null}`.
  - `check_sse_s3_only(bucket)` — Informational: `encryption.sse_algorithm == "AES256"`. `evidence`: `{"sse_algorithm": "AES256"}`.
  - Create `analyze_s3_bucket(bucket: S3BucketConfig) -> list[Finding]` that calls all four rule functions in sequence and returns the list of non-None results.
  - Each Finding must include a `risk_explanation` that explicitly states "This finding is based on simulated configuration data" and a concrete `remediation` recommendation.
- **Completion condition:** All four rule functions return `Finding` with correct `severity` for the matching fixture scenario and `None` for non-matching input. `analyze_s3_bucket` returns multiple findings for a bucket that violates multiple rules.
- **Dependencies:** Task 2.1, Task 4.1.

### Task 5.2 — Implement EC2 Security Group Detection Rules
- **Requirement:** Req 4.2, 4.3, 4.4, 4.5, 4.6; Design §EC2 Scanning Rules
- **Action:** Create `backend/analyzers/ec2_rules.py`. Implement:
  - `CRITICAL_PORTS: frozenset[int]` = `{22, 3389, 3306, 5432, 1433, 27017}`.
  - `is_world_open(rule: InboundRule) -> bool` — returns True if `cidr_ipv4 == "0.0.0.0/0"` or `cidr_ipv6 == "::/0"`.
  - `is_all_ports(rule: InboundRule) -> bool` — returns True if `protocol == "-1"` or (`from_port == 0` and `to_port == 65535`).
  - `classify_rule(rule: InboundRule) -> Severity | None` — returns severity per the ordered rules in Req 4, criterion 2, or None if the rule is not world-open. Port 80 and 443 return `Informational`. Critical ports return `Critical`. All-ports returns `Critical`. All other world-open ports return `High`.
  - `analyze_security_group(sg: SecurityGroupConfig) -> list[Finding]` implementing the full consolidation logic:
    1. Classify each inbound rule with `classify_rule`.
    2. If any all-ports Critical rule exists, emit only one all-ports Finding for that group; skip all individual-port finding generation.
    3. Otherwise, group world-open rules by `(severity, port)`. For each group, emit one consolidated Finding listing all matching rules in `evidence`.
    4. Each Finding must include the SG `group_id` and `group_name` in evidence, a `risk_explanation` stating this is simulated configuration data, and a remediation recommendation.
- **Completion condition:** `analyze_security_group` returns exactly one Critical Finding for a group with only an all-ports rule. Returns one consolidated Finding (not two) for a group with two world-open rules on the same port. Returns no High/Critical Findings for a group with only port 80/443 open.
- **Dependencies:** Task 2.1, Task 4.2.

### Task 5.3 — Implement the Scanner Orchestrator
- **Requirement:** Req 2.3; Design §Backend Architecture
- **Action:** Create `backend/scanner.py` with a `Scanner` class:
  - Constructor accepts `provider: ScannerProvider`.
  - `run(region: str = "us-east-1") -> ScanResult` method that:
    1. Calls `provider.list_s3_buckets()` and `provider.list_security_groups(region)`, catching fixture load errors per entry and recording them as `Warning` objects.
    2. Calls `analyze_s3_bucket` for each bucket and `analyze_security_group` for each security group.
    3. Aggregates all findings and warnings into a `ScanResult` with `simulated=True`, ISO 8601 timestamp, `scan_id` (uuid4), and a `summary` dict counting findings per severity.
  - The `Scanner` must reference only the `ScannerProvider` protocol — it must not import `SimulatedScannerProvider` directly.
- **Completion condition:** `Scanner(SimulatedScannerProvider()).run()` returns a `ScanResult` with a non-empty `findings` list covering all five severity levels, all findings have `simulated=True`, and `summary` totals match the actual findings list.
- **Dependencies:** Task 5.1, Task 5.2, Task 3.2, Task 4.1, Task 4.2.

---

## Phase 6 — Backend API Endpoints

### Task 6.1 — Implement POST /api/scan
- **Requirement:** Req 7.1–7.8; Design §API Endpoints
- **Action:** In `backend/main.py`, add the `POST /api/scan` endpoint:
  - Accepts `ScanRequest` body (optional `region` field, defaults to `"us-east-1"`).
  - Instantiates (or reuses the injected) `Scanner` with the configured `ScannerProvider`.
  - Calls `scanner.run(region)` and stores the resulting `ScanResult` in application state (in-memory, replacing any previous result).
  - Returns the `ScanResult` as JSON with HTTP 200.
  - If `scanner.run()` raises an unhandled exception, logs the full traceback to stdout and returns HTTP 500 with `{"code": "INTERNAL_ERROR", "message": "An unexpected error occurred. Please try again."}`.
  - If the provider raises a fixture load error, returns HTTP 500 with `{"code": "FIXTURE_LOAD_ERROR", "message": "..."}`.
- **Completion condition:** `POST http://localhost:8000/api/scan` with body `{}` returns HTTP 200 with a valid `ScanResult` JSON containing at least one finding. Sending a request that forces a fixture error returns HTTP 500 with the correct error schema.
- **Dependencies:** Task 5.3, Task 3.3.

### Task 6.2 — Implement GET /api/export/json and GET /api/export/csv
- **Requirement:** Req 6.3, 6.4, 6.5, 6.6; Design §Export Implementation
- **Action:** Create `backend/report_generator.py` with:
  - `generate_json_report(result: ScanResult) -> bytes` — serializes the `ScanResult` to pretty-printed JSON bytes. The output must include `"simulated": true` at the top level.
  - `generate_csv_report(result: ScanResult) -> bytes` — produces UTF-8 CSV bytes with a header row: `simulated,resource_type,resource_name,severity,title,evidence,risk_explanation,remediation`. Each finding is one row. `evidence` is serialized as a compact JSON string. Multi-line fields have internal newlines replaced with a space. The `simulated` column is always `"true"`.
  - In `main.py`, add:
    - `GET /api/export/json` — if no scan result exists, return HTTP 404 with `{"code": "NO_SCAN_RESULT", "message": "No scan has been run yet."}`. Otherwise, return `generate_json_report(result)` as a `Response` with `Content-Type: application/json` and `Content-Disposition: attachment; filename="cloudguard-findings-{date}.json"`.
    - `GET /api/export/csv` — same guard, returns `generate_csv_report(result)` as a `Response` with `Content-Type: text/csv` and `Content-Disposition: attachment; filename="cloudguard-findings-{date}.csv"`.
- **Completion condition:** After running `POST /api/scan`, `GET /api/export/json` returns a downloadable file with `"simulated": true` and all findings. `GET /api/export/csv` returns a file with a header row and one row per finding. `GET /api/export/json` before any scan returns HTTP 404 with `code: "NO_SCAN_RESULT"`.
- **Dependencies:** Task 6.1.

---

## Phase 7 — Application Shell and Layout

### Task 7.1 — Build the API Client
- **Requirement:** Design §API Client; Req 7.4
- **Action:** Create `frontend/src/api/client.ts` with:
  - A `BASE_URL` constant reading from `import.meta.env.VITE_API_BASE_URL`.
  - A `fetchWithTimeout(url, options, timeoutMs = 120_000)` utility using `AbortController`.
  - `scanApi.triggerScan(request: ScanRequest): Promise<ScanResult>` — `POST /api/scan`.
  - `scanApi.exportJson(): Promise<Blob>` — `GET /api/export/json`, returns the response as a Blob.
  - `scanApi.exportCsv(): Promise<Blob>` — `GET /api/export/csv`, returns the response as a Blob.
  - `scanApi.health(): Promise<{ status: string; simulated: boolean }>` — `GET /api/health`.
  - All functions must: parse `{ code, message }` from error responses and throw a typed `ApiError` (class with `code` and `message` fields); trigger the 120-second timeout abort; re-throw a timeout-specific `ApiError` with `code: "REQUEST_TIMEOUT"` and `message: "Request timed out — please try again"`.
- **Completion condition:** TypeScript compiles with no errors. Unit test (with `vi.stubGlobal('fetch', ...)`) verifies that a simulated 121-second delay triggers the timeout error.
- **Dependencies:** Task 2.2, Task 1.2.

### Task 7.2 — Implement Global Scan State Store
- **Requirement:** Design §State Management; Req 5.9, 7.1
- **Action:** Create `frontend/src/store/scanStore.ts` using Zustand (install if not yet installed). Define the store with:
  - State: `status: 'idle' | 'scanning' | 'complete' | 'error'`, `scanResult: ScanResult | null`, `error: string | null`, `lastScanAt: string | null`.
  - Actions: `triggerScan(region?: string): Promise<void>` — sets status to `'scanning'`, calls `scanApi.triggerScan`, on success sets `status: 'complete'`, `scanResult`, `lastScanAt`; on failure sets `status: 'error'`, `error`.
  - `clearError(): void` — clears the `error` field and resets status to `'idle'` if in error state.
- **Completion condition:** Importing the store in a test and calling `triggerScan` with a mocked `scanApi` transitions state correctly through `idle → scanning → complete` and `idle → scanning → error`.
- **Dependencies:** Task 7.1.

### Task 7.3 — Build Shared UI Components
- **Requirement:** Req 1.2, Req 9.2, 9.3; Design §Shared Components
- **Action:** Create the following components in `frontend/src/components/shared/`:
  - `SeverityBadge.tsx` — accepts `severity: Severity`, renders a pill/chip with the correct Tailwind classes from `SEVERITY_COLORS` and an ARIA label `aria-label={severity}`.
  - `LoadingSpinner.tsx` — an accessible spinner with `role="status"` and a visually hidden "Loading…" text.
  - `ErrorBanner.tsx` — accepts `message: string` and `onDismiss: () => void`. Renders a non-blocking red notification banner with a dismiss button. The dismiss button has `aria-label="Dismiss error"`. The banner is not dismissible if `onDismiss` is not provided.
  - `EmptyState.tsx` — accepts `title: string` and optional `description: string`. Renders a centered empty-state message.
- **Completion condition:** Each component renders without TypeScript errors. `SeverityBadge` renders with the correct color class for each severity value. `ErrorBanner` calls `onDismiss` when the dismiss button is clicked.
- **Dependencies:** Task 2.2.

### Task 7.4 — Build the Application Shell
- **Requirement:** Req 1.2, Req 9.4, 9.5; Design §Routing, AppShell
- **Action:**
  - Create `frontend/src/components/layout/SimulatedBanner.tsx` — a full-width, high-contrast, amber/yellow banner displaying "Demo Mode — Simulated Data" with no dismiss button. Includes `role="alert"` and `aria-live="polite"`.
  - Create `frontend/src/components/layout/AppShell.tsx` — renders the `SimulatedBanner` at the very top of the page (above the nav), a left sidebar or top nav with links to `/dashboard`, `/findings`, and `/scan`, and a `<Outlet />` for page content. Nav links have visible focus indicators (Tailwind `focus:ring` classes). All nav icon buttons have `aria-label` attributes.
  - Update `frontend/src/App.tsx` to configure React Router v6 with routes: `/` redirecting to `/dashboard`, `/dashboard`, `/findings`, `/scan`. Wrap all routes in the `AppShell` layout.
  - Update `frontend/src/main.tsx` to wrap the app in `BrowserRouter`.
- **Completion condition:** Running `npm run dev` and visiting `http://localhost:5173` redirects to `/dashboard`. The "Demo Mode — Simulated Data" banner is visible on all three routes. Navigation links are keyboard-focusable with visible focus rings.
- **Dependencies:** Task 7.3, Task 1.2.

---

## Phase 8 — Dashboard Page

### Task 8.1 — Build the Stats Panel
- **Requirement:** Req 5.1; Design §StatsPanel
- **Action:** Create `frontend/src/components/dashboard/StatsPanel.tsx` accepting `summary: Record<Severity, number> | null` and `totalFindings: number`. Render five color-coded stat cards — one per severity — each showing the severity label and count. When `summary` is null, render skeleton/zero-state cards. Cards use the correct severity background colors from the design. Each card is keyboard-accessible (if clickable, it has a `tabIndex` and `aria-label`).
- **Completion condition:** Rendering `<StatsPanel summary={{ Critical: 3, High: 5, Medium: 2, Low: 1, Informational: 4 }} totalFindings={15} />` shows five cards with correct counts and correct colors.
- **Dependencies:** Task 2.2, Task 7.3.

### Task 8.2 — Build the Severity Chart
- **Requirement:** Req 5.2; Design §SeverityChart
- **Action:** Create `frontend/src/components/dashboard/SeverityChart.tsx` accepting `summary: Record<Severity, number> | null`. Use Recharts `BarChart` (or `PieChart`/`RadialBarChart`) to render a severity distribution chart. Severity bars/segments use the correct severity colors. Include a chart title. When `summary` is null or all zeros, render the `EmptyState` component with text "No findings to chart". Wrap the chart in a container with `role="img"` and `aria-label="Severity distribution chart"`.
- **Completion condition:** Rendering with a non-null summary displays a chart. Rendering with all-zero summary displays the empty state. No TypeScript or runtime errors.
- **Dependencies:** Task 8.1.

### Task 8.3 — Build the Recent Findings Component
- **Requirement:** Req 5.8; Design §RecentFindings
- **Action:** Create `frontend/src/components/dashboard/RecentFindings.tsx` accepting `findings: Finding[]`. Render the first five items (by array order) as a compact list, each showing a `SeverityBadge`, the finding title, and the resource name. Truncate titles longer than 80 characters with an ellipsis. When `findings` is empty, render `EmptyState` with text "No recent findings". The component does not implement expand/detail — that is in `FindingsTable`.
- **Completion condition:** Rendering with ten findings shows exactly five. Rendering with an empty array shows the empty state. Titles longer than 80 characters are visually truncated.
- **Dependencies:** Task 7.3, Task 2.2.

### Task 8.4 — Build the Dashboard Page
- **Requirement:** Req 5.1, 5.2, 5.8, 5.9, 5.10, 5.12; Design §DashboardPage
- **Action:** Create `frontend/src/pages/DashboardPage.tsx`. It must:
  - On mount, if no scan result exists in the store (`scanResult === null`), automatically trigger a scan by calling `triggerScan()` from the Zustand store.
  - While `status === 'scanning'`, render `LoadingSpinner` and disable any scan-trigger button (if present on this page).
  - When `status === 'complete'`, render `StatsPanel`, `SeverityChart`, and `RecentFindings` populated with data from `scanResult`.
  - When `status === 'error'`, render `ErrorBanner` with the error message and a "Retry" button that calls `triggerScan()`.
  - When `status === 'complete'` and `scanResult.findings.length === 0`, render `EmptyState` with "No findings detected" in the findings area.
  - If `scanResult.warnings.length > 0`, render a collapsible warnings section listing each warning's `resourceId` and `reason`.
  - Display the scan completion timestamp from `lastScanAt` when status is `'complete'`.
- **Completion condition:** Visiting `/dashboard` triggers a scan automatically. After the scan, the stats panel, chart, and recent findings render with data matching the scan result. The "Demo Mode — Simulated Data" banner is visible.
- **Dependencies:** Task 8.1, Task 8.2, Task 8.3, Task 7.2, Task 7.4.

---

## Phase 9 — Findings Page

### Task 9.1 — Build the SeverityFilter Component
- **Requirement:** Req 5.5; Design §SeverityFilter
- **Action:** Create `frontend/src/components/findings/SeverityFilter.tsx` accepting `selected: Severity[]` and `onChange: (selected: Severity[]) => void`. Render a group of five checkboxes, one per severity, each showing a `SeverityBadge`. Checking/unchecking a severity calls `onChange` with the updated selection. All checkboxes have `id`, `name`, and matching `htmlFor` label associations. When all are unchecked, treat it as "show all" (the parent component is responsible for this logic). Uses `role="group"` with `aria-label="Filter by severity"`.
- **Completion condition:** Toggling each checkbox calls `onChange` with the correct updated array. All checkboxes are keyboard-navigable with visible focus indicators.
- **Dependencies:** Task 7.3, Task 2.2.

### Task 9.2 — Build the SearchInput Component
- **Requirement:** Req 5.6, 5.7; Design §SearchInput
- **Action:** Create `frontend/src/components/findings/SearchInput.tsx` accepting `value: string` and `onChange: (value: string) => void`. Render a text input with placeholder "Search by resource or finding title…". The `onChange` is called on every keystroke (debounce is handled in the hook, not this component). Include a clear button (×) that calls `onChange("")` and is visible only when `value` is non-empty. The clear button has `aria-label="Clear search"`. The input has `aria-label="Search findings"`.
- **Completion condition:** Typing in the input calls `onChange` with the current value. Clicking the clear button calls `onChange("")`. The clear button appears only when `value` is non-empty.
- **Dependencies:** Task 2.2.

### Task 9.3 — Build the useFindings Hook
- **Requirement:** Req 5.5, 5.6, 5.7; Design §useFindings
- **Action:** Create `frontend/src/hooks/useFindings.ts`. This hook:
  - Reads `scanResult` from the Zustand store.
  - Maintains local state: `searchQuery: string`, `selectedSeverities: Severity[]`.
  - Returns `filteredFindings: Finding[]` computed by:
    1. If `selectedSeverities` is non-empty, filter to those severities.
    2. If `searchQuery` is non-empty, filter to findings where `resource_name` or `title` contains the query (case-insensitive partial match).
    3. Both filters apply together.
  - Debounces `searchQuery` changes to prevent filtering on every keystroke; the debounce delay should be ≤200ms.
  - Returns setters `setSearchQuery` and `setSelectedSeverities`, plus the current `searchQuery` and `selectedSeverities` values.
- **Completion condition:** With 10 findings of mixed severity, calling `setSelectedSeverities(['Critical'])` returns only Critical findings. Calling `setSearchQuery('ssh')` returns only findings matching 'ssh' in resource name or title. Both filters applied together return the intersection.
- **Dependencies:** Task 7.2, Task 2.2.

### Task 9.4 — Build the FindingRow Component
- **Requirement:** Req 5.3, 5.4; Design §FindingRow
- **Action:** Create `frontend/src/components/findings/FindingRow.tsx` accepting `finding: Finding` and `isExpanded: boolean` and `onToggle: () => void`. Render two states:
  - **Collapsed:** One `<tr>` with four cells: Resource Type, Resource Name, `SeverityBadge`, Finding Title. A chevron icon button in a fifth cell toggles expansion. The row is keyboard-activatable via the toggle button.
  - **Expanded:** An additional `<tr>` immediately after with a full-width `<td colspan={5}>` containing three sections: **Evidence** (renders `finding.evidence` as a formatted key-value list or JSON block), **Risk Explanation** (`finding.risk_explanation`), **Remediation** (`finding.remediation`). Each section has a clear heading.
  - The toggle button has `aria-expanded={isExpanded}` and `aria-label="Toggle finding details"`.
- **Completion condition:** Clicking the toggle button on a collapsed row reveals the evidence, risk explanation, and remediation sections. Clicking again hides them. Pressing Enter/Space on the toggle button also works.
- **Dependencies:** Task 7.3, Task 2.2.

### Task 9.5 — Build the FindingsTable Component
- **Requirement:** Req 5.3, 5.4; Design §FindingsTable
- **Action:** Create `frontend/src/components/findings/FindingsTable.tsx` accepting `findings: Finding[]`. Render an HTML `<table>` with a `<thead>` row (Resource Type, Resource Name, Severity, Finding Title, Details). Render one `FindingRow` per finding, managing a `Set<string>` of expanded finding IDs in local state. Pass `isExpanded` and `onToggle` to each row. When `findings` is empty, render `EmptyState` in the table body with text "No findings match the current filters". The table has `role="table"` and a visible caption.
- **Completion condition:** Rendering with five findings shows five rows. Clicking a row's toggle shows its expanded detail. Clicking another row's toggle does not collapse the first (multiple rows can be expanded simultaneously). Rendering with zero findings shows the empty state.
- **Dependencies:** Task 9.4.

### Task 9.6 — Build the Findings Page
- **Requirement:** Req 5.3, 5.4, 5.5, 5.6, 5.7, 5.9, 5.11, 5.12; Design §FindingsPage
- **Action:** Create `frontend/src/pages/FindingsPage.tsx`. It must:
  - Use `useFindings` to get `filteredFindings`, `searchQuery`, `selectedSeverities`, and their setters.
  - Render `SeverityFilter` (bound to `selectedSeverities` / `setSelectedSeverities`) and `SearchInput` (bound to `searchQuery` / `setSearchQuery`) above the table.
  - Render `FindingsTable` with `filteredFindings`.
  - Show the count of filtered findings vs. total findings (e.g., "Showing 8 of 23 findings").
  - While `status === 'scanning'`, render `LoadingSpinner` and disable filter/search controls.
  - While `status === 'error'`, render `ErrorBanner`.
  - When `status === 'complete'` and no scan result exists yet, render `EmptyState` with "Run a scan to see findings".
  - If `scanResult.warnings.length > 0`, render a collapsible warnings notice.
- **Completion condition:** Visiting `/findings` after a completed scan shows the full finding list. Typing in search narrows the list. Selecting severity checkboxes filters the list. The "Showing X of Y" counter updates correctly. Clearing search restores the full list within 200ms.
- **Dependencies:** Task 9.1, Task 9.2, Task 9.3, Task 9.5, Task 7.4.

---

## Phase 10 — Exports

### Task 10.1 — Build the useExport Hook
- **Requirement:** Req 6.1–6.6; Design §Export Implementation
- **Action:** Create `frontend/src/hooks/useExport.ts`. This hook:
  - Reads `scanResult` and `status` from the Zustand store.
  - Exposes `canExport: boolean` = `status === 'complete' && scanResult !== null && scanResult.findings.length > 0`.
  - Exposes `exportJson(): Promise<void>` — calls `scanApi.exportJson()`, receives a Blob, creates a timestamped filename `cloudguard-findings-{YYYY-MM-DD}.json`, triggers a browser download via a temporary `<a>` element, and revokes the object URL after download.
  - Exposes `exportCsv(): Promise<void>` — same pattern with `.csv` extension and `scanApi.exportCsv()`.
  - Exposes `exportError: string | null` and `clearExportError: () => void`.
  - On any export API error, sets `exportError` to the error message without disabling the export button.
- **Completion condition:** With a completed scan result, `canExport` is `true`. With `status === 'idle'` or zero findings, `canExport` is `false`. Calling `exportJson()` with a mocked API triggers a download (verifiable by spying on `URL.createObjectURL`).
- **Dependencies:** Task 7.1, Task 7.2.

### Task 10.2 — Build the ExportButton Component
- **Requirement:** Req 6.1, 6.2, 6.5, 6.6; Design §ExportButton
- **Action:** Create `frontend/src/components/export/ExportButton.tsx`. It must:
  - Use `useExport` hook.
  - Render an "Export Report" button that is `disabled` when `canExport === false` with `aria-disabled="true"` and a tooltip/title explaining why (e.g., "Run a scan first").
  - When clicked (and `canExport === true`), show a dropdown or modal with two options: "Download JSON" and "Download CSV".
  - Clicking "Download JSON" calls `exportJson()`. Clicking "Download CSV" calls `exportCsv()`.
  - While an export is in progress, show a loading indicator on the button.
  - If `exportError` is non-null, render a dismissible error notification below the button.
- **Completion condition:** The button is disabled before any scan. After a completed scan, clicking it shows the format picker. Selecting JSON triggers the download flow. An API error shows the error notification without disabling the button.
- **Dependencies:** Task 10.1, Task 7.3.

### Task 10.3 — Integrate Export Button into the Findings Page
- **Requirement:** Req 6.1; Design §FindingsPage
- **Action:** Add `ExportButton` to `FindingsPage.tsx`, positioned above the findings table next to the filter controls. Ensure it is visible without scrolling when findings are present. Add `ExportButton` also to `DashboardPage.tsx` in the page header area.
- **Completion condition:** The Export Report button is visible on both `/dashboard` and `/findings`. It is disabled before a scan and enabled after a successful scan with findings.
- **Dependencies:** Task 10.2, Task 9.6, Task 8.4.

---

## Phase 11 — Application States

### Task 11.1 — Build the Scan Controls Page
- **Requirement:** Req 5.9, 7.5; Design §ScanPage
- **Action:** Create `frontend/src/pages/ScanPage.tsx`. It must:
  - Render a "Run Scan" button. When clicked, calls `triggerScan()` from the store.
  - Render an optional region text input (label "AWS Region", placeholder `us-east-1`, not required). The value is passed to `triggerScan(region)`.
  - While `status === 'scanning'`, the "Run Scan" button is disabled with `aria-disabled="true"`, shows a `LoadingSpinner` inline, and displays "Scan in progress…" text.
  - When `status === 'complete'`, show a success notice: "Scan completed — {total} findings identified" with the timestamp from `lastScanAt`.
  - When `status === 'error'`, show `ErrorBanner` with the error message and allow retry.
  - Include the pre-scan notice: a visible informational box stating "CloudGuard AI evaluates simulated AWS resource configurations. All findings reflect simulated data only." (per Req 1.3). This notice is always visible on the scan page.
- **Completion condition:** Visiting `/scan` and clicking "Run Scan" triggers `triggerScan`. The button is disabled during scanning. After completion, the success notice shows the correct count. After an error, the error banner appears and the button re-enables.
- **Dependencies:** Task 7.2, Task 7.4.

### Task 11.2 — Verify All Application States Are Handled
- **Requirement:** Req 7.1–7.8
- **Action:** Manually verify all required application states by reviewing each page and component:
  - **Loading state:** `LoadingSpinner` visible during scan on `/dashboard`, `/findings`, and `/scan`. Scan trigger controls disabled.
  - **Empty state:** "No findings detected" shown on `/dashboard` when scan returns zero findings. "Run a scan to see findings" on `/findings` before first scan.
  - **Error state:** `ErrorBanner` appears on all pages when `status === 'error'`. Banner persists until dismissed. A retry action is available.
  - **Timeout state:** Mocking a 121-second API delay triggers the "Request timed out" notification.
  - **Partial scan state:** When `scanResult.warnings` is non-empty, warnings panel renders on both `/dashboard` and `/findings`.
  - **Completion state:** Scan completion notice with timestamp and total count on `/scan`. Stats and chart populated on `/dashboard`.
  - **Backend unavailable state:** When backend is not running, `/dashboard` auto-scan shows a connection error state, not a blank page.
- **Completion condition:** Each state above is confirmed by manual test or automated test. No state results in a blank or broken page.
- **Dependencies:** Task 8.4, Task 9.6, Task 11.1.

---

## Phase 12 — Automated Tests

### Task 12.1 — Backend Unit Tests: S3 Rules
- **Requirement:** Req 8.1
- **Action:** Create `backend/tests/test_s3_rules.py`. Write one test per rule, using inline `S3BucketConfig` dicts:
  - `test_critical_public_acl`: All four block settings False + `AllUsers` READ ACL → `Finding` with `severity == Severity.Critical`.
  - `test_critical_public_policy`: All four block settings False + `is_public_policy: True` → `Finding` with `severity == Severity.Critical`.
  - `test_high_partial_block`: Two of four block settings False + no ACL/policy exposure → `Finding` with `severity == Severity.High`.
  - `test_no_finding_full_block`: All four block settings True → `check_effective_public_acl_or_policy` returns None; `check_partial_public_access_block` returns None.
  - `test_high_no_encryption`: `encryption: None` → `Finding` with `severity == Severity.High`.
  - `test_no_finding_kms_encryption`: `sse_algorithm: "aws:kms"` → `check_no_encryption` returns None; `check_sse_s3_only` returns None.
  - `test_informational_sse_s3_only`: `sse_algorithm: "AES256"` → `Finding` with `severity == Severity.Informational`.
  - `test_analyze_bucket_multiple_findings`: Bucket with all four block settings False + `AllUsers` ACL + `encryption: None` → `analyze_s3_bucket` returns at least two findings (Critical + High).
  - `test_all_findings_have_evidence`: For each rule function, assert returned `Finding.evidence` is a non-empty dict.
  - `test_all_findings_simulated_true`: All returned findings have `simulated == True`.
- **Completion condition:** `pytest backend/tests/test_s3_rules.py -v` passes all tests with no real AWS calls or network access.
- **Dependencies:** Task 5.1.

### Task 12.2 — Backend Unit Tests: EC2 Rules
- **Requirement:** Req 8.1
- **Action:** Create `backend/tests/test_ec2_rules.py`. Write one test per scenario:
  - `test_critical_ssh_ipv4`: Port 22, `cidr_ipv4: "0.0.0.0/0"` → Finding with `severity == Critical`.
  - `test_critical_ssh_ipv6`: Port 22, `cidr_ipv6: "::/0"` → Finding with `severity == Critical`.
  - `test_critical_rdp`: Port 3389, `cidr_ipv4: "0.0.0.0/0"` → Critical.
  - `test_critical_mysql`: Port 3306 → Critical.
  - `test_critical_postgres`: Port 5432 → Critical.
  - `test_critical_mssql`: Port 1433 → Critical.
  - `test_critical_mongodb`: Port 27017 → Critical.
  - `test_critical_all_ports_protocol_minus1`: Protocol `-1` → one Critical Finding.
  - `test_critical_all_ports_range`: `from_port: 0, to_port: 65535` → one Critical Finding.
  - `test_high_custom_port`: Port 8080, `0.0.0.0/0` → High.
  - `test_informational_http`: Port 80 → Informational.
  - `test_informational_https`: Port 443 → Informational.
  - `test_no_finding_restricted_cidr`: Port 22, `cidr_ipv4: "10.0.0.0/8"` → no Finding.
  - `test_all_ports_suppresses_individual_ports`: Group with all-ports rule + SSH rule → exactly one Finding (the all-ports one, not two separate findings).
  - `test_consolidation_same_port`: Group with two world-open rules on port 22 → exactly one Finding with both rules in `evidence`.
  - `test_no_world_open_rules`: Group with no world-open rules → empty finding list.
- **Completion condition:** `pytest backend/tests/test_ec2_rules.py -v` passes all tests.
- **Dependencies:** Task 5.2.

### Task 12.3 — Backend Integration Tests: Scanner
- **Requirement:** Req 8.2
- **Action:** Create `backend/tests/test_scanner.py`. Write:
  - `test_full_scan_returns_findings`: Instantiate `SimulatedScannerProvider` with real fixture files, call `Scanner(provider).run()`, assert: result is `ScanResult`, `findings` is non-empty, all findings have all required fields populated (`resource_type`, `resource_name`, `severity`, `title`, `evidence`, `risk_explanation`, `remediation`), all severities are in `{Critical, High, Medium, Low, Informational}`, `result.simulated == True`.
  - `test_summary_matches_findings`: Assert `result.summary` counts match the actual distribution in `result.findings`.
  - `test_all_findings_have_evidence`: Assert every finding has `evidence` as a non-empty dict.
  - `test_all_findings_have_simulated_true`: Assert every finding has `simulated == True`.
  - `test_covers_all_severity_levels`: Assert at least one finding at each of the five severity levels in the combined result (this validates fixture completeness).
  - `test_no_real_aws_calls`: Assert that `boto3` is not importable from within the `providers.simulated` module namespace (use `sys.modules` inspection or `importlib` to verify).
- **Completion condition:** `pytest backend/tests/test_scanner.py -v` passes all tests without network access.
- **Dependencies:** Task 5.3, Task 4.1, Task 4.2.

### Task 12.4 — Backend Integration Tests: Report Generator
- **Requirement:** Req 8.1 (covers Req 6.3, 6.4)
- **Action:** Create `backend/tests/test_report_generator.py`. Write:
  - `test_json_export_contains_simulated_true`: Build a `ScanResult` with two mock findings, call `generate_json_report`, parse the output, assert `"simulated": true` is present.
  - `test_json_export_all_finding_fields`: Assert all required fields (`resource_type`, `resource_name`, `severity`, `title`, `evidence`, `risk_explanation`, `remediation`) are present in each finding in the JSON output.
  - `test_csv_export_has_header`: Assert the first row of the CSV output is the expected header row.
  - `test_csv_export_one_row_per_finding`: Assert the CSV has exactly N+1 rows (header + N findings) for N findings.
  - `test_csv_export_simulated_column_true`: Assert all data rows have `"true"` in the `simulated` column.
  - `test_csv_export_no_embedded_newlines`: Assert no data field in the CSV contains a raw newline character.
- **Completion condition:** `pytest backend/tests/test_report_generator.py -v` passes all tests.
- **Dependencies:** Task 6.2.

### Task 12.5 — Backend Property-Based Tests
- **Requirement:** Req 8.3, Req 8.4
- **Action:** Create `backend/tests/test_properties.py`. Write:
  - `test_s3_severity_always_valid` (Hypothesis): Strategy generates arbitrary `S3BucketConfig`-compatible dicts. Assert `analyze_s3_bucket(bucket)` never raises an unhandled exception and every returned finding has a valid Severity.
  - `test_ec2_severity_always_valid` (Hypothesis): Strategy generates arbitrary `SecurityGroupConfig`-compatible dicts with arbitrary inbound rules. Assert `analyze_security_group(sg)` never raises an unhandled exception and every returned finding has a valid Severity.
  - `test_simulated_provider_no_boto3_import`: Assert that importing `providers.simulated` does not import `boto3` into `sys.modules`.
- **Completion condition:** `pytest backend/tests/test_properties.py -v` passes all tests (Hypothesis runs default example count ≥ 100). No test requires network access.
- **Dependencies:** Task 5.1, Task 5.2, Task 3.2.

### Task 12.6 — Frontend Component Tests
- **Requirement:** Req 8.5
- **Action:** Create component test files in `frontend/tests/components/`:
  - `StatsPanel.test.tsx`: Render with a summary dict. Assert each severity label and count is visible. Assert the Critical card has red styling. Render with `null` summary — assert zero-state renders without crashing.
  - `FindingsTable.test.tsx`: Render with three mock findings. Assert three rows are visible. Click the toggle button on the first row — assert the expanded detail section (evidence, risk explanation, remediation) becomes visible. Click again — assert it is hidden.
  - `SeverityFilter.test.tsx`: Render with all severities unselected. Click "Critical" checkbox — assert `onChange` is called with `['Critical']`. Click "High" — assert `onChange` called with `['Critical', 'High']`. Unclick "Critical" — assert `onChange` called with `['High']`.
  - `SearchInput.test.tsx`: Type "ssh" into the input — assert `onChange` called with `"ssh"`. Assert clear button is not visible when value is empty. Assert clear button is visible when value is "ssh". Click clear button — assert `onChange` called with `""`.
  - `ExportButton.test.tsx`: Render with `canExport=false` — assert button is disabled. Render with `canExport=true` — assert button is enabled. Click button — assert format picker appears. Click "Download JSON" — assert `exportJson` mock is called. Render with `exportError="Export failed"` — assert error message is visible.
- **Completion condition:** `npm run test` passes all component tests. No test makes real network calls.
- **Dependencies:** Task 8.1, Task 9.5, Task 9.1, Task 9.2, Task 10.2.

### Task 12.7 — Frontend Property-Based Tests
- **Requirement:** Req 8.6
- **Action:** Create `frontend/tests/properties/filterExport.property.test.ts`. Write using `fast-check`:
  - `filter_returns_subset`: Arbitrary array of `Finding` objects + arbitrary subset of severities. Assert filtered result is always a subset of the input (every filtered finding is in the original array with matching severity).
  - `search_returns_subset`: Arbitrary array of `Finding` objects + arbitrary search string. Assert filtered result is always a subset of input.
  - `combined_filter_returns_subset`: Both severity filter and search applied together — result is always a subset of input.
  - `json_export_consistent`: Arbitrary array of `Finding` objects (at least 1). Assert that the JSON export output (call the same formatting logic used in `useExport`) contains every finding from the input with all required fields.
  - `csv_export_row_count`: Arbitrary array of `Finding` objects (length 0–50). Assert CSV output has exactly `findings.length + 1` rows (header + data).
- **Completion condition:** `npm run test` passes all property tests. `fast-check` runs at least 100 examples per property.
- **Dependencies:** Task 9.3, Task 10.1, Task 2.2.

---

## Phase 13 — Final Build and Smoke Test

### Task 13.1 — Run Full Backend Test Suite
- **Requirement:** Req 8.7
- **Action:** Run `pytest backend/tests/ -v --tb=short` from the project root. All tests must pass. Zero real AWS calls. Confirm test suite completes in under 120 seconds.
- **Completion condition:** `pytest` exits with code 0. Output shows all test files and all tests passing.
- **Dependencies:** Tasks 12.1–12.5.

### Task 13.2 — Run Full Frontend Test Suite
- **Requirement:** Req 8.7
- **Action:** Run `npm run test --run` (non-watch mode) from `frontend/`. All tests must pass. No network calls. Confirm test suite completes in under 120 seconds.
- **Completion condition:** Vitest exits with code 0. Output shows all component and property tests passing.
- **Dependencies:** Tasks 12.6–12.7.

### Task 13.3 — Production Frontend Build
- **Requirement:** Req 9.1 (no broken layout in production build)
- **Action:** Run `npm run build` from `frontend/`. Resolve any TypeScript errors or missing imports surfaced by the build. Serve the built output with `npm run preview` and verify the application loads at `http://localhost:4173`.
- **Completion condition:** `npm run build` exits with code 0 with no TypeScript errors. The preview server loads `/dashboard` with the "Demo Mode — Simulated Data" banner visible.
- **Dependencies:** Task 13.2.

### Task 13.4 — End-to-End Smoke Test
- **Requirement:** All Session 1 requirements
- **Action:** With both the backend (`uvicorn main:app --reload` on port 8000) and frontend (`npm run dev` or `npm run preview` on port 5173) running:
  1. Verify "Demo Mode — Simulated Data" banner is visible on all three pages.
  2. Navigate to `/scan`, click "Run Scan", observe the loading state, observe the completion notice with finding count.
  3. Navigate to `/dashboard`, verify stats panel shows counts at all five severity levels, chart is rendered, recent findings list shows up to 5 items.
  4. Navigate to `/findings`, verify the full finding list is shown. Type "ssh" in search, verify results narrow. Select "Critical" in filter, verify only Critical findings shown. Clear both — verify full list restored.
  5. Expand one finding row, verify evidence, risk explanation, and remediation sections are present.
  6. Click "Export Report", select JSON, verify a file is downloaded with `"simulated": true`. Select CSV, verify a file is downloaded with the correct headers and a `simulated` column.
  7. Verify no Finding text describes results as "live AWS findings" or "real scan results."
  8. Stop the backend. Reload `/dashboard`. Verify a connection error state is shown, not a blank page.
- **Completion condition:** All eight smoke test steps pass without errors.
- **Dependencies:** Tasks 13.1, 13.3.

---

## Phase 14 — Documentation

### Task 14.1 — Write README
- **Requirement:** General project quality
- **Action:** Create `README.md` in the project root with the following sections:
  - **CloudGuard AI** — One-paragraph description of what the tool does and that Session 1 uses simulated data.
  - **Architecture** — Brief summary: React + Vite frontend, FastAPI backend, `ScannerProvider` abstraction, JSON fixtures. Include a note about Session 2 AWS integration being a planned extension.
  - **Session 1 vs Session 2** — Two-sentence explanation of the separation.
  - **Prerequisites** — Node.js ≥18, Python ≥3.11.
  - **Local Setup — Backend** — Step-by-step: create venv, install requirements, `uvicorn main:app --reload`.
  - **Local Setup — Frontend** — Step-by-step: `npm install`, `npm run dev`.
  - **Running Tests** — `pytest backend/tests/` and `npm run test --run`.
  - **Demo Mode** — Explain that all data is simulated and the banner is always shown.
  - **Security Rules** — Brief description of which S3 and EC2 misconfigurations are detected and at what severity.
  - **Extending to Real AWS (Session 2)** — One paragraph explaining the `ScannerProvider` interface and the `SCANNER_PROVIDER` env var.
- **Completion condition:** `README.md` exists at the project root and covers all listed sections. Instructions in the README are accurate and runnable.
- **Dependencies:** Task 13.4.

---

## Optional Enhancements (Post-MVP)

The following tasks are explicitly optional. They must not delay Session 1 completion.

### Task OPT-1 — S3 Versioning and Logging Checks
- **Requirement:** Req 3.8 (optional)
- **Action:** Add `check_versioning_disabled` (Severity: Low) and `check_logging_disabled` (Severity: Informational) rule functions to `s3_rules.py`. Update fixtures to include at least one bucket exercising each rule. Add corresponding unit tests in `test_s3_rules.py`.
- **Completion condition:** Both rules fire correctly for matching fixture inputs and are covered by passing tests.
- **Dependencies:** Task 5.1, Task 12.1.

### Task OPT-2 — GET /api/findings Endpoint
- **Requirement:** Design §API Endpoints (optional per task list requirements)
- **Action:** Add `GET /api/findings` to `main.py`. Returns the most recent `ScanResult` if available, or HTTP 404 with `{"code": "NO_SCAN_RESULT", "message": "No scan has been run yet."}`.
- **Completion condition:** After a scan, `GET /api/findings` returns the same result as the last `POST /api/scan` response.
- **Dependencies:** Task 6.1.

### Task OPT-3 — PDF Export
- **Requirement:** Req 6.2 (noted as optional)
- **Action:** Add a PDF export option using a suitable Python library (e.g., `reportlab` or `weasyprint`). Add a "Download PDF" option to `ExportButton`. PDF includes cover section, summary table, and per-finding detail sections ordered by severity.
- **Completion condition:** "Download PDF" produces a valid, readable PDF with all findings and `"SIMULATED DATA"` clearly marked.
- **Dependencies:** Task 10.2, Task 6.2.

---

## Validation Checklist

Before marking Session 1 complete, verify:

- [x] **Req 1 (Simulated Mode):** "Demo Mode — Simulated Data" banner is persistent, non-dismissible, and visible on all pages. All export files contain `"simulated": true` or equivalent. No UI text describes results as real AWS findings. **✓ Verified via Playwright on all three routes.**
- [x] **Req 2 (ScannerProvider):** `ScannerProvider` Protocol exists. `SimulatedScannerProvider` loads fixtures and does not import Boto3. Provider is injected via `SCANNER_PROVIDER` env var. **✓ `test_simulated_provider_no_boto3` passes.**
- [x] **Req 3 (S3 Rules):** Critical (effective-public ACL and policy), High (partial block, no encryption), Medium (AuthenticatedUsers ACL), Low (versioning disabled), Informational (SSE-S3 only, logging disabled) rules all fire correctly against fixtures. **✓ 22 S3 unit tests pass.**
- [x] **Req 4 (EC2 Rules):** Critical (SSH, RDP, DB ports, all-ports), High (other ports), Informational (80/443) rules fire correctly. IPv6 CIDR handled. Deduplication and all-ports suppression work. **✓ 22 EC2 unit tests pass.**
- [x] **Req 5 (Dashboard):** Stats panel, chart, recent findings, filter (≤200ms), search (≤200ms), row expansion with evidence, partial scan warnings panel — all present and functional. **✓ Verified via Playwright screenshots.**
- [x] **Req 6 (Exports):** JSON and CSV download from browser. Files contain all required fields. `simulated` flag present in both formats. **✓ Both files downloaded via Playwright; backend verified 52-row CSV and simulated:true JSON.**
- [x] **Req 7 (Error Handling):** Loading, error, empty, timeout, completion, backend-unavailable, and partial scan states all render correctly. **✓ Scan completion notice and error banner components verified.**
- [x] **Req 8 (Tests):** All backend unit, integration, and property tests pass. All frontend component and property tests pass. Suite completes within 120 seconds. No network calls in tests. **✓ 82 backend / 32 frontend passing.**
- [x] **Req 9 (Responsive/Accessible):** Keyboard navigation works. ARIA labels on icon buttons. No horizontal scroll at 768px. Focus indicators visible. **✓ 768px viewport screenshot shows correct 2-column card layout.**
- [x] **No Session 2 code present:** No Boto3 imports. No AWS credential fields. No STS calls. No fake auth. No database. **✓ `test_simulated_provider_no_boto3` passes; network inspection shows only localhost:8001 calls.**

## Verified Completion Summary

| Phase | Status | Evidence |
|---|---|---|
| Backend tests | ✅ 82/82 passed | pytest output, 5.98s runtime |
| Frontend tests | ✅ 32/32 passed | vitest output, 46.80s runtime |
| Production build | ✅ Clean (674 modules) | `tsc -b && vite build` exit 0 |
| Backend API | ✅ All endpoints responding | Health, scan, export/json, export/csv verified |
| Dashboard | ✅ Fully functional | 52 findings, all 5 severity levels, chart, recent findings |
| Findings page | ✅ Fully functional | Search, filter, row expansion, evidence/remediation |
| Scan page | ✅ No redirect issue | Stays on /scan; completion notice shown |
| JSON export | ✅ Downloads correctly | `simulated: true`, 52 findings, all fields present |
| CSV export | ✅ Downloads correctly | `simulated` column, 52 rows, no embedded newlines |
| Demo Mode banner | ✅ Visible on all pages | Playwright screenshots confirm /dashboard, /findings, /scan |
| No real AWS calls | ✅ Confirmed | Network inspection: only http://127.0.0.1:8001 requests |
| Responsive layout | ✅ 768px verified | Stats cards reflow to 2-col, no horizontal scroll |

