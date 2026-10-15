# Requirements Document

## Introduction

CloudGuard AI is a professional AWS security auditing web application that helps developers, DevOps engineers, and security teams identify misconfigurations in their AWS environments. The application presents security findings in a modern dashboard, explains risks in plain language, recommends actionable fixes, and supports JSON and CSV report exports.

Development is structured in two sessions:

- **Session 1 (current):** A fully functional, locally runnable application using simulated AWS resource data (JSON fixtures). All scanning, analysis, dashboard, export, and test work is completed in this session. Simulated results are always clearly labeled as such.
- **Session 2 (future):** Real AWS integration using Boto3, IAM credentials via the standard credential provider chain, STS identity validation, and optional Amazon Bedrock enhancements. Session 2 work is deferred and documented in a separate section below.

The application is built with React + TypeScript + Vite + Tailwind CSS on the frontend and Python + FastAPI on the backend. No databases, authentication systems, or external cloud infrastructure are required.

---

## Glossary

- **CloudGuard_AI**: The full application system encompassing the frontend dashboard and backend API.
- **Frontend**: The React + TypeScript + Vite + Tailwind CSS single-page application served to the user's browser.
- **Backend**: The FastAPI + Python application that runs scanning rules and serves findings.
- **Scanner**: The Backend component responsible for loading resource configurations and running security rules against them.
- **ScannerProvider**: The interface that abstracts resource loading, allowing the simulated provider (Session 1) to be replaced or extended with a real Boto3 provider (Session 2) without changing rule logic.
- **Analyzer**: The Backend component responsible for evaluating resource configurations against deterministic security rules to produce Findings.
- **Report_Generator**: The Backend component responsible for producing exportable security reports (JSON and CSV).
- **SimulatedMode**: The Session 1 operating mode in which the Scanner loads resource configurations from JSON fixtures rather than calling any AWS API. All results produced in this mode are labeled as simulated.
- **Finding**: A single identified security misconfiguration or risk indicator produced by the Analyzer, including severity, affected resource, evidence, risk explanation, and remediation recommendation.
- **Severity**: A classification of a Finding's risk level — one of: Critical, High, Medium, Low, or Informational. Severity reflects configuration risk, not confirmed exploitability.
- **S3_Bucket**: A simulated Amazon S3 storage bucket resource configuration, evaluated for public access and encryption misconfigurations.
- **Security_Group**: A simulated Amazon EC2 security group resource configuration, evaluated for overly permissive inbound rules.
- **Dashboard**: The main Frontend page that displays scan results, Finding summaries, and navigation controls.
- **Export**: The action of producing a downloadable file (JSON or CSV) containing the findings from a completed scan.
- **Scan_Session**: A single end-to-end execution of the Scanner and Analyzer against a set of resource configurations (simulated in Session 1), producing a collection of Findings.
- **Partial_Scan**: A Scan_Session in which some resources were successfully assessed and some were not, due to fixture loading errors or rule exceptions.

---

## Session 1 Requirements — Simulated Scanning

### Requirement 1: Simulated Mode Operation and Labeling

**User Story:** As a user evaluating CloudGuard AI, I want to see realistic security findings generated from simulated AWS resource configurations, clearly labeled as simulated, so that I understand the tool's analysis capabilities without needing real AWS credentials.

#### Acceptance Criteria

1. THE application SHALL operate exclusively in SimulatedMode for Session 1. There SHALL be no real AWS API calls, no AWS credential input, and no STS validation in Session 1.
2. THE Frontend SHALL display a persistent "Demo Mode — Simulated Data" banner on every page of the Dashboard. This banner SHALL be visible without scrolling on a 1280×800 viewport and SHALL NOT be dismissible.
3. ALL Finding titles, risk explanations, remediation text, and export file contents SHALL include language making clear that findings are based on simulated configurations and not real AWS scan results.
4. THE Backend fixture dataset SHALL include at least ten S3_Bucket configurations and at least ten Security_Group configurations, collectively producing Findings at all five Severity levels: Critical, High, Medium, Low, and Informational.
5. ALL simulated resource names, IDs, and account values SHALL be clearly fictitious (e.g., `simulated-bucket-prod`, `sg-sim-0042`, account ID `123456789012`) and SHALL NOT resemble real production resource identifiers.
6. THE simulated resource configurations SHALL be realistic — they SHALL reflect plausible misconfigurations that a real AWS environment might contain, not arbitrary or trivially obvious data.

---

### Requirement 2: Backend Scanner Architecture

**User Story:** As a developer, I want the scanning logic to be structured around a clean provider interface, so that the simulated provider used in Session 1 can be replaced with a real Boto3 provider in Session 2 without rewriting rule logic.

#### Acceptance Criteria

1. THE Backend SHALL define a `ScannerProvider` interface (abstract base class or Protocol) with at minimum the following methods: `list_s3_buckets()` returning a list of S3_Bucket configuration objects, and `list_security_groups(region: str)` returning a list of Security_Group configuration objects.
2. THE Session 1 Backend SHALL implement a `SimulatedScannerProvider` that fulfils the `ScannerProvider` interface by loading resource configurations from JSON fixture files on disk. It SHALL NOT make any network calls or import Boto3.
3. THE Analyzer SHALL accept a `ScannerProvider` instance as a dependency and SHALL call only the interface methods — it SHALL NOT reference `SimulatedScannerProvider` directly or contain any fixture-loading logic.
4. THE FastAPI application SHALL instantiate and inject the `SimulatedScannerProvider` at startup. The provider choice SHALL be configurable via an environment variable (e.g., `SCANNER_PROVIDER=simulated`) so that a future `Boto3ScannerProvider` can be selected without code changes.
5. THE JSON fixture files SHALL be stored under `backend/fixtures/` and SHALL be valid JSON. Each fixture file SHALL be independently loadable and testable.

---

### Requirement 3: S3 Bucket Security Scanning Rules

**User Story:** As a cloud security engineer, I want CloudGuard AI to evaluate simulated S3 bucket configurations for public exposure and encryption misconfigurations, so that I can see how the tool identifies and explains storage security risks.

#### Acceptance Criteria

1. WHEN a Scan_Session begins, THE Scanner SHALL load all S3_Bucket configurations from the `SimulatedScannerProvider`.
2. WHEN the Scanner successfully loads S3_Bucket configurations, THE Analyzer SHALL evaluate each bucket's public access block settings, ACL grants, bucket policy public status, and server-side encryption configuration.
3. Effective public exposure SHALL be determined by evaluating all three controls together. A bucket SHALL be considered effectively public only when ALL of the following are true: (a) at least one of the four S3 Block Public Access settings is disabled, AND (b) either the ACL grants read or write access to the `AllUsers` or `AuthenticatedUsers` canonical groups OR the bucket policy status `IsPublicPolicy` is `true`.
4. WHEN a bucket is determined to be effectively public per criterion 3, THE Analyzer SHALL generate a Finding with Severity "Critical" identifying which specific condition(s) contributed (ACL, policy, or both) and recommending enabling all four S3 Block Public Access settings.
5. WHEN a bucket has at least one S3 Block Public Access setting disabled but does NOT meet the full effective-public threshold in criterion 3, THE Analyzer SHALL generate a Finding with Severity "High" noting that partial public access controls are misconfigured and recommending full enablement of S3 Block Public Access.
6. WHEN a bucket has no server-side encryption configured (no default encryption rule present), THE Analyzer SHALL generate a Finding with Severity "High" and a remediation recommendation to enable SSE-S3 (AES-256) or SSE-KMS encryption.
7. WHEN a bucket has server-side encryption configured using SSE-S3 (AES-256) rather than SSE-KMS, THE Analyzer SHALL generate a Finding with Severity "Informational" noting that customer-managed key encryption is available as a stronger alternative.
8. IF versioning and access logging checks are implemented as optional enhancements: versioning disabled SHALL produce a Finding with Severity "Low" and logging disabled SHALL produce a Finding with Severity "Informational". These checks SHALL NOT block or delay Session 1 completion if not finished.
9. IF THE Scanner encounters an error loading or parsing a specific S3_Bucket fixture entry, THE Analyzer SHALL record a warning for that entry and continue processing remaining entries. No Finding SHALL be generated from a malformed fixture entry.
10. Each S3 Finding SHALL include: bucket name, the specific misconfiguration detected (with the fixture field values that triggered it), assigned Severity, a plain-language risk explanation, and a remediation recommendation.

---

### Requirement 4: EC2 Security Group Scanning Rules

**User Story:** As a cloud security engineer, I want CloudGuard AI to evaluate simulated EC2 security group configurations for overly permissive inbound rules, so that I can see how the tool identifies and explains network exposure risks.

#### Acceptance Criteria

1. WHEN a Scan_Session begins, THE Scanner SHALL load all Security_Group configurations from the `SimulatedScannerProvider`.
2. Severity for inbound rule findings SHALL be assigned deterministically by the following ordered rules, evaluated per inbound rule entry per Security_Group:
   - **Critical**: Any inbound rule permitting traffic from `0.0.0.0/0` or `::/0` on port 22 (SSH), port 3389 (RDP), port 3306 (MySQL), port 5432 (PostgreSQL), port 1433 (MSSQL), port 27017 (MongoDB), or on all ports (protocol `-1` or a port range spanning `0–65535`).
   - **High**: Any inbound rule permitting traffic from `0.0.0.0/0` or `::/0` on any port not listed as Critical above and not port 80 or 443.
   - **Informational**: Any inbound rule permitting traffic from `0.0.0.0/0` or `::/0` on port 80 or 443 (expected public web traffic, noted for awareness).
3. THE Analyzer SHALL evaluate both IPv4 CIDR (`0.0.0.0/0`) and IPv6 CIDR (`::/0`) source ranges when applying the severity rules in criterion 2.
4. WHEN multiple inbound rules in the same Security_Group match the same severity level and port, THE Analyzer SHALL produce a single consolidated Finding for that port-severity combination in that Security_Group, listing all matching rule entries in the Finding's evidence detail.
5. WHEN an all-ports Critical rule (protocol `-1` or port range `0–65535`) is present in a Security_Group, THE Analyzer SHALL generate only the all-ports Finding for that Security_Group and SHALL NOT generate additional individual-port Findings for ports covered by the all-ports rule.
6. Each Security_Group Finding SHALL include: the Security_Group ID, the Security_Group name, the specific inbound rule entry(ies) that triggered the Finding, the assigned Severity, a plain-language risk explanation distinguishing configuration risk from confirmed exploitability, and a remediation recommendation.
7. IF THE Scanner encounters an error loading or parsing a specific Security_Group fixture entry, THE Analyzer SHALL record a warning for that entry and continue processing remaining entries.

---

### Requirement 5: Security Findings Dashboard

**User Story:** As a security team member, I want to view all scan findings in a clear, organized dashboard, so that I can quickly understand the security posture of the simulated environment.

#### Acceptance Criteria

1. THE Dashboard SHALL display an overview statistics panel showing: total Finding count, and Finding count per Severity (Critical, High, Medium, Low, Informational) using color-coded indicators — Critical = red, High = orange, Medium = yellow, Low = blue, Informational = grey.
2. THE Dashboard SHALL display a severity distribution chart (e.g., bar or donut) visualizing the proportion of Findings at each Severity level.
3. THE Dashboard SHALL display a findings table listing each Finding with columns: Resource Type, Resource Name, Severity badge, and Finding Title.
4. WHEN the user expands a Finding row, THE Frontend SHALL display the Finding's evidence (the specific configuration values that triggered it), full risk explanation, and remediation recommendation inline within the same table row, without navigating away from the Dashboard.
5. THE Dashboard SHALL provide a severity filter control allowing the user to show only Findings at one or more selected Severity levels. The filter SHALL apply within 200 milliseconds of each selection change.
6. THE Dashboard SHALL provide a search input that filters the findings table by partial match on Resource Name or Finding Title. Results SHALL update within 200 milliseconds of each keystroke.
7. WHEN the user clears the search input, THE Dashboard SHALL restore the full unfiltered finding set within 200 milliseconds.
8. THE Dashboard SHALL display a "Recent Findings" section showing the five most recently generated Findings (by scan order) with their Severity and title.
9. WHEN a Scan_Session is in progress, THE Dashboard SHALL display a visible loading/progress state and SHALL disable the scan trigger controls until the session completes or fails.
10. WHEN a Scan_Session produces zero Findings, THE Dashboard SHALL display a "No findings detected" message in the findings table area.
11. WHEN a Partial_Scan completes with warnings, THE Dashboard SHALL display the successfully collected Findings and render a collapsible warnings panel listing each resource entry that could not be processed and the reason.
12. WHEN the Backend API is unavailable or returns an error, THE Frontend SHALL display a connection error state on the Dashboard rather than a blank or broken page.

---

### Requirement 6: Security Report Export

**User Story:** As a security manager, I want to export scan findings as a downloadable report, so that I can share results with stakeholders.

#### Acceptance Criteria

1. THE Dashboard SHALL provide an "Export Report" button that is enabled only when a Scan_Session has completed and produced at least one Finding.
2. WHEN the user clicks "Export Report", THE Frontend SHALL present the user with a choice of export format: JSON or CSV.
3. WHEN the user selects JSON export, THE Report_Generator SHALL produce a JSON file containing: scan timestamp in ISO 8601 format, a `"simulated": true` field, total Finding count by Severity, and the full list of Findings each with `resource_type`, `resource_name`, `severity`, `title`, `evidence`, `risk_explanation`, and `remediation` fields.
4. WHEN the user selects CSV export, THE Report_Generator SHALL produce a UTF-8 encoded CSV file with a header row (including a `simulated` column set to `true` for every row) and one data row per Finding, with the same fields as the JSON export. Multi-line text fields SHALL have internal newlines replaced with a space.
5. THE exported file SHALL be downloaded directly in the user's browser without requiring a separate page navigation.
6. IF an export generation error occurs, THE Frontend SHALL display a dismissible error notification and SHALL keep the "Export Report" button enabled so the user can retry.

---

### Requirement 7: Error Handling and Application States

**User Story:** As a user, I want clear feedback for all application states — loading, empty results, errors, and scan completion — so that I always understand what the application is doing.

#### Acceptance Criteria

1. THE Frontend SHALL display a visible loading state (spinner or progress indicator) during any active Scan_Session.
2. WHEN the Backend returns an HTTP 4xx or 5xx response, THE Frontend SHALL display a non-blocking error notification banner with the error message and a dismiss button. The banner SHALL persist until dismissed.
3. WHEN an unhandled exception occurs in the Backend during a Scan_Session, THE Backend SHALL log the full exception stack trace to standard output and SHALL return an HTTP 500 response with `code: "INTERNAL_ERROR"` and a generic user-facing message that does not include class names, file paths, line numbers, or stack trace content.
4. THE Frontend SHALL implement a 120-second request timeout. If the Backend does not respond within that period, THE Frontend SHALL display a "Request timed out — please try again" notification.
5. WHEN a Scan_Session completes successfully, THE Frontend SHALL display a scan completion notice showing the total Finding count and a timestamp.
6. WHEN the Backend API is completely unavailable (connection refused or DNS failure), THE Frontend SHALL display a connection error state rather than a blank or broken page.
7. IF a Partial_Scan completes (some fixture entries could not be processed), THE Backend SHALL return HTTP 200 with the successfully collected Findings and a `warnings` array where each entry contains the resource identifier and a human-readable reason for the failure.
8. WHEN a Scan_Session returns zero Findings and zero warnings, THE Backend SHALL return HTTP 200 with an empty findings array — not an error response.

---

### Requirement 8: Automated Tests

**User Story:** As a developer, I want automated tests covering scanning rules, finding calculations, filters, and exports, so that I can verify correctness without needing real AWS resources.

#### Acceptance Criteria

1. THE Backend SHALL include unit tests for the Analyzer's deterministic severity rule logic covering: each S3 rule (criteria 3–8 of Requirement 3), each EC2 severity rule (criterion 2 of Requirement 4), and the deduplication/consolidation rules (criteria 4–5 of Requirement 4). These tests SHALL use fixture data and SHALL NOT make any network calls.
2. THE Backend SHALL include at least one integration test per resource type (S3 and EC2) using the `SimulatedScannerProvider` to verify that: (a) the Scan_Session completes and returns a findings list, (b) each returned Finding contains the required fields (`resource_type`, `resource_name`, `severity`, `title`, `evidence`, `risk_explanation`, `remediation`), and (c) Severity values are members of `{Critical, High, Medium, Low, Informational}`.
3. THE Backend SHALL include a property-based test (using `hypothesis`) that, for all valid combinations of S3_Bucket attribute inputs, verifies that the Analyzer produces only Findings with Severity in `{Critical, High, Medium, Low, Informational}` and never raises an unhandled exception.
4. THE Backend SHALL include a test verifying that the `SimulatedScannerProvider` does not import or call Boto3 at any point during test execution.
5. THE Frontend SHALL include component tests using Vitest and React Testing Library covering: the overview statistics panel (correct count per severity), the findings table (row rendering and row expansion), the severity filter control (correct filtering behavior), the search input (correct partial match filtering), and the Export Report button (enabled/disabled state logic).
6. THE Frontend SHALL include property-based tests using `fast-check` verifying that: (a) the severity filter always produces a subset of the unfiltered findings list, (b) the search filter always produces a subset of the unfiltered findings list, and (c) JSON and CSV export output is consistent with the findings currently displayed.
7. WHEN the full test suite is executed with `pytest` (Backend) or `vitest` (Frontend), the suite SHALL complete within 120 seconds without requiring real AWS credentials or any network access.

---

### Requirement 9: Responsive Design and Navigation

**User Story:** As a user on any modern device, I want the application to be usable and accessible, so that I can navigate and interact with findings effectively.

#### Acceptance Criteria

1. THE Frontend SHALL render without horizontal scrolling or overlapping elements on viewport widths from approximately 768px (tablet) to 1920px (wide desktop).
2. THE Frontend SHALL be fully operable using keyboard navigation alone. All interactive elements (buttons, filter controls, search input, expandable rows, export controls) SHALL have visible focus indicators meeting WCAG 2.1 SC 2.4.7 (Focus Visible).
3. THE Frontend SHALL provide ARIA labels or roles for all icon-only buttons and non-text UI elements on the Dashboard.
4. THE application SHALL include working navigation between at minimum: a Dashboard/Overview page, a Findings page, and a Scan Controls page (or section).
5. THE Frontend SHALL display meaningful page titles and headings that reflect the current view.

---

## Session 2 Requirements — Future AWS Integration

> These requirements are **deferred**. They SHALL NOT be implemented in Session 1. They are documented here to preserve design intent and to guide the Session 2 provider implementation.

### Future Requirement A: Real AWS Credential Resolution

- THE Backend SHALL resolve AWS credentials exclusively through the standard Boto3 Credential_Chain (environment variables, AWS CLI profile, IAM instance role, or ECS task role).
- THE Frontend SHALL NOT display form fields for AWS Access Key IDs, Secret Access Keys, or session tokens.
- THE Backend SHALL call `sts:GetCallerIdentity` to validate the resolved identity before any real scan, returning HTTP 401 (`INVALID_CREDENTIALS`) on auth failure and HTTP 502 (`CREDENTIAL_VALIDATION_UNAVAILABLE`) on network failure.
- Resolved account ID and ARN SHALL be included in scan metadata; no credential values SHALL appear in API responses or logs.

### Future Requirement B: Real S3 and EC2 Scanning via Boto3

- A `Boto3ScannerProvider` SHALL implement the `ScannerProvider` interface, replacing `SimulatedScannerProvider` when `SCANNER_PROVIDER=boto3`.
- The `Boto3ScannerProvider` SHALL use only Read_Only_Permissions: `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketAcl`, `s3:GetBucketPolicyStatus`, `s3:GetBucketEncryption`, `s3:GetBucketVersioning`, `s3:GetBucketLogging`, `ec2:DescribeSecurityGroups`, `ec2:DescribeRegions`, `sts:GetCallerIdentity`.
- The Backend SHALL handle AWS `AccessDenied` (scan-level = abort with structured error; resource-level = Informational finding and continue) and throttling (exponential backoff, max 3 retries).
- The Backend SHALL include a documented IAM policy JSON file at `docs/iam-policy.json`.
- The Frontend SHALL display a pre-scan read-only permissions notice that the user must acknowledge before a real scan proceeds.

### Future Requirement C: AWS Deployment and Infrastructure

- No specific AWS deployment infrastructure (ECS, Lambda, EC2 hosting) is defined for Session 2 at this time.
- Amazon Bedrock integration is optional and SHALL NOT be required for core scanning functionality.

---
