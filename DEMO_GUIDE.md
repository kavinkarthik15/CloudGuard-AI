# CloudGuard AI — Jury Demonstration Guide

This guide gives exact, copy-pasteable commands and a step-by-step sequence for demonstrating CloudGuard AI to a competition jury.

---

## Startup Commands

Open **two** terminal windows side-by-side.

### Terminal 1 — Backend

```cmd
cd /d "D:\CloudGuard AI\backend"
.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8001 --reload
```

Wait until you see:
```
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8001
```

### Terminal 2 — Frontend (Development Server)

```cmd
cd /d "D:\CloudGuard AI\frontend"
npm run dev
```

Wait until you see:
```
  VITE vX.X.X  ready in XXX ms
  ➜  Local:   http://localhost:5173/
```

Open a browser and go to: **http://localhost:5173**

---

## Demo Sequence

### Step 1 — Landing (Demo Mode, automatic)

**What happens:** The app redirects to `/dashboard` and automatically triggers a Demo Mode scan using simulated fixture data. No AWS credentials are needed.

**What to show:**
- The amber **"Demo Mode — Simulated Data"** banner at the top — explain this is the demo/safe mode.
- The stats panel showing finding counts by severity (Critical, High, Medium, Low, Informational).
- The severity distribution chart.
- The "Recent Findings" panel on the right.

**What to say:**
> "CloudGuard AI is an AWS Security Misconfiguration Auditor. In Demo Mode it analyses a set of realistic but simulated AWS configurations — no real AWS account is needed. The application automatically detected misconfigurations across S3 buckets and EC2 security groups."

---

### Step 2 — Findings Page

Navigate to **Findings** in the sidebar.

**What to show:**
- The total finding count in the subtitle.
- The severity filter — select "Critical" only to isolate the worst issues.
- Click on any finding row to expand it.

**What to say:**
> "Each finding shows the resource ID, severity, a plain-language title, the exact configuration evidence that triggered the rule, the risk explanation, and a step-by-step remediation guide."

**Expanded finding details to highlight:**
- **Evidence** — the exact JSON values from the resource config (e.g. `block_public_acls: false`, `acl_grants: AllUsers READ`).
- **Risk Explanation** — explains why this is dangerous.
- **Remediation** — tells the engineer exactly what to fix.

---

### Step 3 — Export

On the Findings page, click the **Export Report** button (top right).

**What to show:**
- Click "Download JSON" — a JSON file downloads immediately.
- Click "Export Report" again → "Download CSV" — a CSV file downloads.

**What to say:**
> "Findings can be exported as JSON for programmatic ingestion or CSV for sharing with management. Each export is keyed to the specific scan — if the scan expires the user gets a clear error rather than stale data."

Open the downloaded CSV in a text editor or Excel to show headers and rows.

---

### Step 4 — Scan Page & Live AWS Mode (if credentials available)

Navigate to **Scan** in the sidebar.

**What to show (Demo Mode path, always works):**

1. The mode selector shows "⬡ Demo Mode" and "⬡ Live AWS" tabs.
2. Demo Mode tab is selected by default, showing the amber info box.
3. Click **Run Scan** — the scan runs against fixture data, shows a completion card.

**What to say:**
> "Demo Mode runs instantly with no AWS account — perfect for evaluating the tool. For a real audit, switch to Live AWS mode."

**What to show (Live Mode, only if AWS credentials are configured):**

1. Click the **⬡ Live AWS** tab.
2. The profile selector appears — select or type your AWS CLI profile (e.g. `default`).
3. Set the region (e.g. `eu-north-1`).
4. Click **Verify AWS Identity** — the app calls `sts:GetCallerIdentity` and displays your account ID, role ARN, and region.
5. Click **Run Scan** — the scan runs against real AWS resources (read-only).

**What to say:**
> "In Live AWS mode, CloudGuard AI uses only read-only permissions — s3:List*, s3:Get*, ec2:Describe*, and sts:GetCallerIdentity. No resources are created or modified. The identity is verified before the scan starts to catch expired credentials early."

---

### Step 5 — Zero Findings (Explain what it means)

If a Live scan returns zero findings:

The dashboard shows:
> "No findings detected in this live scan. This means no misconfigurations matching the current rules were found — it does not guarantee a fully secure configuration."

**What to say:**
> "Zero findings is meaningful but not a security guarantee. It means none of the rules we implemented fired. CloudGuard AI is transparent about that."

---

### Step 6 — Detection Rules (brief technical summary)

**S3 Rules detected:**
| Severity | Rule |
|---|---|
| Critical | Public ACL (AllUsers/AuthenticatedUsers) + blocks disabled |
| High | Partial public access block (any setting disabled) |
| High | No default encryption configured |
| Medium | AuthenticatedUsers ACL with all blocks on |
| Low | Versioning disabled |
| Informational | SSE-S3 only (KMS recommended) |
| Informational | Access logging disabled |

**EC2 Security Group Rules detected:**
| Severity | Rule |
|---|---|
| Critical | World-open SSH (port 22), RDP (3389), MySQL (3306), PostgreSQL (5432), MSSQL (1433), MongoDB (27017) |
| Critical | All-ports open (protocol -1 or 0–65535) |
| High | World-open non-standard port |
| Informational | World-open HTTP (80) or HTTPS (443) |

---

## Key Talking Points for Jury Q&A

- **No credentials hardcoded** — profile name comes from the request, credentials resolved by boto3 credential chain.
- **Permission failures surface as errors** — `AccessDenied` on list operations is shown to the user, never silently treated as "all clear".
- **Demo and Live mode are strictly separated** — the `simulated` flag on every finding and export reflects the actual data source.
- **Export correctness** — each export is tied to a specific `scan_id`; a stale export returns `SCAN_NOT_FOUND` rather than serving wrong data.
- **Read-only** — the tool calls only `List*`, `Describe*`, and `GetCallerIdentity` — no writes, creates, or deletes.

---

## Troubleshooting

| Issue | Fix |
|---|---|
| Backend returns "could not connect" | Check Terminal 1 — uvicorn must show "Application startup complete." |
| Frontend blank page | Check Terminal 2 — vite dev server must be running at :5173 |
| Port conflict on 8001 | Change `--port 8001` to `--port 8002` and update `frontend/.env.local` to match |
| Live AWS: "credentials expired" | Run `aws sso login --profile <name>` in a terminal |
| Live AWS: "profile not found" | Run `aws configure list-profiles` to see configured profiles |
