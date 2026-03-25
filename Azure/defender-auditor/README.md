# Azure Defender for Cloud Auditor

Audits Azure Defender for Cloud configuration across one or all subscriptions. Checks plan enablement per resource type, Secure Score, security contact configuration, and auto-provisioning of monitoring agents.

---

## Features

- Defender plans — checks enablement status for VMs, SQL, App Service, Storage, Key Vault, DNS, ARM, Containers, OpenSourceRelational, and CSPM
- Secure Score — retrieves current Secure Score for each subscription
- Security contacts — flags missing email, phone, or misconfigured alert settings
- Auto-provisioning — checks whether monitoring agents are set to auto-provision
- Multi-subscription — scans all accessible subscriptions with the `-AllSubscriptions` flag
- JSON, CSV, and colour-coded HTML output

---

## Requirements

- PowerShell 7+ (or Windows PowerShell 5.1)
- Az PowerShell modules:
  ```powershell
  Install-Module Az.Accounts, Az.Security, Az.Resources -Scope CurrentUser
  Connect-AzAccount
  ```

---

## Usage

```powershell
.\defender_auditor.ps1                                         # Audit current subscription, all formats
.\defender_auditor.ps1 -Format html                            # HTML report only
.\defender_auditor.ps1 -Format all -Output my_report           # All formats, custom filename prefix
.\defender_auditor.ps1 -AllSubscriptions                       # Scan all accessible subscriptions
.\defender_auditor.ps1 -AllSubscriptions -Format html          # All subscriptions, HTML only
.\defender_auditor.ps1 -Format stdout                          # Print JSON to terminal
```

---

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Output` | String | `defender_report` | Output filename prefix |
| `-Format` | String | `all` | Output format: `json`, `csv`, `html`, `all`, or `stdout` |
| `-AllSubscriptions` | Switch | — | Scan all subscriptions the account can access |

---

## Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| Defender plan disabled for any resource type | +4 (HIGH) per disabled plan |
| No security contact email configured | +4 (HIGH) |
| No security contact phone configured | +2 (MEDIUM) |
| Alert notifications disabled | +2 (MEDIUM) |
| Auto-provisioning disabled for monitoring agents | +2 (MEDIUM) |
| Secure Score below 50% | +4 (HIGH) |
| Secure Score below 75% | +2 (MEDIUM) |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Multiple Defender plans disabled or severely misconfigured |
| 5–7 | HIGH | Key plans disabled or no security contact configured |
| 2–4 | MEDIUM | Gaps in provisioning, alerting, or Secure Score |
| 0–1 | LOW | Minor gaps only |

---

## Output Fields

Each finding (one per subscription or per misconfigured item) includes:

| Field | Description |
|-------|-------------|
| `SubscriptionId` | Azure subscription ID |
| `SubscriptionName` | Human-readable subscription name |
| `FindingType` | Type of issue (e.g. `DefenderPlanDisabled`, `NoSecurityContact`) |
| `ResourceType` | Affected Defender plan or resource type, where applicable |
| `SecureScore` | Current Secure Score percentage for the subscription |
| `RiskLevel` | CRITICAL / HIGH / MEDIUM / LOW |
| `SeverityScore` | Numeric score 1–10 |
| `Flags` | Observation list describing the issue |
| `Remediations` | Actionable remediation steps |

---

## Running Tests

```powershell
Invoke-Pester Azure/defender-auditor/tests/ -Output Detailed
```

Tests use Az module stubs — no real Azure connection required.

---

## Disclaimer

For authorised internal security auditing only.
