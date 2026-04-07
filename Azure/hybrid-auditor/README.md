# Hybrid Identity Auditor

Audits Hybrid Identity (Azure AD Connect / Entra Connect) security posture via Microsoft Graph. Relevant for tenants with on-premises Active Directory synchronised to Entra ID — common for Irish SMBs in the 20–100 employee range.

Cloud-only tenants (no on-prem sync) receive a single `CloudOnlyTenant INFO` finding and exit cleanly — no false positives.

## Checks

| ID | FindingType | Severity | Description |
|----|-------------|----------|-------------|
| HA-01 | SyncStale | CRITICAL | Directory sync has not completed in >3 hours, or has never run |
| HA-02 | PasswordHashSyncDisabled | MEDIUM | PHS not enabled — no resilient fallback if PTA agents go offline |
| HA-03 | PasswordWritebackDisabled | MEDIUM | Password writeback off — SSPR cannot reset on-premises AD passwords |
| HA-04 | AccidentalDeletionPreventionDisabled | HIGH | Bulk-delete protection disabled — mass wipe risk |
| HA-05 | SeamlessSsoNotEnabled | LOW | Seamless SSO not configured — domain-joined devices prompt for credentials |

## Requirements

- PowerShell 7+
- `Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement`
- Scopes: `Organization.Read.All`, `OnPremDirectorySynchronization.Read.All`
- Global Reader or Hybrid Identity Administrator role

## Usage

```powershell
.\hybrid_auditor.ps1
.\hybrid_auditor.ps1 -Format json
.\hybrid_auditor.ps1 -Output client_hybrid -Format all
```

## Output

Produces `hybrid_report.json`, `hybrid_report.csv`, `hybrid_report.html`.
