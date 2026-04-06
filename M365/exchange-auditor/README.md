# exchange-auditor

Audits Exchange Online transport rules, mailbox delegation, and audit configuration.
Complements the forwarding/inbox-rule checks in the existing m365-auditor.

## Checks

| ID | Finding | Severity |
|----|---------|----------|
| EX-01 | Transport rule forwards mail to external domain | CRITICAL |
| EX-02 | Transport rule bypasses spam/malware filtering | CRITICAL |
| EX-03 | Remote domain allows automatic forwarding | CRITICAL |
| EX-04 | FullAccess mailbox delegation to non-admin account | MEDIUM |
| EX-05 | Shared mailbox sign-in not blocked | HIGH |
| EX-06 | Per-mailbox audit logging disabled | HIGH |
| EX-07 | Admin audit logging disabled | HIGH |
| EX-08 | SMTP AUTH enabled on individual mailbox | HIGH |

## Requirements

- ExchangeOnlineManagement module: `Install-Module ExchangeOnlineManagement`
- Microsoft.Graph module: `Install-Module Microsoft.Graph` (for EX-05 shared mailbox check)
- Exchange Online admin (read-only) + `AuditLogs.Read.All`

## Usage

```powershell
.\exchange_auditor.ps1 -TenantDomain contoso.com
.\exchange_auditor.ps1 -TenantDomain contoso.com -Format json
```

## Output

Produces `exchange_report.json`, `exchange_report.csv`, `exchange_report.html`.
