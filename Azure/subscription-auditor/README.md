# 🏢 Subscription Auditor

Audits Azure subscription and tenant-level security posture — checking Defender for Cloud coverage, privileged role assignments, Global Administrator hygiene, resource locks, and budget alerts. Azure equivalent of the [root-auditor](../AWS/root-auditor/).

---

## ✨ Features

- Microsoft Defender for Cloud — flags workloads not enabled at Standard/P2 tier
- Permanent Owner/Contributor assignments — flags human user accounts with permanent subscription-scope roles where no PIM eligible assignment exists
- Global Administrator count — flags tenants with more than 5 Global Admins
- Global Administrator MFA — flags Global Admins without MFA registered (via Microsoft Graph)
- Resource locks — identifies resource groups with no delete/read-only locks
- Budget alerts — flags subscriptions with no consumption budgets configured
- Numeric severity scoring (1–10)
- JSON, CSV, and colour-coded HTML output

---

## ⚙️ Requirements

- PowerShell 7+
- `Az.Accounts`, `Az.Resources`, `Az.Security`
- `Microsoft.Graph.Authentication`, `Microsoft.Graph.Identity.Governance` (for MFA and PIM checks)

```powershell
Install-Module Az.Accounts, Az.Resources, Az.Security -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance -Scope CurrentUser
Connect-AzAccount
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All","RoleManagement.Read.Directory"
```

---

## 🚀 Usage

### Azure CloudShell

Upload `subscription_auditor.ps1` and run:

```powershell
.\subscription_auditor.ps1
```

### Options

```powershell
.\subscription_auditor.ps1                          # Current subscription, all formats
.\subscription_auditor.ps1 -AllSubscriptions        # All accessible subscriptions
.\subscription_auditor.ps1 -Format html             # HTML output only
.\subscription_auditor.ps1 -Format stdout           # Print JSON to console
.\subscription_auditor.ps1 -Output my_report        # Custom output file prefix
```

---

## 📊 Severity Scoring

| Finding | Severity | Score |
|---------|----------|-------|
| Global Admin without MFA | CRITICAL | 9 |
| Permanent Owner/Contributor (no PIM) | CRITICAL | 8 |
| Defender for Cloud not enabled | HIGH | 7 |
| Too many Global Admins (>5) | MEDIUM | 4 |
| No resource locks on resource groups | MEDIUM | 4 |
| No budget alerts configured | LOW | 2 |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
