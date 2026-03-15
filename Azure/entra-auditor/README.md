# 🔑 Entra Auditor

Audits Entra ID (Azure AD) and RBAC configuration — checking MFA coverage, privileged guest access, service principal permissions, stale app credentials, and dangerous role combinations that create privilege escalation paths. Azure equivalent of the [iam-privilege-mapper](../AWS/iam-privilege-mapper/).

---

## ✨ Features

- MFA registration check — flags users with no MFA method registered (via Microsoft Graph)
- Privileged guest users — identifies external/guest accounts assigned Owner, Contributor, or User Access Administrator
- Service principal scope — flags SPs with Owner or Contributor at subscription scope
- Stale app credentials — flags app registrations with expired or long-running secrets/certificates (>90 days)
- Overpermissive custom roles — flags custom role definitions with wildcard write, delete, or unrestricted actions
- Privilege escalation path detection — flags dangerous role combinations per principal:
  - `User Access Administrator` + `Contributor` → can grant self Owner
  - `Managed Identity Contributor` + `Contributor` → can create and assign managed identity
  - `Role Based Access Control Administrator` → can modify own role assignments
  - `Owner` assigned to a service principal with no owner tracking
  - Any role with `Microsoft.Authorization/*/write` + `Contributor`
- Numeric severity scoring (1–10)
- JSON, CSV, and colour-coded HTML output

---

## ⚙️ Requirements

- PowerShell 7+
- `Az.Accounts`, `Az.Resources`
- `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`

```powershell
Install-Module Az.Accounts, Az.Resources -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users -Scope CurrentUser
Connect-AzAccount
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All","RoleManagement.Read.Directory"
```

---

## 🚀 Usage

### Azure CloudShell

Upload `entra_auditor.ps1` and run:

```powershell
.\entra_auditor.ps1
```

### Options

```powershell
.\entra_auditor.ps1                          # Current subscription, all formats
.\entra_auditor.ps1 -AllSubscriptions        # All accessible subscriptions
.\entra_auditor.ps1 -Format html             # HTML output only
.\entra_auditor.ps1 -Format stdout           # Print JSON to console
.\entra_auditor.ps1 -Output my_report        # Custom output file prefix
```

---

## 📊 Severity Scoring

| Finding | Severity | Score |
|---------|----------|-------|
| Privilege escalation path detected | CRITICAL | 9 |
| User without MFA | HIGH | 7 |
| Privileged guest user | HIGH | 7 |
| Overpermissive custom role | HIGH | 6 |
| Service principal with broad scope | MEDIUM | 5 |
| Stale app credential | MEDIUM | 5 |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
