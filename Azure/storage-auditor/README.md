# 🗄️ Storage Auditor

Audits all Azure Storage Accounts in your subscription for public access, weak authentication, missing encryption controls, and absent data protection features — producing a colour-coded HTML report alongside JSON and CSV outputs. Azure equivalent of the [s3-auditor](../AWS/s3-auditor/).

---

## ✨ Features

- Public blob access detection (`AllowBlobPublicAccess`)
- Shared key access check — flags accounts not enforcing Entra-only authentication
- Customer-managed key (CMK) check — flags accounts using Microsoft-managed keys only
- Infrastructure encryption check — flags accounts without double-encryption enabled
- Soft delete status — checks blob-level and container-level soft delete
- Versioning — flags accounts with blob versioning disabled
- Diagnostic logging — identifies accounts with no diagnostic settings configured
- SAS expiry policy — flags accounts with no SAS token expiry policy enforced
- Numeric severity scoring (1–10)
- JSON, CSV, and colour-coded HTML output

---

## ⚙️ Requirements

- PowerShell 7+
- `Az.Accounts`, `Az.Storage`

```powershell
Install-Module Az.Accounts, Az.Storage -Scope CurrentUser
Connect-AzAccount
```

---

## 🚀 Usage

### Azure CloudShell

Upload `storage_auditor.ps1` and run:

```powershell
.\storage_auditor.ps1
```

### Options

```powershell
.\storage_auditor.ps1                          # Current subscription, all formats
.\storage_auditor.ps1 -AllSubscriptions        # All accessible subscriptions
.\storage_auditor.ps1 -Format html             # HTML output only
.\storage_auditor.ps1 -Format stdout           # Print JSON to console
.\storage_auditor.ps1 -Output my_report        # Custom output file prefix
```

---

## 📊 Severity Scoring

| Finding | Severity | Score |
|---------|----------|-------|
| Public blob access enabled | CRITICAL | 9 |
| Shared key access enabled | HIGH | 7 |
| Soft delete disabled | MEDIUM | 4 |
| No customer-managed key | MEDIUM | 4 |
| Versioning disabled | MEDIUM | 3 |
| No diagnostic logging | MEDIUM | 3 |
| No infrastructure encryption | LOW | 2 |
| No SAS expiry policy | LOW | 2 |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
