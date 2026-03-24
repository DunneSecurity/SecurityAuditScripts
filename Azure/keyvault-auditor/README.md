# 🔑 Azure Key Vault Auditor

Audits Azure Key Vaults for security misconfigurations. Checks RBAC vs legacy access policy model, purge protection, soft delete, diagnostic logging, and expired or expiring secrets, certificates, and keys.

---

## ✨ Features

- Access model — flags Key Vaults still using the legacy access policy model instead of Azure RBAC
- Purge protection — flags vaults without purge protection (HIGH risk; deleted vaults can be immediately purged)
- Soft delete — flags vaults with soft delete disabled (CRITICAL; secret recovery is impossible)
- Diagnostic logging — flags vaults with no diagnostic settings configured
- Secret expiry — CRITICAL for expired secrets, HIGH for expiring within 7 days, MEDIUM within 14 days, configurable warning period
- Certificate expiry — same tiered expiry checks as secrets
- Key expiry — same tiered expiry checks as secrets
- Configurable expiry warning period (default: 30 days)
- JSON, CSV, and colour-coded HTML output

---

## ⚙️ Requirements

- PowerShell 7+ (or Windows PowerShell 5.1)
- Az PowerShell module:
  ```powershell
  Install-Module Az.Accounts, Az.KeyVault -Scope CurrentUser
  Connect-AzAccount
  ```

---

## 🚀 Usage

```powershell
.\keyvault_auditor.ps1                                    # All formats, current subscription
.\keyvault_auditor.ps1 -Format html                       # HTML only
.\keyvault_auditor.ps1 -Format all -Output kv_report      # All formats, custom prefix
.\keyvault_auditor.ps1 -ExpiryWarningDays 60              # Flag items expiring within 60 days
.\keyvault_auditor.ps1 -AllSubscriptions                  # Scan all accessible subscriptions
.\keyvault_auditor.ps1 -Format stdout                     # Print JSON to terminal
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| Soft delete disabled | +8 (CRITICAL) |
| Purge protection disabled | +4 (HIGH) |
| Legacy access policy model (RBAC disabled) | +4 (HIGH) |
| Secret/certificate/key expired | +8 (CRITICAL) |
| Secret/certificate/key expiring within 7 days | +8 (CRITICAL) |
| Secret/certificate/key expiring within 14 days | +4 (HIGH) |
| Secret/certificate/key expiring within warning period | +2 (MEDIUM) |
| No diagnostic logging configured | +2 (MEDIUM) |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Soft delete disabled or active item expired/expiring imminently |
| 5–7 | HIGH | Purge protection disabled or RBAC not enabled |
| 2–4 | MEDIUM | Expiring secrets or missing diagnostic logs |
| 0–1 | LOW | Minor gaps only |

---

## 📋 Output Fields

Each finding (one per Key Vault or per expired/expiring item) includes:

| Field | Description |
|-------|-------------|
| `VaultName` | Key Vault resource name |
| `ResourceGroup` | Resource group containing the vault |
| `SubscriptionId` | Subscription ID |
| `FindingType` | Type of issue (e.g. `SoftDeleteDisabled`, `SecretExpired`) |
| `ItemName` | Secret/certificate/key name (for expiry findings) |
| `ExpiresOn` | Expiry date (for expiry findings) |
| `RiskLevel` | CRITICAL / HIGH / MEDIUM / LOW |
| `SeverityScore` | Numeric score 1–10 |
| `Flags` | Emoji-prefixed observation list |
| `Remediations` | Actionable remediation steps |

---

## Running Tests

```powershell
Invoke-Pester Azure/keyvault-auditor/tests/ -Output Detailed
```

Tests use Az module stubs — no real Azure connection required.

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
