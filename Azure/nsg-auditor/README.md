# 🔒 NSG Auditor

Audits all Network Security Groups in your Azure subscription for dangerous inbound rules, internet-exposed ports, and orphaned groups — producing a colour-coded HTML report alongside JSON and CSV outputs. Azure equivalent of the [sg-auditor](../AWS/sg-auditor/).

---

## ✨ Features

- Detects inbound rules open to `0.0.0.0/0`, `::/0`, or the `Internet` service tag
- Flags 20 high-risk ports exposed to the internet: SSH, RDP, Telnet, FTP, WinRM, SMB, SQL Server, MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Docker, etcd, LDAP/LDAPS, VNC, NFS
- Identifies orphaned NSGs (not associated with any subnet or NIC)
- Flags NSGs relying solely on the built-in `DenyAllInbound` default with no explicit denies for high-risk ports
- Numeric severity scoring (1–10)
- JSON, CSV, and colour-coded HTML output

---

## ⚙️ Requirements

- PowerShell 7+
- `Az.Accounts`, `Az.Network`

```powershell
Install-Module Az.Accounts, Az.Network -Scope CurrentUser
Connect-AzAccount
```

---

## 🚀 Usage

### Azure CloudShell

Upload `nsg_auditor.ps1` and run:

```powershell
.\nsg_auditor.ps1
```

### Options

```powershell
.\nsg_auditor.ps1                              # Current subscription, all formats
.\nsg_auditor.ps1 -AllSubscriptions            # All accessible subscriptions
.\nsg_auditor.ps1 -Format html                 # HTML output only
.\nsg_auditor.ps1 -Format stdout               # Print JSON to console
.\nsg_auditor.ps1 -Output my_report            # Custom output file prefix
```

---

## 📊 Severity Scoring

| Finding | Severity | Score |
|---------|----------|-------|
| RDP (3389) exposed to internet | CRITICAL | 9 |
| SSH (22) exposed to internet | CRITICAL | 9 |
| Database ports exposed (SQL, MySQL, Postgres, Mongo) | HIGH | 7 |
| SMB/WinRM/LDAP exposed | HIGH | 6–7 |
| NSG with no explicit denies for high-risk ports | MEDIUM | 4 |
| Orphaned NSG | LOW | 2 |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
