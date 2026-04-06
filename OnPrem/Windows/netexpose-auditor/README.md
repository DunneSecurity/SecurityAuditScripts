# netexpose-auditor

Active LAN port scanner. Run from your laptop on the client's network to identify hosts with dangerous services exposed — RDP, SMB, WinRM, LDAP, NetBIOS, RPC, MSSQL.

## Checks

| ID | Port | Service | Severity |
|----|------|---------|----------|
| NE-01 | 3389 | RDP | CRITICAL |
| NE-02 | 445 | SMB | CRITICAL |
| NE-03 | 139 | NetBIOS | HIGH |
| NE-04 | 135 | RPC | MEDIUM |
| NE-05 | 5985 | WinRM HTTP | HIGH |
| NE-06 | 5986 | WinRM HTTPS | HIGH |
| NE-07 | 389 | LDAP | MEDIUM |
| NE-08 | 636 | LDAPS | LOW |
| NE-09 | 1433 | MSSQL | HIGH |

Custom ports via `-ExtraPorts` are reported as `ExposedCustomPort` (MEDIUM).

## Requirements

- PowerShell 7+ (uses `ForEach-Object -Parallel`)
- No extra modules required — uses built-in `Test-NetConnection`
- Run from a machine on the client's LAN

## Usage

```powershell
# Scan a full subnet
.\netexpose_auditor.ps1 -Target 192.168.1.0/24

# Scan a single host
.\netexpose_auditor.ps1 -Target 192.168.1.10

# Scan with extra ports
.\netexpose_auditor.ps1 -Target 10.0.0.0/24 -ExtraPorts 8080,8443

# JSON output only
.\netexpose_auditor.ps1 -Target 192.168.1.0/24 -Format json

# Faster scan (higher concurrency)
.\netexpose_auditor.ps1 -Target 192.168.1.0/24 -ThrottleLimit 100

# Shorter timeout (faster, may miss slow hosts)
.\netexpose_auditor.ps1 -Target 192.168.1.0/24 -TimeoutMs 500
```

## Output

Produces `netexpose_report.json`, `netexpose_report.csv`, `netexpose_report.html`.
