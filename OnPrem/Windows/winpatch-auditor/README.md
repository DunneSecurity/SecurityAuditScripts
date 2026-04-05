# Windows Patch Auditor

Audits Windows patch currency, update configuration, and system uptime/reboot state. No external module dependencies — uses `Get-HotFix`, WMI (`Win32_OperatingSystem`), Windows Update service checks, registry reads, and optionally the Windows Update Agent COM API to enumerate pending security updates.

## Usage

```powershell
# Default — all formats, COM API enabled (60s timeout)
.\winpatch_auditor.ps1

# HTML only
.\winpatch_auditor.ps1 -Format html

# Skip COM API (air-gapped / slow machines)
.\winpatch_auditor.ps1 -MaxSearchSeconds 0 -Format json

# Extend COM API timeout to 2 minutes
.\winpatch_auditor.ps1 -MaxSearchSeconds 120

# Custom output prefix
.\winpatch_auditor.ps1 -Output C:\Reports\client_winpatch -Format all
```

## Checks

| ID | Finding | Source | Severity |
|----|---------|--------|----------|
| PATCH-01 | `LastPatchAge` | `Get-HotFix` | CRITICAL (>60d) · HIGH (>30d) · MEDIUM (>14d) |
| PATCH-02 | `UptimeExceeded` | WMI `LastBootUpTime` | HIGH (>60d) · MEDIUM (>30d) |
| PATCH-03 | `PendingRebootRequired` | 3 registry reboot-pending keys | HIGH |
| PATCH-04 | `WindowsUpdateServiceDisabled` | `wuauserv` service start type | HIGH |
| PATCH-05 | `AutoUpdateDisabled` | Registry `AU\AUOptions` | MEDIUM |
| PATCH-06 | `WsusConfigured` | Registry `WUServer` | LOW (informational) |
| PATCH-07 | `PendingSecurityUpdates` | WUA COM API | CRITICAL · HIGH · MEDIUM |
| PATCH-08 | `WindowsUpdateQueryFailed` | WUA COM API error/timeout | MEDIUM |

## Output

| Format | File | Contents |
|--------|------|----------|
| JSON | `winpatch_report.json` | Full report + summary block |
| CSV | `winpatch_report.csv` | One row per finding |
| HTML | `winpatch_report.html` | Styled report with summary cards |

All output files written with owner-only permissions.

## Requirements

- PowerShell 5.1+ or 7+
- Run as local administrator for full registry and WMI access
- Windows Update service running (for COM API path)
