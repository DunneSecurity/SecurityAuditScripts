---
title: Windows Patch Auditor Design
date: 2026-04-02
status: approved
---

# Windows Patch Auditor — Design Spec

## Goal

A standalone PowerShell auditor that checks the patch currency and update hygiene of a Windows machine — both *when* it was last patched and *what* is currently missing — plus uptime/reboot state. Runs on the target machine without external module dependencies. Follows the existing `OnPrem/Windows` auditor conventions exactly.

---

## Location

```
OnPrem/Windows/winpatch-auditor/
├── winpatch_auditor.ps1
└── tests/
    └── winpatch_auditor.Tests.ps1
```

Output prefix: `winpatch_report`

---

## Parameters

```powershell
param(
    [string]$Output           = 'winpatch_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format           = 'all',
    [int]   $MaxSearchSeconds = 60   # 0 = skip COM API entirely
)
```

`-MaxSearchSeconds 0` provides a safe escape hatch for air-gapped or slow machines where the Windows Update Agent COM API would hang.

---

## Checks

### Always-run (no network dependency)

| ID | FindingType | Source | Severity thresholds |
|----|-------------|--------|---------------------|
| PATCH-01 | `LastPatchAge` | `Get-HotFix` — most recent `InstalledOn` date | >60d → CRITICAL (9) · >30d → HIGH (7) · >14d → MEDIUM (4) |
| PATCH-02 | `UptimeExceeded` | `Get-CimInstance Win32_OperatingSystem`.`LastBootUpTime` | >60d → HIGH (7) · >30d → MEDIUM (4) |
| PATCH-03 | `PendingRebootRequired` | Three registry reboot-pending keys (see below) | Any present → HIGH (7) |
| PATCH-04 | `WindowsUpdateServiceDisabled` | `Get-Service wuauserv` — Status + StartType | Disabled → HIGH (8) |
| PATCH-05 | `AutoUpdateDisabled` | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` → `AUOptions` | 1 (disabled) or 2 (notify-only) → MEDIUM (5) |
| PATCH-06 | `WsusConfigured` | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` → `WUServer` | Informational (score 0) — surfaces WSUS URL so consultant knows the update source |

**Pending reboot registry keys checked (PATCH-03):**
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
- `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager` → `PendingFileRenameOperations`
- `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareDistribution\RebootRequired`

### COM API checks (skipped if `MaxSearchSeconds = 0` or on error)

| ID | FindingType | Source | Severity thresholds |
|----|-------------|--------|---------------------|
| PATCH-07 | `PendingSecurityUpdates` | `Microsoft.Update.Session` COM object | ≥1 Critical pending → CRITICAL (9) · ≥1 Important → HIGH (7) · Moderate only → MEDIUM (4) |
| PATCH-08 | `WindowsUpdateQueryFailed` | Catch block on COM API call | MEDIUM (4) — update state unknown |

The COM API search uses `Type=Software` and `IsInstalled=0 AND IsHidden=0`. Results are categorised by `MsrcSeverity` (Critical / Important / Moderate / Low / Unspecified).

---

## JSON Report Structure

```json
{
  "generated_at": "2026-04-02T10:00:00Z",
  "hostname": "WORKSTATION01",
  "summary": {
    "last_patch_date": "2026-02-28",
    "days_since_patch": 33,
    "last_reboot": "2026-02-15",
    "uptime_days": 46,
    "pending_reboot": true,
    "windows_update_service": "Running",
    "auto_update_enabled": false,
    "wsus_server": "http://wsus.corp.local:8530",
    "pending_updates": {
      "critical": 2,
      "important": 3,
      "moderate": 1,
      "low": 0,
      "total": 6
    },
    "com_api_used": true,
    "overall_risk": "CRITICAL"
  },
  "findings": [...]
}
```

---

## Finding Schema

Each finding follows the repo-standard schema:

```powershell
[PSCustomObject]@{
    FindingType    = 'LastPatchAge'       # string ID
    Resource       = 'System'             # or specific resource name
    Severity       = 'HIGH'               # CRITICAL | HIGH | MEDIUM | LOW
    Score          = 7                    # 0-10
    Description    = '...'               # human-readable detail with data
    Recommendation = '...'               # actionable fix
    cis_control    = 7                    # CIS v8 control (7 = Continuous Vulnerability Management)
}
```

All findings map to **CIS v8 Control 7** (Continuous Vulnerability Management).

---

## Output Formats

Identical to all other Windows auditors:

| Format | File | Notes |
|--------|------|-------|
| `json` | `<prefix>.json` | Full report + summary block |
| `csv` | `<prefix>.csv` | One row per finding |
| `html` | `<prefix>.html` | Styled report with summary cards (matches repo CSS) |
| `all` | All three | Default |
| `stdout` | — | JSON to console, no files written |

All files written with owner-only permissions (mode 600 / ACL equivalent).

---

## HTML Report Cards

Summary cards shown above the findings table:

- Days Since Patch (coloured red if CRITICAL threshold)
- Uptime (days)
- Pending Reboot (Yes/No, red if Yes)
- Pending Updates (total count)
- CRITICAL / HIGH / MEDIUM / LOW finding counts

---

## Terminal Summary

Banner matching existing auditors:

```
══════════════════════════════════════════════════════
     WINDOWS PATCH AUDIT COMPLETE
══════════════════════════════════════════════════════
  Hostname        : WORKSTATION01
  Last patched    : 2026-02-28 (33 days ago)
  Uptime          : 46 days (last reboot: 2026-02-15)
  Pending reboot  : Yes
  Pending updates : 6 (2 Critical, 3 Important, 1 Moderate)
  Findings        : 4
  CRITICAL: 1  HIGH: 2  MEDIUM: 1  LOW: 0
══════════════════════════════════════════════════════
```

---

## Stubs and Testability

The script defines no-op stubs for `Get-HotFix`, `Get-CimInstance`, `Get-Service`, `Get-ItemProperty`, and the COM object creation so Pester can `Mock` them without touching the real system. The COM API instantiation is isolated in a helper function `New-UpdateSearcher` so it can be mocked independently.

```powershell
function New-UpdateSearcher {
    $session = New-Object -ComObject 'Microsoft.Update.Session'
    $session.CreateUpdateSearcher()
}
```

The main entry point is guarded by `if ($MyInvocation.InvocationName -ne '.')` so dot-sourcing in tests does not execute anything.

---

## Tests (Pester)

~16 tests covering:

1. PATCH-01: flags CRITICAL when last patch > 60 days
2. PATCH-01: flags HIGH when last patch 31–60 days
3. PATCH-01: flags MEDIUM when last patch 15–30 days
4. PATCH-01: no finding when last patch ≤ 14 days
5. PATCH-01: handles null `InstalledOn` (no hotfixes found) → CRITICAL
6. PATCH-02: flags HIGH when uptime > 60 days
7. PATCH-02: flags MEDIUM when uptime 31–60 days
8. PATCH-02: no finding when uptime ≤ 30 days
9. PATCH-03: flags HIGH when RebootRequired registry key present
10. PATCH-03: no finding when no reboot-pending keys present
11. PATCH-04: flags HIGH when wuauserv is disabled
12. PATCH-04: no finding when wuauserv is running
13. PATCH-05: flags MEDIUM when AUOptions = 1 (disabled)
14. PATCH-07: flags CRITICAL when COM API returns critical pending update
15. PATCH-07: no pending-update finding when COM API returns empty
16. PATCH-08: flags MEDIUM when COM API throws (query failed)

---

## Integration

### exec_summary.py
Add `winpatch_report.json` to `KNOWN_PATTERNS` and `PILLAR_LABELS` (pillar: `"Windows On-Prem"`).

### Run-Audit.ps1
Add `winpatch` to the `$WindowsAuditors` array:
```powershell
@{ Name = 'winpatch'; Script = 'OnPrem\Windows\winpatch-auditor\winpatch_auditor.ps1'; Prefix = 'winpatch_report'; AllSubs = $false }
```

### README updates
- Root README: add `winpatch-auditor` row to On-Premises Windows scripts table, increment Windows count 7→8 in diagram
- `OnPrem/README.md`: add to directory tree and scripts table
- New `OnPrem/Windows/winpatch-auditor/README.md`

---

## Out of Scope

- No domain/WSUS enumeration across multiple machines (runs locally only)
- No remediation actions — read-only throughout
- No `PSWindowsUpdate` module dependency
- No Microsoft Update Catalog lookups
