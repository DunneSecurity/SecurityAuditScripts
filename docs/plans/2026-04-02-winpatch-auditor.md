# Windows Patch Auditor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `winpatch_auditor.ps1` — a Windows on-premises patch currency auditor covering last-patch age, uptime/reboot state, Windows Update config, and live pending-update enumeration via the WUA COM API, with full JSON/CSV/HTML output and integration into `Run-Audit.ps1` and `exec_summary.py`.

**Architecture:** A single PowerShell script with no external module dependencies. Always-run checks use `Get-HotFix`, `Get-CimInstance`, `Get-Service`, and registry reads. The COM API path wraps `Microsoft.Update.Session` in an isolatable `New-UpdateSearcher` helper that Pester can Mock. `MaxSearchSeconds = 0` skips the COM path entirely. Returns `@{ findings = ...; summary = ... }` for clean output-layer consumption.

**Tech Stack:** PowerShell 5.1+/7, Pester 5, `System.Web` for HTML encoding.

**Spec:** `docs/specs/2026-04-02-winpatch-auditor-design.md`

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `OnPrem/Windows/winpatch-auditor/winpatch_auditor.ps1` | All audit logic, output writers, main entry |
| Create | `OnPrem/Windows/winpatch-auditor/tests/winpatch_auditor.Tests.ps1` | 16 Pester tests |
| Create | `OnPrem/Windows/winpatch-auditor/README.md` | Usage docs |
| Modify | `tools/exec_summary.py` | Add `winpatch_report.json` to 3 lists |
| Modify | `Run-Audit.ps1` | Add winpatch to `$WindowsAuditors` |
| Modify | `README.md` | Add row to Windows table, update diagram 7→8 |
| Modify | `OnPrem/README.md` | Add to directory tree and scripts table |

---

### Task 1: Scaffold — directory, param block, helpers, stubs, empty audit function

**Files:**
- Create: `OnPrem/Windows/winpatch-auditor/winpatch_auditor.ps1`
- Create: `OnPrem/Windows/winpatch-auditor/tests/winpatch_auditor.Tests.ps1`

- [ ] **Step 1: Create the auditor skeleton**

Create `OnPrem/Windows/winpatch-auditor/winpatch_auditor.ps1`:

```powershell
<#
.SYNOPSIS
    Audits Windows patch currency, update configuration, and uptime/reboot state.
.DESCRIPTION
    Read-only audit of Windows Update hygiene. Checks last patch age via Get-HotFix,
    system uptime via WMI, pending-reboot registry flags, Windows Update service state,
    automatic update policy, and optionally queries the Windows Update Agent COM API
    for pending security updates.
.PARAMETER Output
    Output file prefix (default: winpatch_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER MaxSearchSeconds
    Seconds to wait for the Windows Update COM API search. 0 skips the COM search
    entirely (safe for air-gapped or slow machines). Default: 60.
.EXAMPLE
    .\winpatch_auditor.ps1
    .\winpatch_auditor.ps1 -Format html
    .\winpatch_auditor.ps1 -MaxSearchSeconds 0 -Format json
#>
param(
    [string]$Output           = 'winpatch_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format           = 'all',
    [int]   $MaxSearchSeconds = 60
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------
function Get-SeverityLabel {
    param([int]$Score)
    if ($Score -ge 8) { return 'CRITICAL' }
    if ($Score -ge 6) { return 'HIGH' }
    if ($Score -ge 3) { return 'MEDIUM' }
    return 'LOW'
}

function Get-SeverityColour {
    param([string]$Severity)
    switch ($Severity) {
        'CRITICAL' { return '#dc3545' }
        'HIGH'     { return '#fd7e14' }
        'MEDIUM'   { return '#ffc107' }
        'LOW'      { return '#28a745' }
        default    { return '#6c757d' }
    }
}

# ---------------------------------------------------------------------------
# File permission helper
# ---------------------------------------------------------------------------
function Set-RestrictedPermissions {
    param([string]$Path)
    if ($IsLinux -or $IsMacOS) {
        & chmod 600 $Path
    } else {
        $acl = Get-Acl $Path
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            'FullControl', 'Allow')
        $acl.SetAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl
    }
}

# ---------------------------------------------------------------------------
# COM API wrapper — isolated for Pester Mocking
# ---------------------------------------------------------------------------
function New-UpdateSearcher {
    $session = New-Object -ComObject 'Microsoft.Update.Session'
    $session.CreateUpdateSearcher()
}

# ---------------------------------------------------------------------------
# Main audit function
# ---------------------------------------------------------------------------
function Get-WinPatchFindings {
    param([int]$MaxSearchSeconds = 60)

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $now = Get-Date

    $summary = @{
        hostname                 = $env:COMPUTERNAME
        last_patch_date          = $null
        days_since_patch         = $null
        last_reboot              = $null
        uptime_days              = $null
        pending_reboot           = $false
        windows_update_service   = 'Unknown'
        auto_update_enabled      = $true
        wsus_server              = $null
        pending_updates          = @{ critical = 0; important = 0; moderate = 0; low = 0; total = 0 }
        com_api_used             = $false
        overall_risk             = 'LOW'
    }

    # checks go here in later tasks

    # Compute overall risk
    if (@($findings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count -gt 0) { $summary.overall_risk = 'CRITICAL' }
    elseif (@($findings | Where-Object { $_.Severity -eq 'HIGH' }).Count -gt 0)     { $summary.overall_risk = 'HIGH' }
    elseif (@($findings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count -gt 0)   { $summary.overall_risk = 'MEDIUM' }

    return @{ findings = $findings; summary = $summary }
}

# ---------------------------------------------------------------------------
# Output helpers (stubs — implemented in Task 5)
# ---------------------------------------------------------------------------
function Write-JsonReport    { param($ReportData, $Path) }
function Write-CsvReport     { param($Findings, $Path) }
function Write-HtmlReport    { param($Findings, $Summary, $Path) }
function Write-TerminalSummary { param($Findings, $Summary) }

# ---------------------------------------------------------------------------
# Main — skipped when dot-sourced by Pester
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    $result   = Get-WinPatchFindings -MaxSearchSeconds $MaxSearchSeconds
    $findings = @($result.findings)
    $summary  = $result.summary

    $reportData = @{
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
        hostname     = $env:COMPUTERNAME
        summary      = $summary
        findings     = $findings
    }

    switch ($Format) {
        'json'   { Write-JsonReport -ReportData $reportData -Path "$Output.json"; Write-Host "JSON: $Output.json" }
        'csv'    { Write-CsvReport  -Findings $findings     -Path "$Output.csv";  Write-Host "CSV:  $Output.csv" }
        'html'   { Write-HtmlReport -Findings $findings -Summary $summary -Path "$Output.html"; Write-Host "HTML: $Output.html" }
        'all'    {
            Write-JsonReport -ReportData $reportData -Path "$Output.json"
            Write-CsvReport  -Findings $findings     -Path "$Output.csv"
            Write-HtmlReport -Findings $findings -Summary $summary -Path "$Output.html"
            Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
        }
        'stdout' { $reportData | ConvertTo-Json -Depth 10 }
        default  { Write-Error "Unknown format '$Format'"; exit 1 }
    }

    Write-TerminalSummary -Findings $findings -Summary $summary
}
```

- [ ] **Step 2: Create the test skeleton**

Create `OnPrem/Windows/winpatch-auditor/tests/winpatch_auditor.Tests.ps1`:

```powershell
# OnPrem/Windows/winpatch-auditor/tests/winpatch_auditor.Tests.ps1
BeforeAll {
    . "$PSScriptRoot/../winpatch_auditor.ps1"
}

Describe 'Get-WinPatchFindings' {
    # tests added in Tasks 2–4
}

Describe 'Get-SeverityLabel' {
    It 'returns CRITICAL for score 8+' {
        Get-SeverityLabel 9 | Should -Be 'CRITICAL'
    }
    It 'returns HIGH for score 6-7' {
        Get-SeverityLabel 7 | Should -Be 'HIGH'
    }
    It 'returns MEDIUM for score 3-5' {
        Get-SeverityLabel 4 | Should -Be 'MEDIUM'
    }
    It 'returns LOW for score 0-2' {
        Get-SeverityLabel 1 | Should -Be 'LOW'
    }
}
```

- [ ] **Step 3: Commit scaffold**

```bash
git add OnPrem/Windows/winpatch-auditor/
git commit -m "feat(winpatch): scaffold auditor and test skeleton"
```

---

### Task 2: PATCH-01 (last patch age) and PATCH-02 (uptime) — tests then implementation

**Files:**
- Modify: `OnPrem/Windows/winpatch-auditor/winpatch_auditor.ps1`
- Modify: `OnPrem/Windows/winpatch-auditor/tests/winpatch_auditor.Tests.ps1`

- [ ] **Step 1: Add PATCH-01 and PATCH-02 tests**

Replace the `# tests added in Tasks 2–4` comment in the Describe block with:

```powershell
    # ── PATCH-01: Last patch age ──────────────────────────────────────────────

    It '1. PATCH-01 flags CRITICAL when last patch > 60 days ago' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-65); HotFixID = 'KB111111' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }
        Mock New-UpdateSearcher { throw 'skip' }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'LastPatchAge'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
        $finding.Score    | Should -Be 9
    }

    It '2. PATCH-01 flags HIGH when last patch 31-60 days ago' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-45); HotFixID = 'KB222222' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'LastPatchAge'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $finding.Score    | Should -Be 7
    }

    It '3. PATCH-01 flags MEDIUM when last patch 15-30 days ago' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-20); HotFixID = 'KB333333' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'LastPatchAge'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
        $finding.Score    | Should -Be 4
    }

    It '4. PATCH-01 produces no finding when last patch <= 14 days ago' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-7); HotFixID = 'KB444444' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'LastPatchAge'
        $finding | Should -BeNullOrEmpty
    }

    It '5. PATCH-01 flags CRITICAL when no hotfixes found' {
        Mock Get-HotFix { @() }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'LastPatchAge'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
    }

    # ── PATCH-02: Uptime ──────────────────────────────────────────────────────

    It '6. PATCH-02 flags HIGH when uptime > 60 days' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB555555' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-65) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'UptimeExceeded'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $finding.Score    | Should -Be 7
    }

    It '7. PATCH-02 flags MEDIUM when uptime 31-60 days' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB666666' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-45) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'UptimeExceeded'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
        $finding.Score    | Should -Be 4
    }

    It '8. PATCH-02 produces no finding when uptime <= 30 days' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB777777' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-10) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'UptimeExceeded'
        $finding | Should -BeNullOrEmpty
    }
```

- [ ] **Step 2: Implement PATCH-01 and PATCH-02 in `Get-WinPatchFindings`**

Replace `# checks go here in later tasks` with:

```powershell
    # ------------------------------------------------------------------
    # PATCH-01: Last patch age
    # ------------------------------------------------------------------
    try {
        $hotfixes = @(Get-HotFix | Where-Object { $null -ne $_.InstalledOn } | Sort-Object InstalledOn -Descending)
        if ($hotfixes.Count -eq 0) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'LastPatchAge'
                Resource       = 'System'
                Severity       = 'CRITICAL'
                Score          = 9
                Description    = 'No installed hotfixes found. The system may have never been patched or patch history is unavailable.'
                Recommendation = 'Run Windows Update immediately and ensure the Windows Update service is enabled.'
                cis_control    = 7
            })
        } else {
            $lastPatch   = $hotfixes[0]
            $daysSince   = [int]($now - $lastPatch.InstalledOn).TotalDays
            $summary.last_patch_date  = $lastPatch.InstalledOn.ToString('yyyy-MM-dd')
            $summary.days_since_patch = $daysSince

            if ($daysSince -gt 60) {
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'LastPatchAge'
                    Resource       = 'System'
                    Severity       = 'CRITICAL'
                    Score          = 9
                    Description    = "Last patch installed $daysSince days ago ($($lastPatch.InstalledOn.ToString('yyyy-MM-dd'))). Systems should be patched at least monthly."
                    Recommendation = 'Run Windows Update immediately. Enable automatic updates or establish a monthly patch cycle aligned with Microsoft Patch Tuesday.'
                    cis_control    = 7
                })
            } elseif ($daysSince -gt 30) {
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'LastPatchAge'
                    Resource       = 'System'
                    Severity       = 'HIGH'
                    Score          = 7
                    Description    = "Last patch installed $daysSince days ago ($($lastPatch.InstalledOn.ToString('yyyy-MM-dd'))). Monthly patching recommended."
                    Recommendation = 'Run Windows Update and establish a monthly patch cycle aligned with Microsoft Patch Tuesday.'
                    cis_control    = 7
                })
            } elseif ($daysSince -gt 14) {
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'LastPatchAge'
                    Resource       = 'System'
                    Severity       = 'MEDIUM'
                    Score          = 4
                    Description    = "Last patch installed $daysSince days ago ($($lastPatch.InstalledOn.ToString('yyyy-MM-dd')))."
                    Recommendation = 'Check for new updates. Consider enabling automatic updates to maintain timely patch coverage.'
                    cis_control    = 7
                })
            }
        }
    } catch {
        Write-Warning "Could not check hotfix history: $_"
    }

    # ------------------------------------------------------------------
    # PATCH-02: Uptime / last reboot
    # ------------------------------------------------------------------
    try {
        $os        = Get-CimInstance -ClassName Win32_OperatingSystem
        $lastBoot  = $os.LastBootUpTime
        $uptime    = [int]($now - $lastBoot).TotalDays
        $summary.last_reboot  = $lastBoot.ToString('yyyy-MM-dd')
        $summary.uptime_days  = $uptime

        if ($uptime -gt 60) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'UptimeExceeded'
                Resource       = 'System'
                Severity       = 'HIGH'
                Score          = 7
                Description    = "System has been running for $uptime days without a reboot (last reboot: $($lastBoot.ToString('yyyy-MM-dd'))). Patches requiring a reboot have not been fully applied."
                Recommendation = 'Schedule a reboot in the next maintenance window. Ensure systems are rebooted at least monthly after Patch Tuesday.'
                cis_control    = 7
            })
        } elseif ($uptime -gt 30) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'UptimeExceeded'
                Resource       = 'System'
                Severity       = 'MEDIUM'
                Score          = 4
                Description    = "System has been running for $uptime days without a reboot (last reboot: $($lastBoot.ToString('yyyy-MM-dd')))."
                Recommendation = 'Schedule a maintenance window reboot to apply any pending updates.'
                cis_control    = 7
            })
        }
    } catch {
        Write-Warning "Could not check system uptime: $_"
    }
```

- [ ] **Step 3: Verify tests pass (run in Pester / CI)**

```powershell
Invoke-Pester OnPrem/Windows/winpatch-auditor/tests/ -Output Detailed
```

Expected: severity helper tests pass, tests 1–8 pass.

Also verify Python suite unaffected:

```bash
python3 -m pytest --import-mode=importlib -q
```

Expected: `894 passed`

- [ ] **Step 4: Commit**

```bash
git add OnPrem/Windows/winpatch-auditor/
git commit -m "feat(winpatch): PATCH-01 last-patch-age and PATCH-02 uptime checks"
```

---

### Task 3: PATCH-03–06 — registry checks (reboot, WU service, auto-update, WSUS)

**Files:**
- Modify: `OnPrem/Windows/winpatch-auditor/winpatch_auditor.ps1`
- Modify: `OnPrem/Windows/winpatch-auditor/tests/winpatch_auditor.Tests.ps1`

- [ ] **Step 1: Add PATCH-03 through PATCH-06 tests**

Append to the `Describe 'Get-WinPatchFindings'` block (after test 8):

```powershell
    # ── PATCH-03: Pending reboot ──────────────────────────────────────────────

    It '9. PATCH-03 flags HIGH when RebootRequired registry key exists' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB999999' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty {
            param($Path, $Name)
            # Return a non-null object for the RebootRequired WU key path
            if ($Path -like '*WindowsUpdate*Auto Update*RebootRequired*') {
                return [PSCustomObject]@{}
            }
            return $null
        }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'PendingRebootRequired'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $finding.Score    | Should -Be 7
        $result.summary.pending_reboot | Should -Be $true
    }

    It '10. PATCH-03 produces no finding when no reboot-pending keys present' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB888888' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'PendingRebootRequired'
        $finding | Should -BeNullOrEmpty
        $result.summary.pending_reboot | Should -Be $false
    }

    # ── PATCH-04: WU service disabled ─────────────────────────────────────────

    It '11. PATCH-04 flags HIGH when wuauserv is disabled' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB777000' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service {
            [PSCustomObject]@{ Name = 'wuauserv'; Status = 'Stopped'; StartType = 'Disabled' }
        }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'WindowsUpdateServiceDisabled'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'HIGH'
        $finding.Score    | Should -Be 8
    }

    It '12. PATCH-04 produces no finding when wuauserv is running' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB666000' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service {
            [PSCustomObject]@{ Name = 'wuauserv'; Status = 'Running'; StartType = 'Automatic' }
        }
        Mock Get-ItemProperty { $null }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'WindowsUpdateServiceDisabled'
        $finding | Should -BeNullOrEmpty
    }

    # ── PATCH-05: Auto-update disabled ────────────────────────────────────────

    It '13. PATCH-05 flags MEDIUM when AUOptions = 1 (disabled)' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB555000' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty {
            param($Path, $Name)
            if ($Path -like '*WindowsUpdate*AU*' -and $Name -eq 'AUOptions') {
                return [PSCustomObject]@{ AUOptions = 1 }
            }
            return $null
        }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 0
        $finding = $result.findings | Where-Object FindingType -eq 'AutoUpdateDisabled'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
        $finding.Score    | Should -Be 5
        $result.summary.auto_update_enabled | Should -Be $false
    }
```

- [ ] **Step 2: Implement PATCH-03 through PATCH-06**

Append to `Get-WinPatchFindings` after the PATCH-02 block:

```powershell
    # ------------------------------------------------------------------
    # PATCH-03: Pending reboot required
    # ------------------------------------------------------------------
    try {
        $rebootRequired = $false

        $wuReboot = Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' `
            -ErrorAction SilentlyContinue
        if ($null -ne $wuReboot) { $rebootRequired = $true }

        $pfroKey = Get-ItemProperty `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
            -Name 'PendingFileRenameOperations' `
            -ErrorAction SilentlyContinue
        if ($null -ne $pfroKey -and $null -ne $pfroKey.PendingFileRenameOperations) { $rebootRequired = $true }

        $sdReboot = Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareDistribution\RebootRequired' `
            -ErrorAction SilentlyContinue
        if ($null -ne $sdReboot) { $rebootRequired = $true }

        $summary.pending_reboot = $rebootRequired

        if ($rebootRequired) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'PendingRebootRequired'
                Resource       = 'System'
                Severity       = 'HIGH'
                Score          = 7
                Description    = 'A system reboot is required to complete the installation of one or more updates. The system is not fully patched until rebooted.'
                Recommendation = 'Schedule a reboot during the next available maintenance window to complete pending update installation.'
                cis_control    = 7
            })
        }
    } catch {
        Write-Warning "Could not check pending reboot status: $_"
    }

    # ------------------------------------------------------------------
    # PATCH-04: Windows Update service disabled
    # ------------------------------------------------------------------
    try {
        $wuSvc = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
        $summary.windows_update_service = if ($null -ne $wuSvc) { $wuSvc.Status.ToString() } else { 'Unknown' }

        if ($null -ne $wuSvc -and $wuSvc.StartType -eq 'Disabled') {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'WindowsUpdateServiceDisabled'
                Resource       = 'wuauserv'
                Severity       = 'HIGH'
                Score          = 8
                Description    = 'The Windows Update service (wuauserv) is disabled. This machine cannot receive security updates automatically.'
                Recommendation = "Enable the Windows Update service: Set-Service -Name 'wuauserv' -StartupType Automatic; Start-Service 'wuauserv'"
                cis_control    = 7
            })
        }
    } catch {
        Write-Warning "Could not check Windows Update service: $_"
    }

    # ------------------------------------------------------------------
    # PATCH-05: Auto-update disabled via policy
    # ------------------------------------------------------------------
    try {
        $auPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        $auKey  = Get-ItemProperty -Path $auPath -Name 'AUOptions' -ErrorAction SilentlyContinue
        $auOptions = if ($null -ne $auKey) { $auKey.AUOptions } else { $null }
        $summary.auto_update_enabled = ($null -eq $auOptions -or $auOptions -notin @(1, 2))

        if ($auOptions -eq 1 -or $auOptions -eq 2) {
            $optionText = if ($auOptions -eq 1) { 'disabled (AUOptions=1)' } else { 'notify-only, no auto-download (AUOptions=2)' }
            $findings.Add([PSCustomObject]@{
                FindingType    = 'AutoUpdateDisabled'
                Resource       = 'Windows Update Policy'
                Severity       = 'MEDIUM'
                Score          = 5
                Description    = "Automatic updates are $optionText. Updates are not being downloaded or installed automatically."
                Recommendation = 'Set AUOptions to 4 (auto-download and schedule install) via Group Policy: Computer Configuration → Administrative Templates → Windows Components → Windows Update → Configure Automatic Updates.'
                cis_control    = 7
            })
        }
    } catch {
        Write-Warning "Could not check auto-update policy: $_"
    }

    # ------------------------------------------------------------------
    # PATCH-06: WSUS server configured (informational)
    # ------------------------------------------------------------------
    try {
        $wuPath     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        $wuKey      = Get-ItemProperty -Path $wuPath -Name 'WUServer' -ErrorAction SilentlyContinue
        $wsusServer = if ($null -ne $wuKey -and $null -ne $wuKey.WUServer -and $wuKey.WUServer -ne '') {
            $wuKey.WUServer
        } else { $null }
        $summary.wsus_server = $wsusServer

        if ($null -ne $wsusServer) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'WsusConfigured'
                Resource       = $wsusServer
                Severity       = 'LOW'
                Score          = 0
                Description    = "Updates are sourced from WSUS server: $wsusServer. Verify this server is actively maintained and approving security updates promptly."
                Recommendation = 'Ensure WSUS approves critical and security updates within 30 days of release. Confirm all machines can reach the WSUS server.'
                cis_control    = 7
            })
        }
    } catch {
        Write-Warning "Could not check WSUS configuration: $_"
    }
```

- [ ] **Step 3: Verify tests pass**

```powershell
Invoke-Pester OnPrem/Windows/winpatch-auditor/tests/ -Output Detailed
```

Expected: tests 1–13 pass.

```bash
python3 -m pytest --import-mode=importlib -q
```

Expected: `894 passed`

- [ ] **Step 4: Commit**

```bash
git add OnPrem/Windows/winpatch-auditor/
git commit -m "feat(winpatch): PATCH-03 to PATCH-06 registry checks"
```

---

### Task 4: PATCH-07/08 — Windows Update COM API (pending updates + failure)

**Files:**
- Modify: `OnPrem/Windows/winpatch-auditor/winpatch_auditor.ps1`
- Modify: `OnPrem/Windows/winpatch-auditor/tests/winpatch_auditor.Tests.ps1`

- [ ] **Step 1: Add PATCH-07 and PATCH-08 tests**

Append to the `Describe 'Get-WinPatchFindings'` block:

```powershell
    # ── PATCH-07: Pending security updates via COM API ────────────────────────

    It '14. PATCH-07 flags CRITICAL when COM API returns a Critical pending update' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB100' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }
        Mock New-UpdateSearcher {
            $fakeUpdate = [PSCustomObject]@{ MsrcSeverity = 'Critical'; Title = 'Critical Security Update' }
            $fakeResult = [PSCustomObject]@{ Updates = @($fakeUpdate) }
            $fakeSearcher = [PSCustomObject]@{}
            $fakeSearcher | Add-Member -MemberType ScriptMethod -Name Search -Value { param($criteria) $fakeResult }
            return $fakeSearcher
        }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 60
        $finding = $result.findings | Where-Object FindingType -eq 'PendingSecurityUpdates'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'CRITICAL'
        $finding.Score    | Should -Be 9
        $result.summary.com_api_used | Should -Be $true
        $result.summary.pending_updates.critical | Should -Be 1
    }

    It '15. PATCH-07 produces no PendingSecurityUpdates finding when COM API returns empty' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB200' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }
        Mock New-UpdateSearcher {
            $fakeResult   = [PSCustomObject]@{ Updates = @() }
            $fakeSearcher = [PSCustomObject]@{}
            $fakeSearcher | Add-Member -MemberType ScriptMethod -Name Search -Value { param($criteria) $fakeResult }
            return $fakeSearcher
        }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 60
        $finding = $result.findings | Where-Object FindingType -eq 'PendingSecurityUpdates'
        $finding | Should -BeNullOrEmpty
        $result.summary.com_api_used          | Should -Be $true
        $result.summary.pending_updates.total | Should -Be 0
    }

    # ── PATCH-08: COM API failure ─────────────────────────────────────────────

    It '16. PATCH-08 flags MEDIUM when COM API throws' {
        Mock Get-HotFix {
            @([PSCustomObject]@{ InstalledOn = (Get-Date).AddDays(-5); HotFixID = 'KB300' })
        }
        Mock Get-CimInstance { [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) } }
        Mock Get-Service { [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
        Mock Get-ItemProperty { $null }
        Mock New-UpdateSearcher { throw 'COM object not available' }

        $result  = Get-WinPatchFindings -MaxSearchSeconds 60
        $finding = $result.findings | Where-Object FindingType -eq 'WindowsUpdateQueryFailed'
        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'MEDIUM'
        $finding.Score    | Should -Be 4
        $result.summary.com_api_used | Should -Be $false
    }
```

- [ ] **Step 2: Implement PATCH-07 and PATCH-08**

Append to `Get-WinPatchFindings` after the PATCH-06 block:

```powershell
    # ------------------------------------------------------------------
    # PATCH-07/08: Pending updates via Windows Update Agent COM API
    # ------------------------------------------------------------------
    if ($MaxSearchSeconds -gt 0) {
        try {
            $searcher = New-UpdateSearcher
            $criteria = 'IsInstalled=0 AND IsHidden=0 AND Type=''Software'''
            $searchResult = $searcher.Search($criteria)

            $pendingCounts = @{ critical = 0; important = 0; moderate = 0; low = 0; total = 0 }
            foreach ($update in $searchResult.Updates) {
                $pendingCounts.total++
                switch ($update.MsrcSeverity) {
                    'Critical'  { $pendingCounts.critical++ }
                    'Important' { $pendingCounts.important++ }
                    'Moderate'  { $pendingCounts.moderate++ }
                    default     { $pendingCounts.low++ }
                }
            }
            $summary.pending_updates = $pendingCounts
            $summary.com_api_used    = $true

            if ($pendingCounts.critical -gt 0) {
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'PendingSecurityUpdates'
                    Resource       = 'Windows Update'
                    Severity       = 'CRITICAL'
                    Score          = 9
                    Description    = "$($pendingCounts.total) pending update(s): $($pendingCounts.critical) Critical, $($pendingCounts.important) Important, $($pendingCounts.moderate) Moderate."
                    Recommendation = 'Run Windows Update immediately and reboot to apply critical security patches.'
                    cis_control    = 7
                })
            } elseif ($pendingCounts.important -gt 0) {
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'PendingSecurityUpdates'
                    Resource       = 'Windows Update'
                    Severity       = 'HIGH'
                    Score          = 7
                    Description    = "$($pendingCounts.total) pending update(s): $($pendingCounts.important) Important, $($pendingCounts.moderate) Moderate."
                    Recommendation = 'Schedule Windows Update installation and plan a reboot within the next maintenance window.'
                    cis_control    = 7
                })
            } elseif ($pendingCounts.moderate -gt 0) {
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'PendingSecurityUpdates'
                    Resource       = 'Windows Update'
                    Severity       = 'MEDIUM'
                    Score          = 4
                    Description    = "$($pendingCounts.total) pending update(s): $($pendingCounts.moderate) Moderate."
                    Recommendation = 'Run Windows Update to apply pending moderate-severity updates.'
                    cis_control    = 7
                })
            }
        } catch {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'WindowsUpdateQueryFailed'
                Resource       = 'Windows Update COM API'
                Severity       = 'MEDIUM'
                Score          = 4
                Description    = "Could not query Windows Update for pending patches: $_"
                Recommendation = 'Ensure the Windows Update service (wuauserv) is running. Use -MaxSearchSeconds 0 to skip this check on air-gapped machines.'
                cis_control    = 7
            })
        }
    }
```

- [ ] **Step 3: Verify all 16 tests pass**

```powershell
Invoke-Pester OnPrem/Windows/winpatch-auditor/tests/ -Output Detailed
```

Expected: all 16 tests + 4 severity helper tests pass (20 total).

```bash
python3 -m pytest --import-mode=importlib -q
```

Expected: `894 passed`

- [ ] **Step 4: Commit**

```bash
git add OnPrem/Windows/winpatch-auditor/
git commit -m "feat(winpatch): PATCH-07/08 COM API pending-update and failure checks"
```

---

### Task 5: Output layer — JSON, CSV, HTML, terminal summary, main entry

**Files:**
- Modify: `OnPrem/Windows/winpatch-auditor/winpatch_auditor.ps1`

- [ ] **Step 1: Replace the four output stubs with full implementations**

Replace the four stub function definitions (`Write-JsonReport`, `Write-CsvReport`, `Write-HtmlReport`, `Write-TerminalSummary`) with:

```powershell
# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Write-JsonReport {
    param([Parameter(Mandatory)][hashtable]$ReportData, [string]$Path)
    $ReportData | ConvertTo-Json -Depth 10 | Out-File $Path -Encoding UTF8
    Set-RestrictedPermissions $Path
}

function Write-CsvReport {
    param([Parameter(Mandatory)][array]$Findings, [string]$Path)
    $Findings | Select-Object FindingType, Resource, Severity, Score, Description, Recommendation, cis_control |
        ConvertTo-Csv -NoTypeInformation | Out-File $Path -Encoding UTF8
    Set-RestrictedPermissions $Path
}

function Write-HtmlReport {
    param(
        [Parameter(Mandatory)][array]$Findings,
        [hashtable]$Summary = @{},
        [string]$Path
    )
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    $daysSince   = if ($null -ne $Summary.days_since_patch) { "$($Summary.days_since_patch)d ago" } else { 'Unknown' }
    $lastPatch   = if ($null -ne $Summary.last_patch_date)  { $Summary.last_patch_date }  else { 'Unknown' }
    $lastReboot  = if ($null -ne $Summary.last_reboot)      { $Summary.last_reboot }      else { 'Unknown' }
    $uptimeDays  = if ($null -ne $Summary.uptime_days)      { "$($Summary.uptime_days)d" } else { 'Unknown' }
    $pendingTotal = $Summary.pending_updates.total
    $rebootFlag  = if ($Summary.pending_reboot) { 'Yes' } else { 'No' }
    $rebootColour = if ($Summary.pending_reboot) { '#dc3545' } else { '#28a745' }
    $patchColour  = if ($counts.CRITICAL -gt 0) { '#dc3545' } elseif ($counts.HIGH -gt 0) { '#fd7e14' } else { '#28a745' }
    $scannedAt   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'

    $rows = foreach ($f in $Findings) {
        $colour = Get-SeverityColour $f.Severity
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Resource))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Description))</td>
            <td><span style='background:$colour;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold'>$($f.Severity)</span></td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Score))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</td>
        </tr>"
    }

    $html = @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Windows Patch Audit Report</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
.header{background:#1a1a2e;color:#fff;padding:30px 40px}
.header h1{margin:0;font-size:1.8em}.header p{margin:5px 0 0;opacity:0.8}
.cards{display:flex;gap:16px;flex-wrap:wrap;padding:20px 40px}
.card{background:#fff;border-radius:8px;padding:16px 24px;box-shadow:0 2px 8px rgba(0,0,0,0.08);min-width:130px;text-align:center}
.val{font-size:2em;font-weight:bold}.lbl{color:#666;font-size:.85em;margin-top:4px}
.tbl-wrap{padding:0 40px 20px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)}
th{background:#1a1a2e;color:#fff;padding:12px 15px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px}
td{padding:10px 15px;border-bottom:1px solid #ecf0f1;vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:#f8f9ff}
.footer{text-align:center;padding:20px;color:#999;font-size:0.85em}
</style></head><body>
<div class='header'><h1>Windows Patch Audit Report</h1>
<p>Host: $($Summary.hostname) &nbsp;|&nbsp; Generated: $scannedAt</p>
</div>
<div class='cards'>
  <div class='card'><div class='val' style='color:$patchColour'>$lastPatch</div><div class='lbl'>Last Patched ($daysSince)</div></div>
  <div class='card'><div class='val'>$uptimeDays</div><div class='lbl'>Uptime (last reboot: $lastReboot)</div></div>
  <div class='card'><div class='val' style='color:$rebootColour'>$rebootFlag</div><div class='lbl'>Pending Reboot</div></div>
  <div class='card'><div class='val'>$pendingTotal</div><div class='lbl'>Pending Updates</div></div>
  <div class='card'><div class='val' style='color:#dc3545'>$($counts.CRITICAL)</div><div class='lbl'>CRITICAL</div></div>
  <div class='card'><div class='val' style='color:#fd7e14'>$($counts.HIGH)</div><div class='lbl'>HIGH</div></div>
  <div class='card'><div class='val' style='color:#ffc107'>$($counts.MEDIUM)</div><div class='lbl'>MEDIUM</div></div>
  <div class='card'><div class='val' style='color:#28a745'>$($counts.LOW)</div><div class='lbl'>LOW</div></div>
</div>
<div class='tbl-wrap'>
<table><thead><tr>
  <th>Finding</th><th>Resource</th><th>Detail</th>
  <th>Severity</th><th>Score</th><th>Recommendation</th>
</tr></thead><tbody>
$($rows -join "`n")
</tbody></table>
</div>
<div class='footer'>Windows Patch Audit Report | Generated $scannedAt</div>
</body></html>
"@
    $html | Out-File $Path -Encoding UTF8
    Set-RestrictedPermissions $Path
}

function Write-TerminalSummary {
    param([array]$Findings, [hashtable]$Summary)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    $lastPatch  = if ($null -ne $Summary.last_patch_date) { "$($Summary.last_patch_date) ($($Summary.days_since_patch) days ago)" } else { 'Unknown' }
    $reboot     = if ($Summary.pending_reboot) { 'Yes' } else { 'No' }
    $pending    = $Summary.pending_updates
    $pendingStr = if ($Summary.com_api_used) {
        "$($pending.total) ($($pending.critical) Critical, $($pending.important) Important, $($pending.moderate) Moderate)"
    } else { 'Not queried (use -MaxSearchSeconds > 0)' }

    Write-Host ''
    Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host '     WINDOWS PATCH AUDIT COMPLETE                     ' -ForegroundColor Cyan
    Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host "  Hostname        : $($Summary.hostname)"              -ForegroundColor Cyan
    Write-Host "  Last patched    : $lastPatch"                        -ForegroundColor Cyan
    Write-Host "  Uptime          : $($Summary.uptime_days) days (last reboot: $($Summary.last_reboot))" -ForegroundColor Cyan
    Write-Host "  Pending reboot  : $reboot"                           -ForegroundColor Cyan
    Write-Host "  Pending updates : $pendingStr"                       -ForegroundColor Cyan
    Write-Host "  Findings        : $($Findings.Count)"                -ForegroundColor Cyan
    Write-Host "  CRITICAL: $($counts.CRITICAL)  HIGH: $($counts.HIGH)  MEDIUM: $($counts.MEDIUM)  LOW: $($counts.LOW)" -ForegroundColor Cyan
    Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host ''
}
```

- [ ] **Step 2: Update the main entry block**

Replace the placeholder main block with the full version:

```powershell
if ($MyInvocation.InvocationName -ne '.') {
    $result   = Get-WinPatchFindings -MaxSearchSeconds $MaxSearchSeconds
    $findings = @($result.findings)
    $summary  = $result.summary

    $reportData = @{
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
        hostname     = $env:COMPUTERNAME
        summary      = $summary
        findings     = $findings
    }

    switch ($Format) {
        'json' {
            Write-JsonReport -ReportData $reportData -Path "$Output.json"
            Write-Host "JSON: $Output.json"
        }
        'csv' {
            Write-CsvReport -Findings $findings -Path "$Output.csv"
            Write-Host "CSV: $Output.csv"
        }
        'html' {
            Write-HtmlReport -Findings $findings -Summary $summary -Path "$Output.html"
            Write-Host "HTML: $Output.html"
        }
        'all' {
            Write-JsonReport -ReportData $reportData -Path "$Output.json"
            Write-CsvReport  -Findings $findings     -Path "$Output.csv"
            Write-HtmlReport -Findings $findings -Summary $summary -Path "$Output.html"
            Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
        }
        'stdout' { $reportData | ConvertTo-Json -Depth 10 }
        default  { Write-Error "Unknown format '$Format'"; exit 1 }
    }

    Write-TerminalSummary -Findings $findings -Summary $summary
}
```

- [ ] **Step 3: Verify tests still pass**

```powershell
Invoke-Pester OnPrem/Windows/winpatch-auditor/tests/ -Output Detailed
```

Expected: all 20 tests pass.

```bash
python3 -m pytest --import-mode=importlib -q
```

Expected: `894 passed`

- [ ] **Step 4: Commit**

```bash
git add OnPrem/Windows/winpatch-auditor/winpatch_auditor.ps1
git commit -m "feat(winpatch): output layer — JSON, CSV, HTML, terminal summary"
```

---

### Task 6: exec_summary.py integration

**Files:**
- Modify: `tools/exec_summary.py`

- [ ] **Step 1: Add `winpatch_report.json` to KNOWN_PATTERNS**

In `tools/exec_summary.py`, find the line:

```python
    # Windows on-prem
    "laps_report.json",
]
```

Replace with:

```python
    # Windows on-prem
    "laps_report.json",
    "winpatch_report.json",
]
```

- [ ] **Step 2: Add to AZURE_WINDOWS_PATTERNS**

Find:

```python
    "laps_report.json",
]
```

(the closing of the `AZURE_WINDOWS_PATTERNS` list — it's the second occurrence). Replace with:

```python
    "laps_report.json",
    "winpatch_report.json",
]
```

- [ ] **Step 3: Add to PILLAR_LABELS**

Find:

```python
    "laps": "Windows LAPS",
}
```

Replace with:

```python
    "laps": "Windows LAPS",
    "winpatch": "Windows Patch Status",
}
```

- [ ] **Step 4: Run pytest to verify no regressions**

```bash
python3 -m pytest --import-mode=importlib -q
```

Expected: `894 passed` (exec_summary has its own tests — they must stay green).

- [ ] **Step 5: Commit**

```bash
git add tools/exec_summary.py
git commit -m "feat(winpatch): wire winpatch_report.json into exec_summary"
```

---

### Task 7: Run-Audit.ps1 integration

**Files:**
- Modify: `Run-Audit.ps1`

- [ ] **Step 1: Add winpatch to `$WindowsAuditors`**

In `Run-Audit.ps1`, find:

```powershell
$WindowsAuditors = @(
    @{ Name = 'laps';         Script = 'OnPrem\Windows\laps-auditor\laps_auditor.ps1';        Prefix = 'laps_report';         AllSubs = $false }
)
```

Replace with:

```powershell
$WindowsAuditors = @(
    @{ Name = 'laps';         Script = 'OnPrem\Windows\laps-auditor\laps_auditor.ps1';        Prefix = 'laps_report';         AllSubs = $false }
    @{ Name = 'winpatch';     Script = 'OnPrem\Windows\winpatch-auditor\winpatch_auditor.ps1'; Prefix = 'winpatch_report';     AllSubs = $false }
)
```

- [ ] **Step 2: Run pytest**

```bash
python3 -m pytest --import-mode=importlib -q
```

Expected: `894 passed`

- [ ] **Step 3: Commit**

```bash
git add Run-Audit.ps1
git commit -m "feat(winpatch): add winpatch to Run-Audit.ps1 Windows auditor group"
```

---

### Task 8: README, docs, and final push

**Files:**
- Create: `OnPrem/Windows/winpatch-auditor/README.md`
- Modify: `README.md`
- Modify: `OnPrem/README.md`

- [ ] **Step 1: Create `OnPrem/Windows/winpatch-auditor/README.md`**

```markdown
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
```

- [ ] **Step 2: Update root `README.md` — Windows table and diagram**

In `README.md`, find the Windows table row for LAPS:

```markdown
| [LAPS Auditor](./OnPrem/Windows/laps-auditor/) | Checks LAPS deployment coverage across domain-joined computers — managed vs unmanaged machines, password age, and expiry configuration. | JSON, CSV, HTML |
```

Append after it:

```markdown
| [Windows Patch Auditor](./OnPrem/Windows/winpatch-auditor/) | Checks last patch age via `Get-HotFix`, system uptime and reboot state, Windows Update service and auto-update policy, and enumerates pending security updates via the Windows Update Agent COM API. | JSON, CSV, HTML |
```

In the Mermaid diagram, find:

```
    subgraph Windows["🪟 Windows  —  7 auditors  (PowerShell)"]
        W["AD · Local Users · Firewall · SMB Signing\nAudit Policy · BitLocker · LAPS"]
    end
```

Replace with:

```
    subgraph Windows["🪟 Windows  —  8 auditors  (PowerShell)"]
        W["AD · Local Users · Firewall · SMB Signing\nAudit Policy · BitLocker · LAPS · Patch"]
    end
```

- [ ] **Step 3: Update `OnPrem/README.md`**

Find:

```
│   └── laps-auditor/         # LAPS deployment coverage and configuration
```

Replace with:

```
│   ├── laps-auditor/         # LAPS deployment coverage and configuration
│   └── winpatch-auditor/     # Patch currency, uptime, WU config, pending updates
```

Find:

```
| [laps_auditor.ps1](./Windows/laps-auditor/) | Windows | Yes (domain-joined) | PowerShell |
```

Append after it:

```
| [winpatch_auditor.ps1](./Windows/winpatch-auditor/) | Windows | No | PowerShell |
```

- [ ] **Step 4: Run pytest one final time**

```bash
python3 -m pytest --import-mode=importlib -q
```

Expected: `894 passed`

- [ ] **Step 5: Commit and push**

```bash
git add OnPrem/Windows/winpatch-auditor/README.md README.md OnPrem/README.md
git commit -m "feat(winpatch): README docs and diagram update (Windows 7→8 auditors)"
git push origin main
```
