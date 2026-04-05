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
