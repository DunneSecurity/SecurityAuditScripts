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
