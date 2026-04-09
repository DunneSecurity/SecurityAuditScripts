<#
.SYNOPSIS
    Audits SharePoint Online and OneDrive external sharing configuration.
.DESCRIPTION
    Read-only audit of SharePoint Online sharing posture:
    - SP-01: Tenant external sharing allows anonymous links
    - SP-02: Anonymous links have no expiry
    - SP-03: Sites more permissive than tenant default
    - SP-04: OneDrive external sharing unrestricted
    - SP-05: Default sharing link type is anonymous
    - SP-06: External sharing not restricted to specific domains
.PARAMETER Output
    Output file prefix (default: sharepoint_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER TenantDomain
    Primary tenant domain (e.g. contoso.com)
.EXAMPLE
    .\sharepoint_auditor.ps1 -TenantDomain contoso.com
#>
param(
    [string]$Output       = 'sharepoint_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format       = 'all',
    [string]$TenantDomain = ''
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# SPO / Graph / Az stubs — overridden by real modules; Pester mocks these
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-SPOTenant' -ErrorAction SilentlyContinue)) {
    function Connect-MgGraph    { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext      { $null }
    function Connect-SPOService { param($Url) }
    function Get-SPOTenant      { $null }
    function Get-SPOSite        { param($IncludePersonalSite, $Limit) @() }
    function Disconnect-SPOService { }
}
if (-not (Get-Command -Name 'Get-AzContext' -ErrorAction SilentlyContinue)) {
    function Get-AzContext { @{ Tenant = @{ Id = '' }; Account = @{ Id = '' } } }
}

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
# SP-01, SP-02, SP-04, SP-05, SP-06: Tenant-level sharing settings
# ---------------------------------------------------------------------------
function Get-SharePointTenantFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $tenant = Get-SPOTenant
    if ($null -eq $tenant) { return $findings }

    # SP-01: Anonymous ("Anyone") sharing enabled at tenant level
    if ($tenant.SharingCapability -eq 'ExternalUserAndGuestSharing') {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'TenantExternalSharingAnyone'
            Resource       = 'tenant'
            Score          = 8
            Severity       = 'CRITICAL'
            CisControl     = 'CIS 3'
            Recommendation = "Restrict tenant sharing to 'New and existing guests' or stricter: " +
                             "SharePoint admin centre → Policies → Sharing → External sharing → " +
                             "SharePoint: change from 'Anyone' to 'New and existing guests'."
        })
    }

    # SP-02: No expiry set on anonymous links
    if ($tenant.RequireAnonymousLinksExpireInDays -le 0) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'AnonymousLinkNoExpiry'
            Resource       = 'tenant'
            Score          = 6
            Severity       = 'HIGH'
            CisControl     = 'CIS 3'
            Recommendation = "Set an expiry on anonymous links (30 days recommended): " +
                             "SharePoint admin centre → Policies → Sharing → Advanced settings → " +
                             "'These links must expire within this many days' → set to 30 or fewer."
        })
    }

    # SP-04: OneDrive external sharing unrestricted
    if ($tenant.OneDriveSharingCapability -eq 'ExternalUserAndGuestSharing') {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'OneDriveExternalSharingUnrestricted'
            Resource       = 'tenant'
            Score          = 7
            Severity       = 'HIGH'
            CisControl     = 'CIS 3'
            Recommendation = "Restrict OneDrive sharing: SharePoint admin centre → Policies → Sharing → " +
                             "OneDrive: change from 'Anyone' to 'New and existing guests' or stricter."
        })
    }

    # SP-05: Default sharing link type is anonymous
    if ($tenant.DefaultSharingLinkType -eq 'AnonymousAccess') {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'AnonymousLinksFound'
            Resource       = 'tenant'
            Score          = 8
            Severity       = 'CRITICAL'
            CisControl     = 'CIS 3'
            Recommendation = "Change the default sharing link from 'Anyone with the link' to " +
                             "'People in your organisation': SharePoint admin centre → Policies → Sharing → " +
                             "Default link type → 'Only people in your organization'."
        })
    }

    # SP-06: External sharing not restricted to specific domains
    $domainList = @($tenant.SharingAllowedDomainList)
    if ($domainList.Count -eq 0 -and $tenant.SharingCapability -ne 'Disabled') {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'ExternalSharingNoDomainRestriction'
            Resource       = 'tenant'
            Score          = 5
            Severity       = 'MEDIUM'
            CisControl     = 'CIS 3'
            Recommendation = "Restrict external sharing to trusted domains: SharePoint admin centre → " +
                             "Policies → Sharing → Advanced settings → 'Limit external sharing by domain' → " +
                             "Add allowed domains."
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# SP-03: Sites more permissive than tenant default
# ---------------------------------------------------------------------------
function Get-SharePointSiteFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $tenant = Get-SPOTenant
    if ($null -eq $tenant) { return $findings }

    $tenantLevel = $tenant.SharingCapability
    $sites = @(Get-SPOSite -IncludePersonalSite $false -Limit All)

    $levelRank = @{
        'Disabled'                        = 0
        'ExistingExternalUserSharingOnly' = 1
        'ExternalUserSharingOnly'         = 2
        'ExternalUserAndGuestSharing'     = 3
    }
    $tenantRank = if ($levelRank.ContainsKey($tenantLevel)) { $levelRank[$tenantLevel] } else { 0 }

    foreach ($site in $sites) {
        $siteRank = if ($levelRank.ContainsKey($site.SharingCapability)) { $levelRank[$site.SharingCapability] } else { 0 }
        if ($siteRank -gt $tenantRank) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'SitePermissiveSharing'
                Resource       = $site.Url
                Score          = 7
                Severity       = 'HIGH'
                CisControl     = 'CIS 3'
                Recommendation = "Align sharing for '$($site.Url)' with tenant policy or stricter: " +
                                 "SharePoint admin centre → Sites → Active sites → select site → Policies → Sharing → " +
                                 "reduce to '$tenantLevel' or lower."
            })
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------
function ConvertTo-SharePointJsonReport {
    param([array]$Findings, [string]$TenantId = '')
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    return @{
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
        tenant_id    = $TenantId
        summary      = @{
            total_findings = $Findings.Count
            critical       = $counts.CRITICAL
            high           = $counts.HIGH
            medium         = $counts.MEDIUM
            low            = $counts.LOW
        }
        findings     = @($Findings | ForEach-Object {
            @{
                finding_type   = $_.FindingType
                resource       = if ($null -ne $_.Resource) { $_.Resource } else { '' }
                risk_level     = $_.Severity
                severity_score = $_.Score
                cis_control    = $_.CisControl
                recommendation = $_.Recommendation
            }
        })
    }
}

function ConvertTo-SharePointCsvReport {
    param([array]$Findings, [string]$Path)
    if ($Findings.Count -eq 0) { return }
    $rows = $Findings | ForEach-Object {
        [PSCustomObject]@{
            finding_type   = $_.FindingType
            resource       = if ($null -ne $_.Resource) { $_.Resource } else { '' }
            risk_level     = $_.Severity
            severity_score = $_.Score
            cis_control    = $_.CisControl
            recommendation = $_.Recommendation
        }
    }
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Set-RestrictedPermissions $Path
}

function ConvertTo-SharePointHtmlReport {
    param([array]$Findings, [string]$TenantId)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    $rows = ''
    foreach ($f in ($Findings | Sort-Object Score -Descending)) {
        $colour   = Get-SeverityColour $f.Severity
        $resource = if ($null -ne $f.Resource) { [System.Web.HttpUtility]::HtmlEncode($f.Resource) } else { '&mdash;' }
        $rec      = [System.Web.HttpUtility]::HtmlEncode($f.Recommendation)
        $rows += "<tr>
          <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
          <td><code>$resource</code></td>
          <td><span style='background:$colour;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em'>$($f.Severity)</span></td>
          <td style='font-size:0.85em'>$([System.Web.HttpUtility]::HtmlEncode($f.CisControl))</td>
          <td style='font-size:0.82em;color:#555;font-style:italic'>$rec</td>
        </tr>`n"
    }
    $noFindings   = if ($Findings.Count -eq 0) { "<tr><td colspan='5' style='text-align:center;color:#888'>No findings — tenant appears compliant.</td></tr>" } else { '' }
    $tenantDisplay = if ($TenantId) { [System.Web.HttpUtility]::HtmlEncode($TenantId) } else { 'N/A' }
    $ts            = (Get-Date).ToUniversalTime().ToString('o')
    return @"
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>SharePoint Security Audit</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
  .header{background:#1a1a2e;color:#fff;padding:30px 40px}
  .header h1{margin:0;font-size:1.8em}
  .header p{margin:5px 0 0;opacity:0.8}
  .summary{display:flex;gap:20px;padding:20px 40px;flex-wrap:wrap}
  .card{background:#fff;border-radius:8px;padding:20px 30px;flex:1;min-width:120px;box-shadow:0 2px 8px rgba(0,0,0,0.08);text-align:center}
  .card .num{font-size:2.5em;font-weight:bold}.card .lbl{color:#666;font-size:.85em;margin-top:4px}
  .section{padding:20px 32px}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)}
  th{background:#1a1a2e;color:#fff;padding:12px 15px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px}
  td{padding:10px 15px;border-bottom:1px solid #ecf0f1;vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:#f8f9ff}
  .footer{text-align:center;padding:20px;color:#999;font-size:0.85em}
</style>
</head>
<body>
<div class="header">
  <h1>SharePoint Online Security Audit</h1>
  <p>Tenant: $tenantDisplay &nbsp;|&nbsp; Generated: $ts</p>
</div>
<div class="summary">
  <div class="card"><div class="num">$($Findings.Count)</div><div class="lbl">Total Findings</div></div>
  <div class="card"><div class="num" style="color:#dc3545">$($counts.CRITICAL)</div><div class="lbl">CRITICAL</div></div>
  <div class="card"><div class="num" style="color:#fd7e14">$($counts.HIGH)</div><div class="lbl">HIGH</div></div>
  <div class="card"><div class="num" style="color:#ffc107">$($counts.MEDIUM)</div><div class="lbl">MEDIUM</div></div>
  <div class="card"><div class="num" style="color:#28a745">$($counts.LOW)</div><div class="lbl">LOW</div></div>
</div>
<div class="section">
  <table>
    <thead><tr><th>Type</th><th>Resource</th><th>Risk</th><th>CIS</th><th>Recommendation</th></tr></thead>
    <tbody>$rows$noFindings</tbody>
  </table>
</div>
<div class="footer">SharePoint Security Audit &nbsp;|&nbsp; For internal use only</div>
</body>
</html>
"@
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$ctx      = Get-AzContext
$tenantId = if ($ctx -and $ctx.Tenant) { $ctx.Tenant.Id } else { '' }

Write-Host "SharePoint Online Security Auditor"
Write-Host "Tenant ID: $tenantId"

$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "[1/2] Checking tenant-level sharing settings..."
Get-SharePointTenantFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[2/2] Checking site-level sharing overrides..."
Get-SharePointSiteFindings | ForEach-Object { $allFindings.Add($_) }

$findings = @($allFindings)
Write-Host "Findings: $($findings.Count)"

switch ($Format) {
    'stdout' {
        $findings | Format-Table FindingType, Resource, Severity, CisControl, Recommendation -Wrap
    }
    'json' {
        $r = ConvertTo-SharePointJsonReport -Findings $findings -TenantId $tenantId
        $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        Write-Host "JSON report: $Output.json"
    }
    'csv' {
        ConvertTo-SharePointCsvReport -Findings $findings -Path "$Output.csv"
        Write-Host "CSV report: $Output.csv"
    }
    'html' {
        $html = ConvertTo-SharePointHtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "HTML report: $Output.html"
    }
    'all' {
        $r = ConvertTo-SharePointJsonReport -Findings $findings -TenantId $tenantId
        $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        ConvertTo-SharePointCsvReport -Findings $findings -Path "$Output.csv"
        $html = ConvertTo-SharePointHtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
    }
}
