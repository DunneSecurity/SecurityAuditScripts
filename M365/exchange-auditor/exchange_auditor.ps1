<#
.SYNOPSIS
    Audits Exchange Online transport rules, mailbox delegation, and audit configuration.
.DESCRIPTION
    Read-only audit of Exchange Online security posture:
    - EX-01: Transport rules forwarding mail to external domains
    - EX-02: Transport rules bypassing spam/malware filtering (SCL=-1)
    - EX-03: Remote domain allows automatic forwarding
    - EX-04: FullAccess mailbox delegation to non-admin accounts
    - EX-05: Shared mailbox sign-in not blocked
    - EX-06: Per-mailbox audit logging disabled
    - EX-07: Admin audit logging disabled
    - EX-08: SMTP AUTH enabled on individual mailboxes
.PARAMETER Output
    Output file prefix (default: exchange_report)
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all)
.PARAMETER TenantDomain
    Primary tenant domain (e.g. contoso.com)
.EXAMPLE
    .\exchange_auditor.ps1 -TenantDomain contoso.com
#>
param(
    [string]$Output       = 'exchange_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string]$Format       = 'all',
    [string]$TenantDomain = ''
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# ExO / Graph / Az stubs
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Get-TransportRule' -ErrorAction SilentlyContinue)) {
    function Connect-MgGraph         { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext           { $null }
    function Connect-ExchangeOnline  { param($AppId, $Organization, $ShowBanner) }
    function Disconnect-ExchangeOnline { param([switch]$Confirm) }
    function Get-TransportRule       { @() }
    function Get-RemoteDomain        { @() }
    function Get-Mailbox             { param($ResultSize, $RecipientTypeDetails, $Filter) @() }
    function Get-MailboxPermission   { param($Identity) @() }
    function Get-AdminAuditLogConfig { [PSCustomObject]@{ AdminAuditLogEnabled = $true } }
    function Get-CASMailbox          { param($Identity) [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $true } }
    function Get-MgUser              { param($UserId, $Property) [PSCustomObject]@{ AccountEnabled = $false } }
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
# EX-01, EX-02: Transport rules — external forwarding and filter bypass
# ---------------------------------------------------------------------------
function Get-ExchangeTransportRuleFindings {
    param([string]$TenantDomain = '')

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $rules    = @(Get-TransportRule)

    foreach ($rule in $rules) {
        if (-not $rule.Enabled) { continue }

        # EX-01: Rule forwards/redirects to external address
        $fwdTargets = @()
        if ($rule.RedirectMessageTo) { $fwdTargets += @($rule.RedirectMessageTo) }
        if ($rule.BlindCopyTo)       { $fwdTargets += @($rule.BlindCopyTo) }
        if ($rule.AddToRecipients)   { $fwdTargets += @($rule.AddToRecipients) }

        foreach ($target in $fwdTargets) {
            $targetStr = "$target"
            $isExternal = $TenantDomain -eq '' -or (-not $targetStr.Contains("@$TenantDomain"))
            if ($isExternal) {
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'TransportRuleExternalForwarding'
                    Resource       = $rule.Name
                    Score          = 9
                    Severity       = 'CRITICAL'
                    CisControl     = 'CIS 9'
                    Recommendation = "Disable or remove transport rule '$($rule.Name)' that forwards to '$targetStr': " +
                                     "Exchange admin centre → Mail flow → Rules → select rule → Disable or Delete. " +
                                     "If business-required, document and restrict to specific trusted addresses."
                })
                break
            }
        }

        # EX-02: Rule bypasses spam/malware filtering (SCL = -1)
        if ($null -ne $rule.SetSCL -and $rule.SetSCL -eq -1) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'TransportRuleBypassesFiltering'
                Resource       = $rule.Name
                Score          = 8
                Severity       = 'CRITICAL'
                CisControl     = 'CIS 9'
                Recommendation = "Review and remove the spam filter bypass in rule '$($rule.Name)': " +
                                 "Exchange admin centre → Mail flow → Rules → select rule → " +
                                 "remove the 'Set the spam confidence level (SCL) to -1' action."
            })
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# EX-03: Remote domain — automatic forwarding
# ---------------------------------------------------------------------------
function Get-ExchangeRemoteDomainFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $domains  = @(Get-RemoteDomain)

    foreach ($domain in $domains) {
        if ($domain.AutoForwardEnabled -eq $true) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'RemoteDomainAutoForwardEnabled'
                Resource       = $domain.Identity
                Score          = 8
                Severity       = 'CRITICAL'
                CisControl     = 'CIS 9'
                Recommendation = "Disable automatic forwarding for remote domain '$($domain.Identity)': " +
                                 "Exchange admin centre → Mail flow → Remote domains → select domain → " +
                                 "Uncheck 'Allow automatic forwarding'. Also disable via anti-spam outbound policy."
            })
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# EX-04, EX-06: Mailbox delegation and audit logging
# ---------------------------------------------------------------------------
function Get-ExchangeMailboxPermissionFindings {
    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $mailboxes = @(Get-Mailbox -ResultSize Unlimited)

    $skipUsers = @('NT AUTHORITY\SELF', 'S-1-5-10')

    foreach ($mbx in $mailboxes) {
        $upn = $mbx.UserPrincipalName

        # EX-04: FullAccess delegation
        $permissions = @(Get-MailboxPermission -Identity $upn)
        foreach ($perm in $permissions) {
            if ($perm.Deny -eq $true) { continue }
            if ($perm.User -in $skipUsers) { continue }
            if ($perm.User -match 'NT AUTHORITY') { continue }
            if ($perm.AccessRights -contains 'FullAccess') {
                $findings.Add([PSCustomObject]@{
                    FindingType    = 'MailboxFullAccessDelegation'
                    Resource       = "$upn → $($perm.User)"
                    Score          = 5
                    Severity       = 'MEDIUM'
                    CisControl     = 'CIS 5'
                    Recommendation = "Review FullAccess delegation on '$upn' granted to '$($perm.User)': " +
                                     "Exchange admin centre → Recipients → Mailboxes → $upn → Delegation → " +
                                     "Remove if not business-justified."
                })
            }
        }

        # EX-06: Per-mailbox audit disabled
        if ($mbx.AuditEnabled -eq $false) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'MailboxAuditLoggingDisabled'
                Resource       = $upn
                Score          = 6
                Severity       = 'HIGH'
                CisControl     = 'CIS 8'
                Recommendation = "Enable audit logging on mailbox '$upn': " +
                                 "PowerShell: Set-Mailbox -Identity '$upn' -AuditEnabled `$true"
            })
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# EX-05: Shared mailbox sign-in not blocked
# ---------------------------------------------------------------------------
function Get-ExchangeSharedMailboxFindings {
    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $mailboxes = @(Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited)

    foreach ($mbx in $mailboxes) {
        $upn = $mbx.UserPrincipalName
        $oid = $mbx.ExternalDirectoryObjectId
        if (-not $oid) { continue }

        $user = Get-MgUser -UserId $oid -Property 'AccountEnabled'
        if ($null -ne $user -and $user.AccountEnabled -eq $true) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'SharedMailboxSignInNotBlocked'
                Resource       = $upn
                Score          = 7
                Severity       = 'HIGH'
                CisControl     = 'CIS 5'
                Recommendation = "Block direct sign-in for shared mailbox '$upn': " +
                                 "Entra admin centre → Users → select '$upn' → " +
                                 "Edit properties → Account → Block sign-in: Yes."
            })
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# EX-07: Admin audit logging
# ---------------------------------------------------------------------------
function Get-ExchangeAuditFindings {
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $config   = Get-AdminAuditLogConfig

    if ($null -ne $config -and $config.AdminAuditLogEnabled -eq $false) {
        $findings.Add([PSCustomObject]@{
            FindingType    = 'AdminAuditLoggingDisabled'
            Resource       = 'tenant'
            Score          = 7
            Severity       = 'HIGH'
            CisControl     = 'CIS 8'
            Recommendation = "Enable Exchange admin audit logging: " +
                             "PowerShell: Set-AdminAuditLogConfig -AdminAuditLogEnabled `$true"
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# EX-08: SMTP AUTH enabled on individual mailboxes
# ---------------------------------------------------------------------------
function Get-ExchangeSmtpAuthFindings {
    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $mailboxes = @(Get-Mailbox -ResultSize Unlimited)

    foreach ($mbx in $mailboxes) {
        $upn = $mbx.UserPrincipalName
        $cas = Get-CASMailbox -Identity $upn
        # SmtpClientAuthenticationDisabled = $false means SMTP AUTH is ON
        if ($null -ne $cas -and $cas.SmtpClientAuthenticationDisabled -eq $false) {
            $findings.Add([PSCustomObject]@{
                FindingType    = 'SmtpAuthEnabledOnMailbox'
                Resource       = $upn
                Score          = 6
                Severity       = 'HIGH'
                CisControl     = 'CIS 4'
                Recommendation = "Disable SMTP AUTH on mailbox '$upn' unless required by a legacy app: " +
                                 "PowerShell: Set-CASMailbox -Identity '$upn' -SmtpClientAuthenticationDisabled `$true"
            })
        }
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------
function ConvertTo-ExchangeJsonReport {
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

function ConvertTo-ExchangeCsvReport {
    param([array]$Findings, [string]$Path)
    if ($Findings.Count -eq 0) { return }
    $Findings | ForEach-Object {
        [PSCustomObject]@{
            finding_type   = $_.FindingType
            resource       = if ($null -ne $_.Resource) { $_.Resource } else { '' }
            risk_level     = $_.Severity
            severity_score = $_.Score
            cis_control    = $_.CisControl
            recommendation = $_.Recommendation
        }
    } | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Set-RestrictedPermissions $Path
}

function ConvertTo-ExchangeHtmlReport {
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
    $noFindings    = if ($Findings.Count -eq 0) { "<tr><td colspan='5' style='text-align:center;color:#888'>No findings — tenant appears compliant.</td></tr>" } else { '' }
    $tenantDisplay = if ($TenantId) { [System.Web.HttpUtility]::HtmlEncode($TenantId) } else { 'N/A' }
    $ts            = (Get-Date).ToUniversalTime().ToString('o')
    return @"
<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><title>Exchange Online Security Audit</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f6fa;color:#333}
  .header{background:#1a1a2e;color:#fff;padding:30px 40px}.header h1{margin:0;font-size:1.8em}.header p{margin:5px 0 0;opacity:0.8}
  .summary{display:flex;gap:20px;padding:20px 40px;flex-wrap:wrap}
  .card{background:#fff;border-radius:8px;padding:20px 30px;flex:1;min-width:120px;box-shadow:0 2px 8px rgba(0,0,0,0.08);text-align:center}
  .card .num{font-size:2.5em;font-weight:bold}.card .lbl{color:#666;font-size:.85em;margin-top:4px}
  .section{padding:20px 32px}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)}
  th{background:#1a1a2e;color:#fff;padding:12px 15px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.5px}
  td{padding:10px 15px;border-bottom:1px solid #ecf0f1;vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:#f8f9ff}
  .footer{text-align:center;padding:20px;color:#999;font-size:0.85em}
</style></head>
<body>
<div class="header"><h1>Exchange Online Security Audit</h1><p>Tenant: $tenantDisplay &nbsp;|&nbsp; Generated: $ts</p></div>
<div class="summary">
  <div class="card"><div class="num">$($Findings.Count)</div><div class="lbl">Total Findings</div></div>
  <div class="card"><div class="num" style="color:#dc3545">$($counts.CRITICAL)</div><div class="lbl">CRITICAL</div></div>
  <div class="card"><div class="num" style="color:#fd7e14">$($counts.HIGH)</div><div class="lbl">HIGH</div></div>
  <div class="card"><div class="num" style="color:#ffc107">$($counts.MEDIUM)</div><div class="lbl">MEDIUM</div></div>
  <div class="card"><div class="num" style="color:#28a745">$($counts.LOW)</div><div class="lbl">LOW</div></div>
</div>
<div class="section"><table>
  <thead><tr><th>Type</th><th>Resource</th><th>Risk</th><th>CIS</th><th>Recommendation</th></tr></thead>
  <tbody>$rows$noFindings</tbody>
</table></div>
<div class="footer">Exchange Online Security Audit &nbsp;|&nbsp; For internal use only</div>
</body></html>
"@
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$ctx      = Get-AzContext
$tenantId = if ($ctx -and $ctx.Tenant) { $ctx.Tenant.Id } else { '' }
$accountUpn = if ($ctx -and $ctx.Account) { $ctx.Account.Id } else { '' }
if (-not $TenantDomain -and $accountUpn -match '@(.+)$') { $TenantDomain = $Matches[1] }

Write-Host "Exchange Online Security Auditor"
Write-Host "Tenant ID    : $tenantId"
Write-Host "Tenant Domain: $TenantDomain"

$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "[1/6] Checking transport rules..."
Get-ExchangeTransportRuleFindings -TenantDomain $TenantDomain | ForEach-Object { $allFindings.Add($_) }

Write-Host "[2/6] Checking remote domain auto-forwarding..."
Get-ExchangeRemoteDomainFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[3/6] Checking mailbox delegation and audit..."
Get-ExchangeMailboxPermissionFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[4/6] Checking shared mailbox sign-in..."
Get-ExchangeSharedMailboxFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[5/6] Checking admin audit logging..."
Get-ExchangeAuditFindings | ForEach-Object { $allFindings.Add($_) }

Write-Host "[6/6] Checking SMTP AUTH per mailbox..."
Get-ExchangeSmtpAuthFindings | ForEach-Object { $allFindings.Add($_) }

$findings = @($allFindings)
Write-Host "Findings: $($findings.Count)"

switch ($Format) {
    'stdout' { $findings | Format-Table FindingType, Resource, Severity, CisControl, Recommendation -Wrap }
    'json' {
        $r = ConvertTo-ExchangeJsonReport -Findings $findings -TenantId $tenantId
        $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        Write-Host "JSON report: $Output.json"
    }
    'csv' {
        ConvertTo-ExchangeCsvReport -Findings $findings -Path "$Output.csv"
        Write-Host "CSV report: $Output.csv"
    }
    'html' {
        $html = ConvertTo-ExchangeHtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "HTML report: $Output.html"
    }
    'all' {
        $r = ConvertTo-ExchangeJsonReport -Findings $findings -TenantId $tenantId
        $r | ConvertTo-Json -Depth 10 | Out-File "$Output.json" -Encoding UTF8
        Set-RestrictedPermissions "$Output.json"
        ConvertTo-ExchangeCsvReport -Findings $findings -Path "$Output.csv"
        $html = ConvertTo-ExchangeHtmlReport -Findings $findings -TenantId $tenantId
        $html | Out-File "$Output.html" -Encoding UTF8
        Set-RestrictedPermissions "$Output.html"
        Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
    }
}
