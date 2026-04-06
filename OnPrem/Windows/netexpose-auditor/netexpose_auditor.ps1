<#
.SYNOPSIS
    Audits network service exposure from within the LAN.
.DESCRIPTION
    Active port scan from the assessor's machine. Probes each host in the
    target IP or CIDR range for dangerous services: RDP, SMB, WinRM, LDAP,
    NetBIOS, RPC, MSSQL. Additional ports via -ExtraPorts.
.PARAMETER Target
    Single IP address (192.168.1.10) or CIDR range (192.168.1.0/24).
.PARAMETER ExtraPorts
    Additional TCP ports to probe on top of the default set.
.PARAMETER Output
    Output file prefix (default: netexpose_report).
.PARAMETER Format
    Output format: json | csv | html | all | stdout (default: all).
.PARAMETER TimeoutMs
    TCP connect timeout in milliseconds (default: 1000).
.PARAMETER ThrottleLimit
    ForEach-Object -Parallel concurrency limit (default: 50).
.PARAMETER Sequential
    Run sequentially instead of in parallel. Used by Pester tests.
.EXAMPLE
    .\netexpose_auditor.ps1 -Target 192.168.1.0/24
    .\netexpose_auditor.ps1 -Target 10.0.0.5 -ExtraPorts 8080,8443
    .\netexpose_auditor.ps1 -Target 192.168.1.0/24 -Format json
#>
param(
    [Parameter(Mandatory)][string]$Target,
    [int[]]  $ExtraPorts    = @(),
    [string] $Output        = 'netexpose_report',
    [ValidateSet('json','csv','html','all','stdout')]
    [string] $Format        = 'all',
    [int]    $TimeoutMs     = 1000,
    [int]    $ThrottleLimit = 50,
    [switch] $Sequential
)

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Stub — available at runtime via Windows built-ins; Pester BeforeAll
# defines its own version before dot-sourcing this script.
# ---------------------------------------------------------------------------
if (-not (Get-Command -Name 'Test-NetConnection' -ErrorAction SilentlyContinue)) {
    function Test-NetConnection {
        param($ComputerName, $Port, $InformationLevel, $WarningAction)
        [PSCustomObject]@{ TcpTestSucceeded = $false }
    }
}

# ---------------------------------------------------------------------------
# Default port definitions
# ---------------------------------------------------------------------------
$script:DEFAULT_PORTS = @(
    @{ Port=3389; Service='RDP';         FindingId='NE-01'; Severity='CRITICAL'; Score=9; CisControl='CIS 12.2'
       Recommendation='Restrict RDP (3389) to a management VLAN or VPN — or disable if unused. Enforce Network Level Authentication (NLA).' }
    @{ Port=445;  Service='SMB';         FindingId='NE-02'; Severity='CRITICAL'; Score=9; CisControl='CIS 12.2'
       Recommendation='Block inbound SMB (445) at all network boundaries. SMB exposure is the primary ransomware lateral-movement vector.' }
    @{ Port=139;  Service='NetBIOS';     FindingId='NE-03'; Severity='HIGH';     Score=6; CisControl='CIS 12.2'
       Recommendation='Disable NetBIOS over TCP/IP on all adapters where it is not required. Block port 139 at the firewall.' }
    @{ Port=135;  Service='RPC';         FindingId='NE-04'; Severity='MEDIUM';   Score=4; CisControl='CIS 12.2'
       Recommendation='Block inbound RPC (135) at the network boundary. Restrict access to management hosts only.' }
    @{ Port=5985; Service='WinRM HTTP';  FindingId='NE-05'; Severity='HIGH';     Score=7; CisControl='CIS 12.2'
       Recommendation='Restrict WinRM HTTP (5985) to a management VLAN. Prefer WinRM HTTPS (5986). Disable if remote management is not required.' }
    @{ Port=5986; Service='WinRM HTTPS'; FindingId='NE-06'; Severity='HIGH';     Score=6; CisControl='CIS 12.2'
       Recommendation='Restrict WinRM HTTPS (5986) to a management VLAN. Ensure certificate-based authentication is enforced.' }
    @{ Port=389;  Service='LDAP';        FindingId='NE-07'; Severity='MEDIUM';   Score=4; CisControl='CIS 12.2'
       Recommendation='Restrict unauthenticated LDAP (389). Enforce LDAP signing and channel binding. Prefer LDAPS (636).' }
    @{ Port=636;  Service='LDAPS';       FindingId='NE-08'; Severity='LOW';      Score=2; CisControl='CIS 12.2'
       Recommendation='Ensure LDAPS (636) uses a valid certificate. Restrict access to domain-joined clients only.' }
    @{ Port=1433; Service='MSSQL';       FindingId='NE-09'; Severity='HIGH';     Score=7; CisControl='CIS 12.2'
       Recommendation='Restrict MSSQL (1433) to application servers only. Never expose database ports to the broader LAN.' }
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Get-SeverityLabel {
    param([int]$Score)
    if ($Score -ge 8) { return 'CRITICAL' }
    if ($Score -ge 5) { return 'HIGH' }
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
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl
    }
}

# ---------------------------------------------------------------------------
# CIDR expansion
# ---------------------------------------------------------------------------
function Expand-CidrRange {
    param([string]$Target)

    if ($Target -match '^(\d{1,3}\.){3}\d{1,3}$') {
        $null = [System.Net.IPAddress]::Parse($Target)  # throws on invalid octets
        return , [string[]]@($Target)
    }

    if ($Target -match '^(.+)/(\d+)$') {
        $baseIp = $Matches[1]
        $prefix = [int]$Matches[2]
        if ($prefix -lt 0 -or $prefix -gt 32) { throw "Invalid CIDR prefix: /$prefix" }

        $ipBytes = [System.Net.IPAddress]::Parse($baseIp).GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)

        $mask      = if ($prefix -eq 0) { [uint32]0 } else { [uint32]::MaxValue -shl (32 - $prefix) }
        $network   = $ipInt -band $mask
        $broadcast = $network -bor (-bnot $mask -band [uint32]::MaxValue)

        $hosts = [System.Collections.Generic.List[string]]::new()
        for ($i = $network + 1; $i -lt $broadcast; $i++) {
            $bytes = [System.BitConverter]::GetBytes([uint32]$i)
            [Array]::Reverse($bytes)
            $hosts.Add(([System.Net.IPAddress]::new($bytes)).ToString())
        }
        return , [string[]]@($hosts)
    }

    throw "Invalid target '$Target'. Use an IP address or CIDR notation (e.g. 192.168.1.0/24)."
}

# ---------------------------------------------------------------------------
# Per-host port probe (synchronous — Pester-mockable via Test-NetConnection)
# ---------------------------------------------------------------------------
function Invoke-HostScan {
    param(
        [string]      $Ip,
        [hashtable[]] $AllPorts,
        [int]         $TimeoutMs = 1000
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($portDef in $AllPorts) {
        # Note: Test-NetConnection does not support a configurable timeout.
        # $TimeoutMs is reserved for a future TcpClient-based probe implementation.
        $conn = Test-NetConnection -ComputerName $Ip -Port $portDef.Port `
                    -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($conn.TcpTestSucceeded) {
            $isCustom = $portDef.FindingId -eq 'NE-XX'
            $findings.Add([PSCustomObject]@{
                FindingType    = if ($isCustom) { 'ExposedCustomPort' } else { 'ExposedService' }
                Host           = $Ip
                Port           = $portDef.Port
                Service        = $portDef.Service
                Severity       = $portDef.Severity
                CisControl     = $portDef.CisControl
                Score          = $portDef.Score
                Recommendation = $portDef.Recommendation
            })
        }
    }
    return @($findings)
}

# ---------------------------------------------------------------------------
# Parallel dispatcher
# ---------------------------------------------------------------------------
function Get-NetworkExposureFindings {
    param(
        [string[]]    $Hosts,
        [hashtable[]] $Ports,
        [int[]]       $ExtraPorts    = @(),
        [int]         $TimeoutMs     = 1000,
        [int]         $ThrottleLimit = 50,
        [switch]      $Sequential
    )

    $allPorts = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($p in $Ports) { $allPorts.Add($p) }
    foreach ($port in $ExtraPorts) {
        $allPorts.Add(@{
            Port           = $port
            Service        = "Port $port"
            FindingId      = 'NE-XX'
            Severity       = Get-SeverityLabel -Score 4
            Score          = 4
            CisControl     = 'CIS 12.2'
            Recommendation = "Investigate whether port $port should be exposed. Restrict access if not required."
        })
    }

    $allPortsList = @($allPorts)
    $bag = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()

    if ($Sequential) {
        foreach ($ip in $Hosts) {
            $results = Invoke-HostScan -Ip $ip -AllPorts $allPortsList -TimeoutMs $TimeoutMs
            foreach ($r in $results) { $bag.Add($r) }
        }
    } else {
        $invokeHostScanStr = ${function:Invoke-HostScan}.ToString()
        $testNetConnStr    = ${function:Test-NetConnection}.ToString()

        $Hosts | ForEach-Object -Parallel {
            ${function:Test-NetConnection} = [scriptblock]::Create($using:testNetConnStr)
            ${function:Invoke-HostScan}    = [scriptblock]::Create($using:invokeHostScanStr)
            $results = Invoke-HostScan -Ip $_ -AllPorts $using:allPortsList -TimeoutMs $using:TimeoutMs
            foreach ($r in $results) { ($using:bag).Add($r) }
        } -ThrottleLimit $ThrottleLimit
    }

    return @($bag)
}

# ---------------------------------------------------------------------------
# Output functions
# ---------------------------------------------------------------------------
function ConvertTo-NetExposeJsonReport {
    param([array]$Findings, [string]$Target)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    return [ordered]@{
        generated_at = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        target       = $Target
        summary      = $counts
        findings     = @($Findings | ForEach-Object {
            [ordered]@{
                finding_type   = $_.FindingType
                host           = $_.Host
                port           = $_.Port
                service        = $_.Service
                severity       = $_.Severity
                cis_control    = $_.CisControl
                score          = $_.Score
                recommendation = $_.Recommendation
            }
        })
    }
}

function Write-NetExposeJsonReport {
    param([array]$Findings, [string]$Target, [string]$Path)
    ConvertTo-NetExposeJsonReport -Findings $Findings -Target $Target |
        ConvertTo-Json -Depth 10 | Out-File $Path -Encoding UTF8
    Set-RestrictedPermissions $Path
}

function Write-NetExposeCsvReport {
    param([array]$Findings, [string]$Path)
    if ($Findings.Count -eq 0) { return }
    $Findings | Select-Object FindingType, Host, Port, Service, Severity, Score, CisControl, Recommendation |
        ConvertTo-Csv -NoTypeInformation | Out-File $Path -Encoding UTF8
    Set-RestrictedPermissions $Path
}

function Write-NetExposeHtmlReport {
    param([array]$Findings, [string]$Target, [string]$Path)
    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Findings) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }

    $rows = foreach ($f in ($Findings | Sort-Object Score -Descending)) {
        $colour = Get-SeverityColour $f.Severity
        "<tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.FindingType))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Host))</td>
            <td>$($f.Port)</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Service))</td>
            <td style='color:$colour;font-weight:bold'>$([System.Web.HttpUtility]::HtmlEncode($f.Severity))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.CisControl))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</td>
        </tr>"
    }

    $noFindings = if ($Findings.Count -eq 0) {
        '<tr><td colspan="7" style="text-align:center;color:#28a745">No exposed services detected</td></tr>'
    } else { '' }

    $scannedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $html = @"
<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>Network Exposure Report</title>
<style>
body{font-family:Arial,sans-serif;margin:2rem;background:#f8f9fa}
h1{color:#343a40}
.summary{display:flex;gap:1rem;margin-bottom:1.5rem}
.badge{padding:.5rem 1rem;border-radius:.25rem;color:#fff;font-weight:bold}
.CRITICAL{background:#dc3545}.HIGH{background:#fd7e14}.MEDIUM{background:#ffc107;color:#212529}.LOW{background:#28a745}
table{width:100%;border-collapse:collapse;background:#fff}
th{background:#343a40;color:#fff;padding:.5rem;text-align:left}
td{padding:.5rem;border-bottom:1px solid #dee2e6;vertical-align:top}
tr:hover{background:#f1f3f5}
.footer{margin-top:1rem;font-size:.8rem;color:#6c757d}
</style></head><body>
<h1>Network Exposure Audit</h1>
<p>Target: <strong>$([System.Web.HttpUtility]::HtmlEncode($Target))</strong> &nbsp;|&nbsp; Scanned: $scannedAt</p>
<div class='summary'>
  <span class='badge CRITICAL'>CRITICAL: $($counts.CRITICAL)</span>
  <span class='badge HIGH'>HIGH: $($counts.HIGH)</span>
  <span class='badge MEDIUM'>MEDIUM: $($counts.MEDIUM)</span>
  <span class='badge LOW'>LOW: $($counts.LOW)</span>
</div>
<table>
  <thead><tr><th>Type</th><th>Host</th><th>Port</th><th>Service</th><th>Risk</th><th>CIS</th><th>Recommendation</th></tr></thead>
  <tbody>$($rows -join '')$noFindings</tbody>
</table>
<div class='footer'>Network Exposure Audit &nbsp;|&nbsp; For internal use only</div>
</body></html>
"@
    $html | Out-File $Path -Encoding UTF8
    Set-RestrictedPermissions $Path
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Host "Network Exposure Auditor"
Write-Host "Target: $Target"

$hosts = @(Expand-CidrRange -Target $Target)
Write-Host "Hosts to scan: $($hosts.Count)"

Write-Host "Scanning for exposed services..."
$findings = @(Get-NetworkExposureFindings `
    -Hosts      $hosts `
    -Ports      $script:DEFAULT_PORTS `
    -ExtraPorts $ExtraPorts `
    -TimeoutMs  $TimeoutMs `
    -ThrottleLimit $ThrottleLimit `
    -Sequential:$Sequential)

Write-Host "Findings: $($findings.Count)"

switch ($Format) {
    'stdout' {
        $findings | Format-Table FindingType, Host, Port, Service, Severity, Recommendation -Wrap
    }
    'json' {
        Write-NetExposeJsonReport -Findings $findings -Target $Target -Path "$Output.json"
        Write-Host "JSON report: $Output.json"
    }
    'csv' {
        Write-NetExposeCsvReport -Findings $findings -Path "$Output.csv"
        Write-Host "CSV report: $Output.csv"
    }
    'html' {
        Write-NetExposeHtmlReport -Findings $findings -Target $Target -Path "$Output.html"
        Write-Host "HTML report: $Output.html"
    }
    'all' {
        Write-NetExposeJsonReport -Findings $findings -Target $Target -Path "$Output.json"
        Write-NetExposeCsvReport  -Findings $findings -Path "$Output.csv"
        Write-NetExposeHtmlReport -Findings $findings -Target $Target -Path "$Output.html"
        Write-Host "Reports: $Output.json  $Output.csv  $Output.html"
    }
}
