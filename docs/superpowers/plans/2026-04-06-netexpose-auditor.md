# Network Exposure Auditor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a PowerShell auditor that scans a target IP or CIDR range from a laptop on the client LAN, identifying hosts with dangerous services (RDP, SMB, WinRM, LDAP, NetBIOS, RPC, MSSQL) exposed on the network.

**Architecture:** Single PS1 script with `Expand-CidrRange` (CIDR-to-IP-list), `Invoke-HostScan` (per-host port probe, Pester-mockable), and `Get-NetworkExposureFindings` (parallel dispatcher via `ForEach-Object -Parallel`). Output layer mirrors winpatch pattern. Integration via `Run-Audit.ps1`, `exec_summary.py`, `audit.py`.

**Tech Stack:** PowerShell 7+ · Pester 5 · `Test-NetConnection` (built-in) · `ForEach-Object -Parallel`

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `OnPrem/Windows/netexpose-auditor/netexpose_auditor.ps1` | CIDR expansion, port scan, JSON/CSV/HTML output |
| Create | `OnPrem/Windows/netexpose-auditor/tests/netexpose_auditor.Tests.ps1` | Pester tests (~15) |
| Create | `OnPrem/Windows/netexpose-auditor/README.md` | Usage docs |
| Modify | `tools/exec_summary.py` | Add `netexpose_report.json` to KNOWN_PATTERNS, AZURE_WINDOWS_PATTERNS, PILLAR_LABELS |
| Modify | `audit.py` | Add `netexpose` entry to `WINDOWS_PS1` |
| Modify | `Run-Audit.ps1` | Add `netexpose` to `$WindowsAuditors` |
| Modify | `README.md` | Update directory tree + auditor table |

---

## Task 1: netexpose-auditor — failing tests (RED)

**Files:**
- Create: `OnPrem/Windows/netexpose-auditor/tests/netexpose_auditor.Tests.ps1`

- [ ] **Step 1: Create directory**

```bash
mkdir -p OnPrem/Windows/netexpose-auditor/tests
```

- [ ] **Step 2: Write the failing tests**

Save to `OnPrem/Windows/netexpose-auditor/tests/netexpose_auditor.Tests.ps1`:

```powershell
# OnPrem/Windows/netexpose-auditor/tests/netexpose_auditor.Tests.ps1
BeforeAll {
    function Test-NetConnection {
        param($ComputerName, $Port, $InformationLevel, $WarningAction)
        [PSCustomObject]@{ TcpTestSucceeded = $false }
    }

    . "$PSScriptRoot/../netexpose_auditor.ps1" -Target '10.0.0.1'
}

# ---------------------------------------------------------------------------
# Expand-CidrRange
# ---------------------------------------------------------------------------
Describe 'Expand-CidrRange' {
    It 'returns a single IP unchanged' {
        $result = Expand-CidrRange '10.0.0.5'
        $result | Should -HaveCount 1
        $result[0] | Should -Be '10.0.0.5'
    }

    It 'returns 2 host IPs for a /30' {
        $result = Expand-CidrRange '192.168.1.0/30'
        $result | Should -HaveCount 2
        $result | Should -Contain '192.168.1.1'
        $result | Should -Contain '192.168.1.2'
    }

    It 'returns 254 host IPs for a /24' {
        $result = Expand-CidrRange '10.0.0.0/24'
        $result | Should -HaveCount 254
        $result | Should -Contain '10.0.0.1'
        $result | Should -Contain '10.0.0.254'
        $result | Should -Not -Contain '10.0.0.0'
        $result | Should -Not -Contain '10.0.0.255'
    }

    It 'throws on invalid input' {
        { Expand-CidrRange 'not-an-ip' } | Should -Throw
    }
}

# ---------------------------------------------------------------------------
# Invoke-HostScan
# ---------------------------------------------------------------------------
Describe 'Invoke-HostScan' {
    It 'emits NE-01 CRITICAL ExposedService finding when RDP is open' {
        Mock Test-NetConnection {
            param($ComputerName, $Port)
            [PSCustomObject]@{ TcpTestSucceeded = ($Port -eq 3389) }
        }
        $findings = Invoke-HostScan -Ip '10.0.0.1' -AllPorts $script:DEFAULT_PORTS
        $f = $findings | Where-Object { $_.Port -eq 3389 }
        $f              | Should -Not -BeNullOrEmpty
        $f.FindingType  | Should -Be 'ExposedService'
        $f.Service      | Should -Be 'RDP'
        $f.Severity     | Should -Be 'CRITICAL'
        $f.Host         | Should -Be '10.0.0.1'
    }

    It 'emits NE-02 CRITICAL finding when SMB is open' {
        Mock Test-NetConnection {
            param($ComputerName, $Port)
            [PSCustomObject]@{ TcpTestSucceeded = ($Port -eq 445) }
        }
        $findings = Invoke-HostScan -Ip '10.0.0.1' -AllPorts $script:DEFAULT_PORTS
        $f = $findings | Where-Object { $_.Port -eq 445 }
        $f.Service  | Should -Be 'SMB'
        $f.Severity | Should -Be 'CRITICAL'
    }

    It 'emits no finding when port is closed' {
        Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $false } }
        $findings = Invoke-HostScan -Ip '10.0.0.1' -AllPorts $script:DEFAULT_PORTS
        $findings | Should -BeNullOrEmpty
    }

    It 'emits one finding per open port when multiple ports open on same host' {
        Mock Test-NetConnection {
            param($ComputerName, $Port)
            [PSCustomObject]@{ TcpTestSucceeded = ($Port -in @(3389, 445)) }
        }
        $findings = Invoke-HostScan -Ip '10.0.0.1' -AllPorts $script:DEFAULT_PORTS
        $findings | Should -HaveCount 2
    }

    It 'emits ExposedCustomPort MEDIUM finding for an extra port' {
        $customPorts = @(@{
            Port = 8080; Service = 'Port 8080'; FindingId = 'NE-XX'
            Severity = 'MEDIUM'; Score = 4; CisControl = 'CIS 12.2'
            Recommendation = 'Investigate port 8080 exposure.'
        })
        Mock Test-NetConnection {
            param($ComputerName, $Port)
            [PSCustomObject]@{ TcpTestSucceeded = ($Port -eq 8080) }
        }
        $findings = Invoke-HostScan -Ip '10.0.0.1' -AllPorts $customPorts
        $f = $findings | Where-Object { $_.Port -eq 8080 }
        $f              | Should -Not -BeNullOrEmpty
        $f.FindingType  | Should -Be 'ExposedCustomPort'
        $f.Severity     | Should -Be 'MEDIUM'
    }

    It 'returns empty array when all ports closed' {
        Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $false } }
        $findings = Invoke-HostScan -Ip '10.0.0.1' -AllPorts $script:DEFAULT_PORTS
        $findings | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-NetworkExposureFindings
# ---------------------------------------------------------------------------
Describe 'Get-NetworkExposureFindings' {
    It 'returns empty when all ports closed across multiple hosts' {
        Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $false } }
        $findings = Get-NetworkExposureFindings -Hosts @('10.0.0.1','10.0.0.2') `
                        -Ports $script:DEFAULT_PORTS -ExtraPorts @() -Sequential
        $findings | Should -BeNullOrEmpty
    }

    It 'aggregates findings from multiple hosts' {
        Mock Test-NetConnection {
            param($ComputerName, $Port)
            [PSCustomObject]@{ TcpTestSucceeded = ($Port -eq 3389) }
        }
        $findings = Get-NetworkExposureFindings -Hosts @('10.0.0.1','10.0.0.2') `
                        -Ports $script:DEFAULT_PORTS -ExtraPorts @() -Sequential
        $findings | Should -HaveCount 2
        ($findings | Select-Object -ExpandProperty Host | Sort-Object -Unique) | Should -HaveCount 2
    }
}

# ---------------------------------------------------------------------------
# ConvertTo-NetExposeJsonReport
# ---------------------------------------------------------------------------
Describe 'ConvertTo-NetExposeJsonReport' {
    It 'emits generated_at, target, summary, and findings fields' {
        $f = [PSCustomObject]@{
            FindingType = 'ExposedService'; Host = '10.0.0.1'; Port = 3389
            Service = 'RDP'; Severity = 'CRITICAL'; CisControl = 'CIS 12.2'
            Score = 9; Recommendation = 'Test'
        }
        $report = ConvertTo-NetExposeJsonReport -Findings @($f) -Target '10.0.0.0/24'
        $report.generated_at | Should -Not -BeNullOrEmpty
        $report.target       | Should -Be '10.0.0.0/24'
        $report.summary      | Should -Not -BeNullOrEmpty
        $report.findings     | Should -HaveCount 1
    }

    It 'summary counts match findings array' {
        $findings = @(
            [PSCustomObject]@{ FindingType='ExposedService'; Host='10.0.0.1'; Port=3389; Service='RDP';  Severity='CRITICAL'; CisControl='CIS 12.2'; Score=9; Recommendation='X' }
            [PSCustomObject]@{ FindingType='ExposedService'; Host='10.0.0.1'; Port=5985; Service='WinRM HTTP'; Severity='HIGH'; CisControl='CIS 12.2'; Score=7; Recommendation='X' }
        )
        $report = ConvertTo-NetExposeJsonReport -Findings $findings -Target '10.0.0.1'
        $report.summary.CRITICAL | Should -Be 1
        $report.summary.HIGH     | Should -Be 1
        $report.summary.MEDIUM   | Should -Be 0
    }
}
```

- [ ] **Step 3: Run tests — expect failure**

```bash
cd /home/declan/Claude/SecurityAuditScripts
/home/declan/bin/pwsh -Command "Invoke-Pester -Path OnPrem/Windows/netexpose-auditor/tests -Output Detailed"
```

Expected: All tests fail with `Expand-CidrRange: command not found` style errors.

---

## Task 2: netexpose-auditor — implementation (GREEN)

**Files:**
- Create: `OnPrem/Windows/netexpose-auditor/netexpose_auditor.ps1`

- [ ] **Step 1: Write the implementation**

Save to `OnPrem/Windows/netexpose-auditor/netexpose_auditor.ps1`:

```powershell
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
        return @($Target)
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
        return @($hosts)
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
            Severity       = 'MEDIUM'
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
        $invokeHostScanFn  = ${function:Invoke-HostScan}
        $testNetConnFn     = ${function:Test-NetConnection}

        $Hosts | ForEach-Object -Parallel {
            ${function:Test-NetConnection} = $using:testNetConnFn
            ${function:Invoke-HostScan}    = $using:invokeHostScanFn
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

$hosts = Expand-CidrRange -Target $Target
Write-Host "Hosts to scan: $($hosts.Count)"

Write-Host "Scanning for exposed services..."
$findings = Get-NetworkExposureFindings `
    -Hosts      $hosts `
    -Ports      $script:DEFAULT_PORTS `
    -ExtraPorts $ExtraPorts `
    -TimeoutMs  $TimeoutMs `
    -ThrottleLimit $ThrottleLimit `
    -Sequential:$Sequential

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
```

- [ ] **Step 2: Run tests — expect all green**

```bash
cd /home/declan/Claude/SecurityAuditScripts
/home/declan/bin/pwsh -Command "Invoke-Pester -Path OnPrem/Windows/netexpose-auditor/tests -Output Detailed"
```

Expected: All tests pass. If any fail, read the error and fix only the broken line.

- [ ] **Step 3: Commit**

```bash
git add OnPrem/Windows/netexpose-auditor/
git commit -m "feat(netexpose): add network exposure auditor — parallel LAN port scan (NE-01–NE-09)"
```

---

## Task 3: README

**Files:**
- Create: `OnPrem/Windows/netexpose-auditor/README.md`

- [ ] **Step 1: Write README**

Save to `OnPrem/Windows/netexpose-auditor/README.md`:

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add OnPrem/Windows/netexpose-auditor/README.md
git commit -m "docs(netexpose): add README"
```

---

## Task 4: Integration wiring

**Files:**
- Modify: `tools/exec_summary.py`
- Modify: `audit.py`
- Modify: `Run-Audit.ps1`
- Modify: `README.md`
- Modify: `tests/test_audit.py`

- [ ] **Step 1: Add to `KNOWN_PATTERNS` in `tools/exec_summary.py`**

Find:
```python
    "laps_report.json",
    "winpatch_report.json",
]
```

Replace with:
```python
    "laps_report.json",
    "winpatch_report.json",
    "netexpose_report.json",
]
```

- [ ] **Step 2: Add to `AZURE_WINDOWS_PATTERNS` in `tools/exec_summary.py`**

Find:
```python
    "laps_report.json",
    "winpatch_report.json",
]
```

(The second occurrence — inside `AZURE_WINDOWS_PATTERNS`.)

Replace with:
```python
    "laps_report.json",
    "winpatch_report.json",
    "netexpose_report.json",
]
```

- [ ] **Step 3: Add to `PILLAR_LABELS` in `tools/exec_summary.py`**

Find:
```python
    "winpatch": "Windows Patch Status",
}
```

Replace with:
```python
    "winpatch": "Windows Patch Status",
    "netexpose": "Network Exposure",
}
```

- [ ] **Step 4: Add to `WINDOWS_PS1` in `audit.py`**

Find:
```python
    "laps":         "OnPrem/Windows/laps-auditor/laps_auditor.ps1",
}
```

Replace with:
```python
    "laps":         "OnPrem/Windows/laps-auditor/laps_auditor.ps1",
    "netexpose":    "OnPrem/Windows/netexpose-auditor/netexpose_auditor.ps1",
}
```

- [ ] **Step 5: Update `WINDOWS_PS1` count in `tests/test_audit.py`**

Find:
```python
        self.assertEqual(len(audit.WINDOWS_PS1), 15)  # 7 Azure + m365/sharepoint/teams/intune/exchange + policy + azbackup + laps
```

Replace with:
```python
        self.assertEqual(len(audit.WINDOWS_PS1), 16)  # 7 Azure + m365/sharepoint/teams/intune/exchange + policy + azbackup + laps + netexpose
```

- [ ] **Step 6: Add to `$WindowsAuditors` in `Run-Audit.ps1`**

Find:
```powershell
$WindowsAuditors = @(
    @{ Name = 'laps';         Script = 'OnPrem\Windows\laps-auditor\laps_auditor.ps1';        Prefix = 'laps_report';         AllSubs = $false }
    @{ Name = 'winpatch';     Script = 'OnPrem\Windows\winpatch-auditor\winpatch_auditor.ps1'; Prefix = 'winpatch_report';     AllSubs = $false }
)
```

Replace with:
```powershell
$WindowsAuditors = @(
    @{ Name = 'laps';         Script = 'OnPrem\Windows\laps-auditor\laps_auditor.ps1';               Prefix = 'laps_report';         AllSubs = $false }
    @{ Name = 'winpatch';     Script = 'OnPrem\Windows\winpatch-auditor\winpatch_auditor.ps1';        Prefix = 'winpatch_report';     AllSubs = $false }
    @{ Name = 'netexpose';    Script = 'OnPrem\Windows\netexpose-auditor\netexpose_auditor.ps1';      Prefix = 'netexpose_report';    AllSubs = $false }
)
```

- [ ] **Step 7: Update root `README.md` — directory tree**

Find:
```
│   ├── winpatch-auditor/               # Windows Update patch currency and pending reboots
```

Replace with:
```
│   ├── winpatch-auditor/               # Windows Update patch currency and pending reboots
│   └── netexpose-auditor/              # LAN port scan — RDP/SMB/WinRM/LDAP exposure (NE-01–NE-09)
```

- [ ] **Step 8: Update root `README.md` — auditor table**

Find the winpatch auditor row:
```
| [Windows Patch Auditor](./OnPrem/Windows/winpatch-auditor/) |
```

(Find the full row, append after it.)

Find:
```markdown
| [Windows Patch Auditor](./OnPrem/Windows/winpatch-auditor/) | Audits Windows Update patch currency — last patch date, days since last patch, pending update count by category (security/critical/other), pending reboot flag, WSUS configuration, and per-patch pending list. Uses Windows Update COM API (PATCH-07/08) and registry (PATCH-01–06). | JSON, CSV, HTML |
```

Replace with:
```markdown
| [Windows Patch Auditor](./OnPrem/Windows/winpatch-auditor/) | Audits Windows Update patch currency — last patch date, days since last patch, pending update count by category (security/critical/other), pending reboot flag, WSUS configuration, and per-patch pending list. Uses Windows Update COM API (PATCH-07/08) and registry (PATCH-01–06). | JSON, CSV, HTML |
| [Network Exposure Auditor](./OnPrem/Windows/netexpose-auditor/) | Active LAN port scan from the assessor's machine. Probes each host in a target IP or CIDR range for dangerous exposed services: RDP (3389), SMB (445), NetBIOS (139), RPC (135), WinRM (5985/5986), LDAP (389/636), MSSQL (1433). Additional ports via -ExtraPorts. Uses ForEach-Object -Parallel for fast /24 scans. | JSON, CSV, HTML |
```

- [ ] **Step 9: Run Python tests to verify no regressions**

```bash
cd /home/declan/Claude/SecurityAuditScripts
python3 -m pytest tests/ -x -q --import-mode=importlib
```

Expected: All tests pass.

- [ ] **Step 10: Run full Pester suite to verify no regressions**

```bash
/home/declan/bin/pwsh -Command "Invoke-Pester -Path OnPrem/Windows/netexpose-auditor/tests -Output Detailed"
```

Expected: All netexpose tests pass.

- [ ] **Step 11: Commit**

```bash
git add tools/exec_summary.py audit.py Run-Audit.ps1 README.md tests/test_audit.py
git commit -m "feat(netexpose): wire network exposure auditor into Run-Audit.ps1, exec_summary, audit.py, README"
```
