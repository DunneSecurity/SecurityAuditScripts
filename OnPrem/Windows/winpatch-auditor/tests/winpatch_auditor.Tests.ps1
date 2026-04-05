# OnPrem/Windows/winpatch-auditor/tests/winpatch_auditor.Tests.ps1
BeforeAll {
    function Get-HotFix      { param([string]$Id) @() }
    function Get-CimInstance { param([string]$ClassName) [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-1) } }
    function Get-Service     { param([string]$Name, [string]$ErrorAction) [PSCustomObject]@{ Status = 'Running'; StartType = 'Automatic' } }
    function Get-ItemProperty { param($Path, $Name, $ErrorAction) $null }
    . "$PSScriptRoot/../winpatch_auditor.ps1"
}

Describe 'Get-WinPatchFindings' {
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
