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
