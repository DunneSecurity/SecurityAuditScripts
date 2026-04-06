# M365/exchange-auditor/tests/exchange_auditor.Tests.ps1
BeforeAll {
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
    function Get-AzContext { @{ Tenant = @{ Id = 'tid-001' }; Account = @{ Id = 'admin@contoso.com' } } }

    . "$PSScriptRoot/../exchange_auditor.ps1"
}

# ---------------------------------------------------------------------------
# Get-ExchangeTransportRuleFindings
# ---------------------------------------------------------------------------

Describe 'Get-ExchangeTransportRuleFindings' {
    It 'flags EX-01 when a transport rule redirects to external address' {
        Mock Get-TransportRule {
            @([PSCustomObject]@{
                Name               = 'Fwd to external'
                Enabled            = $true
                RedirectMessageTo  = @('attacker@evil.com')
                BlindCopyTo        = @()
                AddToRecipients    = @()
                SetSCL             = $null
            })
        }
        $findings = Get-ExchangeTransportRuleFindings -TenantDomain 'contoso.com'
        $f = $findings | Where-Object { $_.FindingType -eq 'TransportRuleExternalForwarding' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'CRITICAL'
        $f.CisControl | Should -Match '^CIS'
    }

    It 'does not flag EX-01 when redirect is to internal address' {
        Mock Get-TransportRule {
            @([PSCustomObject]@{
                Name               = 'Fwd to internal'
                Enabled            = $true
                RedirectMessageTo  = @('internal@contoso.com')
                BlindCopyTo        = @()
                AddToRecipients    = @()
                SetSCL             = $null
            })
        }
        $findings = Get-ExchangeTransportRuleFindings -TenantDomain 'contoso.com'
        ($findings | Where-Object { $_.FindingType -eq 'TransportRuleExternalForwarding' }) | Should -BeNullOrEmpty
    }

    It 'flags EX-02 when a transport rule sets SCL to -1 (bypass spam filter)' {
        Mock Get-TransportRule {
            @([PSCustomObject]@{
                Name               = 'Bypass spam filter'
                Enabled            = $true
                RedirectMessageTo  = @()
                BlindCopyTo        = @()
                AddToRecipients    = @()
                SetSCL             = -1
            })
        }
        $findings = Get-ExchangeTransportRuleFindings -TenantDomain 'contoso.com'
        $f = $findings | Where-Object { $_.FindingType -eq 'TransportRuleBypassesFiltering' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'CRITICAL'
    }

    It 'returns empty when no transport rules exist' {
        Mock Get-TransportRule { @() }
        $findings = Get-ExchangeTransportRuleFindings -TenantDomain 'contoso.com'
        $findings | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-ExchangeRemoteDomainFindings
# ---------------------------------------------------------------------------

Describe 'Get-ExchangeRemoteDomainFindings' {
    It 'flags EX-03 when Default remote domain allows auto-forward' {
        Mock Get-RemoteDomain {
            @([PSCustomObject]@{ Identity = 'Default'; AutoForwardEnabled = $true })
        }
        $findings = Get-ExchangeRemoteDomainFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'RemoteDomainAutoForwardEnabled' }
        $f | Should -Not -BeNullOrEmpty
        $f.Resource | Should -Be 'Default'
        $f.Severity | Should -Be 'CRITICAL'
    }

    It 'does not flag EX-03 when auto-forward is disabled' {
        Mock Get-RemoteDomain {
            @([PSCustomObject]@{ Identity = 'Default'; AutoForwardEnabled = $false })
        }
        $findings = Get-ExchangeRemoteDomainFindings
        $findings | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-ExchangeMailboxPermissionFindings
# ---------------------------------------------------------------------------

Describe 'Get-ExchangeMailboxPermissionFindings' {
    It 'flags EX-04 when a non-admin has FullAccess to a mailbox' {
        Mock Get-Mailbox {
            @([PSCustomObject]@{
                UserPrincipalName  = 'alice@contoso.com'
                RecipientTypeDetails = 'UserMailbox'
                AuditEnabled       = $true
                ExternalDirectoryObjectId = 'oid-alice'
            })
        }
        Mock Get-MailboxPermission {
            @(
                [PSCustomObject]@{ User = 'NT AUTHORITY\SELF'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false }
                [PSCustomObject]@{ User = 'bob@contoso.com';   AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false }
            )
        }
        $findings = Get-ExchangeMailboxPermissionFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'MailboxFullAccessDelegation' }
        $f | Should -Not -BeNullOrEmpty
        $f.Resource | Should -Match 'alice@contoso.com'
    }

    It 'does not flag EX-04 for SELF permission' {
        Mock Get-Mailbox {
            @([PSCustomObject]@{
                UserPrincipalName  = 'alice@contoso.com'
                RecipientTypeDetails = 'UserMailbox'
                AuditEnabled       = $true
                ExternalDirectoryObjectId = 'oid-alice'
            })
        }
        Mock Get-MailboxPermission {
            @([PSCustomObject]@{ User = 'NT AUTHORITY\SELF'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false })
        }
        $findings = Get-ExchangeMailboxPermissionFindings
        ($findings | Where-Object { $_.FindingType -eq 'MailboxFullAccessDelegation' }) | Should -BeNullOrEmpty
    }

    It 'flags EX-06 when mailbox audit logging is disabled' {
        Mock Get-Mailbox {
            @([PSCustomObject]@{
                UserPrincipalName  = 'alice@contoso.com'
                RecipientTypeDetails = 'UserMailbox'
                AuditEnabled       = $false
                ExternalDirectoryObjectId = 'oid-alice'
            })
        }
        Mock Get-MailboxPermission { @() }
        $findings = Get-ExchangeMailboxPermissionFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'MailboxAuditLoggingDisabled' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
    }
}

# ---------------------------------------------------------------------------
# Get-ExchangeSharedMailboxFindings
# ---------------------------------------------------------------------------

Describe 'Get-ExchangeSharedMailboxFindings' {
    It 'flags EX-05 when shared mailbox account is enabled for sign-in' {
        Mock Get-Mailbox {
            @([PSCustomObject]@{
                UserPrincipalName         = 'info@contoso.com'
                RecipientTypeDetails      = 'SharedMailbox'
                AuditEnabled              = $true
                ExternalDirectoryObjectId = 'oid-info'
            })
        }
        Mock Get-MgUser {
            [PSCustomObject]@{ AccountEnabled = $true }
        }
        $findings = Get-ExchangeSharedMailboxFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'SharedMailboxSignInNotBlocked' }
        $f | Should -Not -BeNullOrEmpty
        $f.Resource | Should -Be 'info@contoso.com'
        $f.Severity | Should -Be 'HIGH'
    }

    It 'does not flag EX-05 when shared mailbox account is blocked' {
        Mock Get-Mailbox {
            @([PSCustomObject]@{
                UserPrincipalName         = 'info@contoso.com'
                RecipientTypeDetails      = 'SharedMailbox'
                AuditEnabled              = $true
                ExternalDirectoryObjectId = 'oid-info'
            })
        }
        Mock Get-MgUser {
            [PSCustomObject]@{ AccountEnabled = $false }
        }
        $findings = Get-ExchangeSharedMailboxFindings
        ($findings | Where-Object { $_.FindingType -eq 'SharedMailboxSignInNotBlocked' }) | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-ExchangeAuditFindings
# ---------------------------------------------------------------------------

Describe 'Get-ExchangeAuditFindings' {
    It 'flags EX-07 when admin audit log is disabled' {
        Mock Get-AdminAuditLogConfig {
            [PSCustomObject]@{ AdminAuditLogEnabled = $false }
        }
        $findings = Get-ExchangeAuditFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'AdminAuditLoggingDisabled' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
    }

    It 'does not flag EX-07 when admin audit log is enabled' {
        Mock Get-AdminAuditLogConfig {
            [PSCustomObject]@{ AdminAuditLogEnabled = $true }
        }
        $findings = Get-ExchangeAuditFindings
        ($findings | Where-Object { $_.FindingType -eq 'AdminAuditLoggingDisabled' }) | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-ExchangeSmtpAuthFindings
# ---------------------------------------------------------------------------

Describe 'Get-ExchangeSmtpAuthFindings' {
    It 'flags EX-08 when SMTP AUTH is enabled on a mailbox' {
        Mock Get-Mailbox {
            @([PSCustomObject]@{
                UserPrincipalName  = 'alice@contoso.com'
                RecipientTypeDetails = 'UserMailbox'
                AuditEnabled       = $true
                ExternalDirectoryObjectId = 'oid-alice'
            })
        }
        Mock Get-CASMailbox {
            [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $false }
        }
        $findings = Get-ExchangeSmtpAuthFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'SmtpAuthEnabledOnMailbox' }
        $f | Should -Not -BeNullOrEmpty
        $f.Resource | Should -Be 'alice@contoso.com'
        $f.Severity | Should -Be 'HIGH'
    }

    It 'does not flag EX-08 when SMTP AUTH is disabled' {
        Mock Get-Mailbox {
            @([PSCustomObject]@{
                UserPrincipalName  = 'alice@contoso.com'
                RecipientTypeDetails = 'UserMailbox'
                AuditEnabled       = $true
                ExternalDirectoryObjectId = 'oid-alice'
            })
        }
        Mock Get-CASMailbox {
            [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $true }
        }
        $findings = Get-ExchangeSmtpAuthFindings
        $findings | Should -BeNullOrEmpty
    }
}
