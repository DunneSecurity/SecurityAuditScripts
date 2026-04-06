# M365/sharepoint-auditor/tests/sharepoint_auditor.Tests.ps1
BeforeAll {
    function Connect-MgGraph     { param($Scopes, [switch]$NoWelcome) }
    function Get-MgContext       { $null }
    function Connect-SPOService  { param($Url) }
    function Get-SPOTenant       { $null }
    function Get-SPOSite         { param($IncludePersonalSite, $Limit) @() }
    function Disconnect-SPOService { }
    function Get-AzContext { @{ Tenant = @{ Id = 'tid-001' }; Account = @{ Id = 'admin@contoso.com' } } }

    . "$PSScriptRoot/../sharepoint_auditor.ps1"
}

# ---------------------------------------------------------------------------
# Get-SharePointTenantFindings
# ---------------------------------------------------------------------------

Describe 'Get-SharePointTenantFindings' {
    It 'flags SP-01 when SharingCapability is ExternalUserAndGuestSharing' {
        Mock Get-SPOTenant {
            [PSCustomObject]@{
                SharingCapability                  = 'ExternalUserAndGuestSharing'
                RequireAnonymousLinksExpireInDays  = 30
                OneDriveSharingCapability          = 'ExistingExternalUserSharingOnly'
                DefaultSharingLinkType             = 'Direct'
                SharingAllowedDomainList           = @('trusted.com')
            }
        }
        $findings = Get-SharePointTenantFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'TenantExternalSharingAnyone' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'CRITICAL'
        $f.CisControl | Should -Match '^CIS'
    }

    It 'does not flag SP-01 when SharingCapability is ExistingExternalUserSharingOnly' {
        Mock Get-SPOTenant {
            [PSCustomObject]@{
                SharingCapability                  = 'ExistingExternalUserSharingOnly'
                RequireAnonymousLinksExpireInDays  = 30
                OneDriveSharingCapability          = 'ExistingExternalUserSharingOnly'
                DefaultSharingLinkType             = 'Direct'
                SharingAllowedDomainList           = @('trusted.com')
            }
        }
        $findings = Get-SharePointTenantFindings
        ($findings | Where-Object { $_.FindingType -eq 'TenantExternalSharingAnyone' }) | Should -BeNullOrEmpty
    }

    It 'flags SP-02 when RequireAnonymousLinksExpireInDays is 0' {
        Mock Get-SPOTenant {
            [PSCustomObject]@{
                SharingCapability                  = 'ExistingExternalUserSharingOnly'
                RequireAnonymousLinksExpireInDays  = 0
                OneDriveSharingCapability          = 'ExistingExternalUserSharingOnly'
                DefaultSharingLinkType             = 'Direct'
                SharingAllowedDomainList           = @('trusted.com')
            }
        }
        $findings = Get-SharePointTenantFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'AnonymousLinkNoExpiry' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
    }

    It 'does not flag SP-02 when expiry is set' {
        Mock Get-SPOTenant {
            [PSCustomObject]@{
                SharingCapability                  = 'ExistingExternalUserSharingOnly'
                RequireAnonymousLinksExpireInDays  = 30
                OneDriveSharingCapability          = 'ExistingExternalUserSharingOnly'
                DefaultSharingLinkType             = 'Direct'
                SharingAllowedDomainList           = @('trusted.com')
            }
        }
        $findings = Get-SharePointTenantFindings
        ($findings | Where-Object { $_.FindingType -eq 'AnonymousLinkNoExpiry' }) | Should -BeNullOrEmpty
    }

    It 'flags SP-04 when OneDriveSharingCapability is ExternalUserAndGuestSharing' {
        Mock Get-SPOTenant {
            [PSCustomObject]@{
                SharingCapability                  = 'ExistingExternalUserSharingOnly'
                RequireAnonymousLinksExpireInDays  = 30
                OneDriveSharingCapability          = 'ExternalUserAndGuestSharing'
                DefaultSharingLinkType             = 'Direct'
                SharingAllowedDomainList           = @('trusted.com')
            }
        }
        $findings = Get-SharePointTenantFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'OneDriveExternalSharingUnrestricted' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'HIGH'
    }

    It 'flags SP-05 when DefaultSharingLinkType is AnonymousAccess' {
        Mock Get-SPOTenant {
            [PSCustomObject]@{
                SharingCapability                  = 'ExistingExternalUserSharingOnly'
                RequireAnonymousLinksExpireInDays  = 30
                OneDriveSharingCapability          = 'ExistingExternalUserSharingOnly'
                DefaultSharingLinkType             = 'AnonymousAccess'
                SharingAllowedDomainList           = @('trusted.com')
            }
        }
        $findings = Get-SharePointTenantFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'AnonymousLinksFound' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'CRITICAL'
    }

    It 'flags SP-06 when SharingAllowedDomainList is empty and sharing is not disabled' {
        Mock Get-SPOTenant {
            [PSCustomObject]@{
                SharingCapability                  = 'ExistingExternalUserSharingOnly'
                RequireAnonymousLinksExpireInDays  = 30
                OneDriveSharingCapability          = 'ExistingExternalUserSharingOnly'
                DefaultSharingLinkType             = 'Direct'
                SharingAllowedDomainList           = @()
            }
        }
        $findings = Get-SharePointTenantFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'ExternalSharingNoDomainRestriction' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'MEDIUM'
    }

    It 'returns empty when Get-SPOTenant returns null' {
        Mock Get-SPOTenant { $null }
        $findings = Get-SharePointTenantFindings
        $findings | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
# Get-SharePointSiteFindings
# ---------------------------------------------------------------------------

Describe 'Get-SharePointSiteFindings' {
    It 'flags SP-03 when a site is more permissive than tenant default' {
        Mock Get-SPOTenant {
            [PSCustomObject]@{
                SharingCapability                  = 'ExistingExternalUserSharingOnly'
                RequireAnonymousLinksExpireInDays  = 30
                OneDriveSharingCapability          = 'ExistingExternalUserSharingOnly'
                DefaultSharingLinkType             = 'Direct'
                SharingAllowedDomainList           = @('trusted.com')
            }
        }
        Mock Get-SPOSite {
            @([PSCustomObject]@{
                Url               = 'https://contoso.sharepoint.com/sites/public'
                SharingCapability = 'ExternalUserAndGuestSharing'
            })
        }
        $findings = Get-SharePointSiteFindings
        $f = $findings | Where-Object { $_.FindingType -eq 'SitePermissiveSharing' }
        $f | Should -Not -BeNullOrEmpty
        $f.Resource | Should -Be 'https://contoso.sharepoint.com/sites/public'
        $f.Severity | Should -Be 'HIGH'
    }

    It 'does not flag SP-03 when site is at same level as tenant' {
        Mock Get-SPOTenant {
            [PSCustomObject]@{
                SharingCapability                  = 'ExistingExternalUserSharingOnly'
                RequireAnonymousLinksExpireInDays  = 30
                OneDriveSharingCapability          = 'ExistingExternalUserSharingOnly'
                DefaultSharingLinkType             = 'Direct'
                SharingAllowedDomainList           = @('trusted.com')
            }
        }
        Mock Get-SPOSite {
            @([PSCustomObject]@{
                Url               = 'https://contoso.sharepoint.com/sites/intranet'
                SharingCapability = 'ExistingExternalUserSharingOnly'
            })
        }
        $findings = Get-SharePointSiteFindings
        $findings | Should -BeNullOrEmpty
    }

    It 'returns empty when no sites returned' {
        Mock Get-SPOTenant {
            [PSCustomObject]@{
                SharingCapability                  = 'ExistingExternalUserSharingOnly'
                RequireAnonymousLinksExpireInDays  = 30
                OneDriveSharingCapability          = 'ExistingExternalUserSharingOnly'
                DefaultSharingLinkType             = 'Direct'
                SharingAllowedDomainList           = @('trusted.com')
            }
        }
        Mock Get-SPOSite { @() }
        $findings = Get-SharePointSiteFindings
        $findings | Should -BeNullOrEmpty
    }
}
