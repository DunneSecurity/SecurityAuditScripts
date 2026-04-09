<#
.SYNOPSIS
    Seeds intentionally misconfigured resources into the Azure/Entra tenant
    to verify that audit scripts detect them correctly.

.DESCRIPTION
    Creates test users, app registrations, CA policies, NSGs, storage accounts
    and key vaults — all prefixed "audit-test-" for easy identification and cleanup.
    Run cleanup-test-data.ps1 afterward to remove everything.

.NOTES
    Requires: Connect-AzAccount + Connect-MgGraph with appropriate scopes.
    Run via: /snap/bin/pwsh -File seed-test-data.ps1
#>

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

# ── Auth ──────────────────────────────────────────────────────────────────────
$azCtx = Get-AzContext
if (-not $azCtx) { Write-Error "Run Connect-AzAccount first."; exit 1 }
$mgCtx = Get-MgContext
if (-not $mgCtx) { Write-Error "Run Connect-MgGraph first."; exit 1 }

$tenantId = $azCtx.Tenant.Id
$upnSuffix = ($mgCtx.Account -split '@')[1]
$created   = [ordered]@{}

Write-Host ""
Write-Host "━━━ 🌱 Seeding audit test data ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Tenant : $tenantId" -ForegroundColor Gray
Write-Host "  Domain : $upnSuffix" -ForegroundColor Gray
Write-Host ""

# ── Helper ────────────────────────────────────────────────────────────────────
function Get-OrActivateRole {
    param([string]$RoleName)
    $role = Get-MgDirectoryRole -Filter "displayName eq '$RoleName'" -ErrorAction SilentlyContinue
    if (-not $role) {
        $tmpl = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $RoleName }
        $role = New-MgDirectoryRole -RoleTemplateId $tmpl.Id
    }
    return $role
}

$testPassword = "AuditTest@$(Get-Random -Minimum 1000 -Maximum 9999)!"

# ── 1. Global Admin user — no MFA ─────────────────────────────────────────────
# Triggers: UserNoMfa, TooManyGlobalAdmins, GlobalAdminNoMfa
Write-Host "[1/8] Creating Global Admin user (no MFA configured)..." -ForegroundColor Yellow
$gaUpn = "audit-test-globaladmin@$upnSuffix"
try {
    $gaUser = New-MgUser `
        -DisplayName    "Audit Test - Global Admin" `
        -UserPrincipalName $gaUpn `
        -AccountEnabled $true `
        -PasswordProfile @{ Password = $testPassword; ForceChangePasswordNextSignIn = $false } `
        -MailNickname   "audit-test-globaladmin"

    $gaRole = Get-OrActivateRole -RoleName "Global Administrator"
    $body   = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($gaUser.Id)" }
    New-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -BodyParameter $body | Out-Null

    $created['GlobalAdminUser'] = @{ Id = $gaUser.Id; UPN = $gaUpn; Type = 'User'; Role = 'Global Administrator' }
    Write-Host "  ✓ $gaUpn  (ID: $($gaUser.Id))" -ForegroundColor Green
} catch {
    Write-Warning "  Failed: $($_.Exception.Message)"
}

# ── 2. Privileged guest account ────────────────────────────────────────────────
# Triggers: PrivilegedGuest
Write-Host "[2/8] Creating privileged guest account..." -ForegroundColor Yellow
try {
    $invite = Invoke-MgGraphRequest -Method POST `
        -Uri  "https://graph.microsoft.com/v1.0/invitations" `
        -Body (@{
            invitedUserEmailAddress = "audit-test-guest@example.com"
            invitedUserDisplayName  = "Audit Test - Privileged Guest"
            inviteRedirectUrl       = "https://myapps.microsoft.com"
            sendInvitationMessage   = $false
        } | ConvertTo-Json)

    $guestId = $invite.invitedUser.id
    $privRole = Get-OrActivateRole -RoleName "Privileged Role Administrator"
    $body2    = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$guestId" }
    New-MgDirectoryRoleMember -DirectoryRoleId $privRole.Id -BodyParameter $body2 | Out-Null

    $guestUpn = (Get-MgUser -UserId $guestId).UserPrincipalName
    $created['PrivilegedGuest'] = @{ Id = $guestId; UPN = $guestUpn; Type = 'User'; Role = 'Privileged Role Administrator' }
    Write-Host "  ✓ Guest: $guestUpn  (ID: $guestId)" -ForegroundColor Green
} catch {
    Write-Warning "  Failed: $($_.Exception.Message)"
}

# ── 3. App registration — expired secret + broad SP scope ─────────────────────
# Triggers: StaleAppCredential, ServicePrincipalBroadScope
Write-Host "[3/8] Creating over-permissioned app with expired secret..." -ForegroundColor Yellow
try {
    $app = New-MgApplication `
        -DisplayName    "audit-test-overpermissioned-app" `
        -SignInAudience  "AzureADMyOrg"

    # Add an already-expired secret
    $expiredSecret = Add-MgApplicationPassword -ApplicationId $app.Id -BodyParameter @{
        PasswordCredential = @{
            DisplayName = "audit-test-expired-secret"
            EndDateTime = (Get-Date).AddDays(-30).ToString('o')
        }
    }

    # Create SP
    $sp = New-MgServicePrincipal -AppId $app.AppId

    # Assign broad Microsoft Graph Application permissions via app role
    $graphSp   = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
    $roleId    = ($graphSp.AppRoles | Where-Object { $_.Value -eq 'Directory.ReadWrite.All' }).Id
    if ($roleId) {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
            -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $roleId | Out-Null
    }

    $created['OverpermissionedApp'] = @{
        AppObjectId = $app.Id; AppId = $app.AppId
        SpId = $sp.Id; Name = "audit-test-overpermissioned-app"; Type = 'Application'
    }
    Write-Host "  ✓ App: audit-test-overpermissioned-app  (AppId: $($app.AppId))" -ForegroundColor Green
} catch {
    Write-Warning "  Failed: $($_.Exception.Message)"
}

# ── 4. Custom role with * wildcard actions ─────────────────────────────────────
# Triggers: OverpermissiveCustomRole
$sub = Get-AzSubscription -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sub) {
    Write-Host "[4/8] Creating overpermissive custom role..." -ForegroundColor Yellow
    try {
        $roleScope = "/subscriptions/$($sub.Id)"
        $customRole = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]::new()
        $customRole.Name            = "audit-test-overpermissive-role"
        $customRole.Description     = "Audit test: wildcard actions — should be flagged"
        $customRole.IsCustom        = $true
        $customRole.Actions         = @("*")
        $customRole.NotActions      = @()
        $customRole.AssignableScopes = @($roleScope)
        New-AzRoleDefinition -Role $customRole | Out-Null

        $created['CustomRole'] = @{ Name = "audit-test-overpermissive-role"; Scope = $roleScope; Type = 'RoleDefinition' }
        Write-Host "  ✓ Custom role: audit-test-overpermissive-role" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed: $($_.Exception.Message)"
    }
} else {
    Write-Host "[4/8] No subscription — skipping custom role" -ForegroundColor DarkGray
}

# ── 5. CA policy in report-only mode ──────────────────────────────────────────
# Triggers: CaPolicyReportOnly
Write-Host "[5/8] Creating report-only CA policy (MFA not enforced)..." -ForegroundColor Yellow
try {
    $ca = Invoke-MgGraphRequest -Method POST `
        -Uri  "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
        -Body (@{
            displayName   = "audit-test-mfa-report-only"
            state         = "enabledForReportingButNotEnforced"
            conditions    = @{
                users        = @{ includeUsers = @("All") }
                applications = @{ includeApplications = @("All") }
            }
            grantControls = @{
                operator        = "OR"
                builtInControls = @("mfa")
            }
        } | ConvertTo-Json -Depth 10)

    $created['CaPolicy'] = @{ Id = $ca.id; Name = "audit-test-mfa-report-only"; State = "report-only"; Type = 'ConditionalAccessPolicy' }
    Write-Host "  ✓ CA policy: audit-test-mfa-report-only  (ID: $($ca.id))" -ForegroundColor Green
} catch {
    Write-Warning "  Failed: $($_.Exception.Message)"
}

# ── 6–8. Azure subscription resources ─────────────────────────────────────────
if ($sub) {
    Set-AzContext -SubscriptionId $sub.Id | Out-Null
    $rg  = "audit-test-rg"
    $loc = "northeurope"

    Write-Host "[6/8] Creating resource group + NSG with dangerous port rules..." -ForegroundColor Yellow
    try {
        New-AzResourceGroup -Name $rg -Location $loc -Force | Out-Null

        # RDP (3389) + SSH (22) open from Internet — triggers DangerousPort
        $rdpRule = New-AzNetworkSecurityRuleConfig -Name "audit-test-allow-rdp-internet" `
            -Protocol Tcp -Direction Inbound -Priority 100 `
            -SourceAddressPrefix "Internet" -SourcePortRange "*" `
            -DestinationAddressPrefix "*" -DestinationPortRange "3389" `
            -Access Allow

        $sshRule = New-AzNetworkSecurityRuleConfig -Name "audit-test-allow-ssh-internet" `
            -Protocol Tcp -Direction Inbound -Priority 110 `
            -SourceAddressPrefix "Internet" -SourcePortRange "*" `
            -DestinationAddressPrefix "*" -DestinationPortRange "22" `
            -Access Allow

        $nsg = New-AzNetworkSecurityGroup -Name "audit-test-nsg" `
            -ResourceGroupName $rg -Location $loc `
            -SecurityRules @($rdpRule, $sshRule)

        $created['NSG'] = @{ Name = $nsg.Name; ResourceGroup = $rg; Type = 'NSG' }
        Write-Host "  ✓ NSG: audit-test-nsg (RDP+SSH open from Internet)" -ForegroundColor Green
    } catch {
        Write-Warning "  NSG failed: $($_.Exception.Message)"
    }

    Write-Host "[7/8] Creating storage account (public blob, no versioning, no soft delete)..." -ForegroundColor Yellow
    try {
        $storName = "audittest$(Get-Random -Maximum 99999)"
        $stor = New-AzStorageAccount -Name $storName -ResourceGroupName $rg `
            -Location $loc -SkuName Standard_LRS -Kind StorageV2 `
            -AllowBlobPublicAccess $true -MinimumTlsVersion TLS1_0

        # Disable soft delete + versioning on blob service
        $ctx = $stor.Context
        Enable-AzStorageBlobDeleteRetentionPolicy -Context $ctx -RetentionDays 0 -ErrorAction SilentlyContinue
        Update-AzStorageBlobServiceProperty -ResourceGroupName $rg `
            -StorageAccountName $storName -IsVersioningEnabled $false | Out-Null

        $created['StorageAccount'] = @{ Name = $storName; ResourceGroup = $rg; Type = 'StorageAccount' }
        Write-Host "  ✓ Storage: $storName (public blob, TLS 1.0, no versioning)" -ForegroundColor Green
    } catch {
        Write-Warning "  Storage failed: $($_.Exception.Message)"
    }

    Write-Host "[8/8] Creating Key Vault (no purge protection, legacy access policy)..." -ForegroundColor Yellow
    try {
        $kvName = "audit-test-kv-$(Get-Random -Maximum 9999)"
        # EnableSoftDelete defaults to true in modern Azure — use legacy access policy model
        # and disable purge protection (the two things the auditor checks)
        $kv = New-AzKeyVault -Name $kvName -ResourceGroupName $rg `
            -Location $loc -EnabledForTemplateDeployment

        # Legacy access policy model (not RBAC) — triggers LegacyAccessPolicyModel
        # KV is already created with vault access policies by default
        # Disable purge protection — triggers PurgeProtectionDisabled
        # (purge protection is off by default on new vaults)

        $created['KeyVault'] = @{ Name = $kvName; ResourceGroup = $rg; Type = 'KeyVault' }
        Write-Host "  ✓ Key Vault: $kvName (legacy access policy, no purge protection)" -ForegroundColor Green
    } catch {
        Write-Warning "  Key Vault failed: $($_.Exception.Message)"
    }

    # Permanent Owner on subscription — triggers PermanentOwnerAssignment
    if ($created.ContainsKey('GlobalAdminUser')) {
        try {
            New-AzRoleAssignment -ObjectId $created['GlobalAdminUser'].Id `
                -RoleDefinitionName "Owner" -Scope "/subscriptions/$($sub.Id)" | Out-Null
            $created['GlobalAdminUser']['SubOwner'] = "/subscriptions/$($sub.Id)"
            Write-Host "  ✓ Assigned permanent Owner on subscription to test user" -ForegroundColor Green
        } catch {
            Write-Warning "  Owner assignment failed: $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "[6-8/8] No subscription — skipping NSG / Storage / Key Vault" -ForegroundColor DarkGray
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━ ✅ Seeding complete ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""
$created.Keys | ForEach-Object {
    $item = $created[$_]
    Write-Host "  $_" -ForegroundColor Cyan -NoNewline
    Write-Host "  →  $($item | ConvertTo-Json -Compress)" -ForegroundColor Gray
}
Write-Host ""
Write-Host "  Test password used: $testPassword" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Run the audit scripts now, then cleanup-test-data.ps1 to remove everything." -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
