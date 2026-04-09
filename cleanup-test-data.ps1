<#
.SYNOPSIS
    Removes all audit test data seeded by seed-test-data.ps1.

.DESCRIPTION
    Deletes everything prefixed "audit-test-" from the tenant:
    users, guest accounts, app registrations, CA policies, custom roles,
    and the audit-test-rg resource group (which contains NSG, storage, KV).

.NOTES
    Run via: /snap/bin/pwsh -File cleanup-test-data.ps1
#>

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

$azCtx = Get-AzContext
if (-not $azCtx) { Write-Error "Run Connect-AzAccount first."; exit 1 }
$mgCtx = Get-MgContext
if (-not $mgCtx) { Write-Error "Run Connect-MgGraph first."; exit 1 }

Write-Host ""
Write-Host "━━━ 🧹 Cleaning up audit test data ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# ── Users (display name starts with "Audit Test -") ───────────────────────────
Write-Host "[1/5] Removing test users..." -ForegroundColor Yellow
$testUsers = Get-MgUser -Filter "startsWith(displayName,'Audit Test')" -All -ErrorAction SilentlyContinue
foreach ($u in $testUsers) {
    try {
        Remove-MgUser -UserId $u.Id
        Write-Host "  ✓ Deleted user: $($u.UserPrincipalName)" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed to delete $($u.UserPrincipalName): $($_.Exception.Message)"
    }
}

# Guest invited with audit-test-guest@example.com
$guestUpn = "audit-test-guest_example.com#EXT#@"
$guest = Get-MgUser -All -ErrorAction SilentlyContinue | Where-Object { $_.UserPrincipalName -like "$guestUpn*" }
foreach ($g in $guest) {
    try {
        Remove-MgUser -UserId $g.Id
        Write-Host "  ✓ Deleted guest: $($g.UserPrincipalName)" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed to delete guest: $($_.Exception.Message)"
    }
}

# ── App registrations + service principals ─────────────────────────────────────
Write-Host "[2/5] Removing test app registrations..." -ForegroundColor Yellow
$testApps = Get-MgApplication -Filter "startsWith(displayName,'audit-test')" -All -ErrorAction SilentlyContinue
foreach ($a in $testApps) {
    try {
        Remove-MgApplication -ApplicationId $a.Id
        Write-Host "  ✓ Deleted app: $($a.DisplayName)" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed to delete app $($a.DisplayName): $($_.Exception.Message)"
    }
}

# Orphaned service principals
$testSps = Get-MgServicePrincipal -Filter "startsWith(displayName,'audit-test')" -All -ErrorAction SilentlyContinue
foreach ($sp in $testSps) {
    try {
        Remove-MgServicePrincipal -ServicePrincipalId $sp.Id
        Write-Host "  ✓ Deleted SP: $($sp.DisplayName)" -ForegroundColor Green
    } catch { }  # May already be removed with app
}

# ── Conditional Access policies ────────────────────────────────────────────────
Write-Host "[3/5] Removing test CA policies..." -ForegroundColor Yellow
$testCa = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName -like 'audit-test-*' }
foreach ($p in $testCa) {
    try {
        Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $p.Id
        Write-Host "  ✓ Deleted CA policy: $($p.DisplayName)" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed to delete CA policy $($p.DisplayName): $($_.Exception.Message)"
    }
}

# ── Custom RBAC roles ──────────────────────────────────────────────────────────
Write-Host "[4/5] Removing test custom roles..." -ForegroundColor Yellow
$sub = Get-AzSubscription -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sub) {
    $testRoles = Get-AzRoleDefinition -Custom -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like 'audit-test-*' }
    foreach ($r in $testRoles) {
        try {
            Remove-AzRoleDefinition -Id $r.Id -Force
            Write-Host "  ✓ Deleted custom role: $($r.Name)" -ForegroundColor Green
        } catch {
            Write-Warning "  Failed to delete role $($r.Name): $($_.Exception.Message)"
        }
    }
}

# ── Resource group (NSG, Storage, Key Vault) ───────────────────────────────────
Write-Host "[5/5] Removing audit-test-rg resource group..." -ForegroundColor Yellow
if ($sub) {
    Set-AzContext -SubscriptionId $sub.Id | Out-Null
    $rg = Get-AzResourceGroup -Name "audit-test-rg" -ErrorAction SilentlyContinue
    if ($rg) {
        try {
            Remove-AzResourceGroup -Name "audit-test-rg" -Force -AsJob | Out-Null
            Write-Host "  ✓ Deletion of audit-test-rg queued (runs in background)" -ForegroundColor Green
        } catch {
            Write-Warning "  Failed to delete resource group: $($_.Exception.Message)"
        }
    } else {
        Write-Host "  audit-test-rg not found — nothing to delete" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  No subscription — skipping" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "━━━ ✅ Cleanup complete ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  Note: Key Vault soft-deleted items may need manual purge via:" -ForegroundColor Gray
Write-Host "  Remove-AzKeyVault -VaultName <name> -InRemovedState -Force -Location northeurope" -ForegroundColor Gray
Write-Host ""
