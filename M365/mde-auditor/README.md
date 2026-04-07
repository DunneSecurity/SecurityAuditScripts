# Defender for Endpoint Auditor

Audits Microsoft Defender for Endpoint (MDE) device security posture via Microsoft Graph. Distinct from `defender-auditor` which covers Defender for Cloud (CSPM).

## Checks

| ID | FindingType | Severity | Description |
|----|-------------|----------|-------------|
| MDE-01 | DeviceNotOnboardedToMde | CRITICAL | Windows device not onboarded to Defender for Endpoint |
| MDE-02 | RtpDisabled | HIGH | Real-time protection disabled (antivirusStatus ≠ monitored) |
| MDE-03 | DeviceNotEncrypted | HIGH | BitLocker not enabled on Windows device |
| MDE-04 | TamperProtectionDisabled | HIGH | Tamper protection disabled — AV settings can be changed by malware |
| MDE-05 | StaleAntiVirusScan | MEDIUM | No antivirus scan in >7 days, or device has never been scanned |

## Requirements

- PowerShell 7+
- `Install-Module Microsoft.Graph`
- Scopes: `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`
- Intune/MDE administrator or Global reader role
- Licence: M365 Business Premium or Microsoft Defender for Endpoint Plan 1/2

## Usage

```powershell
.\mde_auditor.ps1
.\mde_auditor.ps1 -Format json
.\mde_auditor.ps1 -TenantDomain contoso.com -Format all
```

## Output

Produces `mde_report.json`, `mde_report.csv`, `mde_report.html`.

Findings are per check-type (not per device) — up to 10 affected device names are listed in the `resource` field.
