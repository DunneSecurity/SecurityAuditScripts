# sharepoint-auditor

Audits SharePoint Online and OneDrive external sharing posture.

## Checks

| ID | Finding | Severity |
|----|---------|----------|
| SP-01 | Tenant allows anonymous ("Anyone") sharing | CRITICAL |
| SP-02 | Anonymous links have no expiry | HIGH |
| SP-03 | Sites more permissive than tenant default | HIGH |
| SP-04 | OneDrive external sharing unrestricted | HIGH |
| SP-05 | Default sharing link type is anonymous | CRITICAL |
| SP-06 | External sharing not restricted to allowed domains | MEDIUM |

## Requirements

- SharePoint Online Management Shell: `Install-Module Microsoft.Online.SharePoint.PowerShell`
- Connected to SPO admin: `Connect-SPOService -Url https://<tenant>-admin.sharepoint.com`
- SPO Admin role

## Usage

```powershell
.\sharepoint_auditor.ps1 -TenantDomain contoso.com
.\sharepoint_auditor.ps1 -TenantDomain contoso.com -Format json
.\sharepoint_auditor.ps1 -Output ./reports/sharepoint_report -Format all
```

## Output

Produces `sharepoint_report.json`, `sharepoint_report.csv`, `sharepoint_report.html`.
