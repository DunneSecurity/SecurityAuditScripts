# ☁️ Cloud Audit Scripts

[![CI](https://github.com/Decdd19/SecurityAuditScripts/actions/workflows/ci.yml/badge.svg)](https://github.com/Decdd19/SecurityAuditScripts/actions/workflows/ci.yml)

A collection of security auditing scripts for AWS and other cloud platforms. Built for cloud security engineers, sysadmins, and anyone who wants visibility into their cloud environment without relying solely on commercial tooling.

> **Purpose:** Practical, standalone scripts that give you real security insight. No agents, no SaaS dependencies — just run and review.

---

## 📁 Repository Structure

```
SecurityAuditScripts/
├── README.md
├── AWS/
│   ├── README.md
│   ├── iam-privilege-mapper/       # IAM users, roles, privilege escalation
│   ├── s3-auditor/                 # S3 bucket public access, encryption, versioning
│   ├── cloudtrail-auditor/         # CloudTrail coverage and logging gaps
│   ├── sg-auditor/                 # Security group open ports and ingress rules
│   └── root-auditor/               # Root account MFA, access keys, password policy
└── Azure/
    ├── README.md
    ├── entra-auditor/              # Entra ID MFA, guest roles, app credentials, privesc
    ├── storage-auditor/            # Storage account public access, encryption, soft delete
    ├── activitylog-auditor/        # Activity Log diagnostic settings and alerting
    ├── nsg-auditor/                # NSG open ports, orphaned groups
    └── subscription-auditor/       # Defender for Cloud, PIM, Global Admin hygiene
```

---

## 🛠️ Scripts

### AWS

| Script | Description | Output |
|--------|-------------|--------|
| [IAM Privilege Mapper](./AWS/iam-privilege-mapper/) | Maps IAM users, roles, and groups. Identifies high-risk permissions, privilege escalation paths, stale credentials, and MFA gaps. | JSON, CSV, HTML |
| [S3 Bucket Auditor](./AWS/s3-auditor/) | Audits all S3 buckets for public access, missing encryption, versioning, logging, and lifecycle policies. | JSON, CSV, HTML |
| [CloudTrail Auditor](./AWS/cloudtrail-auditor/) | Checks CloudTrail coverage across all regions for logging gaps, missing KMS encryption, and CloudWatch integration. | JSON, CSV, HTML |
| [Security Group Auditor](./AWS/sg-auditor/) | Scans all security groups across all regions for dangerous open ports, unrestricted ingress, and unused groups. | JSON, CSV, HTML |
| [Root Account Auditor](./AWS/root-auditor/) | Audits root account security posture including MFA, access keys, password policy, and alternate contacts. | JSON, CSV, HTML |

### Azure

| Script | Description | Output |
|--------|-------------|--------|
| [Entra Auditor](./Azure/entra-auditor/) | Audits Entra ID users, guest access, app credentials, custom roles, and privilege escalation paths. | JSON, CSV, HTML |
| [Storage Auditor](./Azure/storage-auditor/) | Audits Storage Accounts for public access, shared key auth, encryption, soft delete, versioning, and logging. | JSON, CSV, HTML |
| [Activity Log Auditor](./Azure/activitylog-auditor/) | Checks Activity Log diagnostic settings for coverage, retention, missing categories, and alerting gaps. | JSON, CSV, HTML |
| [NSG Auditor](./Azure/nsg-auditor/) | Scans Network Security Groups for dangerous open ports, internet-exposed rules, and orphaned groups. | JSON, CSV, HTML |
| [Subscription Auditor](./Azure/subscription-auditor/) | Audits subscription posture including Defender for Cloud, permanent privileged roles, Global Admin hygiene, and budget alerts. | JSON, CSV, HTML |

---

## ⚙️ General Requirements

### AWS

- Python 3.7+
- `boto3` (`pip install boto3`)
- AWS credentials configured

Authentication order:
1. **AWS CloudShell** — credentials are pre-configured, just upload and run
2. **Environment variables:**
   ```bash
   export AWS_ACCESS_KEY_ID=your_key
   export AWS_SECRET_ACCESS_KEY=your_secret
   export AWS_DEFAULT_REGION=us-east-1
   ```
3. **AWS CLI profile** (`aws configure`) — most scripts support `--profile` flag
4. **IAM role** — if running on EC2/Lambda, the instance/execution role is used automatically

### Azure

- PowerShell 7+
- Az PowerShell module + Microsoft Graph SDK (see each script's README for exact modules)
- Active Az context (`Connect-AzAccount` already run)

```powershell
# Install core Az modules
Install-Module Az.Accounts, Az.Resources, Az.Network, Az.Storage, Az.Monitor, Az.Security -Scope CurrentUser

# Install Graph modules (required by entra-auditor and subscription-auditor)
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.Governance -Scope CurrentUser

Connect-AzAccount
```

---

## 🚀 Quick Start

### AWS
```bash
git clone https://github.com/Decdd19/SecurityAuditScripts.git
cd SecurityAuditScripts
pip install boto3
python3 AWS/iam-privilege-mapper/iam_mapper_v2.py --format html --output iam_report
```

### Azure
```powershell
git clone https://github.com/Decdd19/SecurityAuditScripts.git
cd SecurityAuditScripts
Connect-AzAccount
.\Azure\entra-auditor\entra_auditor.ps1 -Format html
```

---

## 📌 Notes

- Scripts are **read-only** — they query APIs and do not make any changes to your environment
- AWS scripts are designed to run in **AWS CloudShell**; Azure scripts run in **Azure CloudShell** or locally
- Output files are written to the current working directory unless specified otherwise
- All output files are created with owner-only permissions (600)
- AWS scripts support `--format` (json, csv, html, all) and `--profile` flags
- Azure scripts support `-Format` (json, csv, html, all, stdout) and `-AllSubscriptions` flags

---

## 🤝 Contributing

Feel free to open a PR or raise an issue if you have improvements, bug fixes, or want to add a script for another service.

---

## ⚠️ Disclaimer

These scripts are provided for **internal security auditing purposes only**. Always ensure you have appropriate authorisation before running security tooling against any cloud environment.
