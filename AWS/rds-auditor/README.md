# 🗄️ RDS Auditor

Audits RDS database instances and clusters across all AWS regions for security misconfigurations. Checks public accessibility, storage encryption, backup retention, deletion protection, IAM authentication, and multi-AZ deployment.

---

## ✨ Features

- Public accessibility flag — identifies instances directly reachable from the internet
- Storage encryption status — distinguishes AWS-managed vs customer-managed KMS keys
- Backup retention — flags instances with retention below 7 days
- Deletion protection — flags instances without deletion protection enabled
- IAM database authentication — flags instances not using IAM auth
- Multi-AZ deployment — flags single-AZ production instances
- Auto minor version upgrade status
- Multi-region sweep across all 18 standard AWS regions
- Numeric severity scoring (1–10)
- JSON, CSV, and colour-coded HTML output

---

## ⚙️ Requirements

- Python 3.7+
- `boto3` — `pip install boto3`

### IAM Permissions Required

```json
{
  "Effect": "Allow",
  "Action": [
    "rds:DescribeDBInstances",
    "rds:DescribeDBClusters",
    "ec2:DescribeRegions",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

---

## 🚀 Usage

### AWS CloudShell
1. Upload `rds_auditor.py` via **Actions → Upload file**
2. Run:
```bash
python3 rds_auditor.py
```

### Options

```bash
python3 rds_auditor.py --format html --output rds_report     # HTML only
python3 rds_auditor.py --format all                          # JSON + CSV + HTML
python3 rds_auditor.py --regions eu-west-1 us-east-1         # Specific regions
python3 rds_auditor.py --profile prod-account                # Specific AWS profile
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| Publicly accessible | +5 |
| Storage not encrypted | +3 |
| No deletion protection | +2 |
| Backup retention < 7 days | +1 |
| IAM auth disabled | +1 |
| Single-AZ deployment | +1 |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Publicly accessible database |
| 5–7 | HIGH | Unencrypted or public + multiple gaps |
| 2–4 | MEDIUM | Missing backup or deletion protection |
| 0–1 | LOW | Minor gaps only |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
