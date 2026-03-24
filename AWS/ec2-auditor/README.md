# 🖥️ EC2 Auditor

Audits EC2 instances across all AWS regions for common security misconfigurations. Checks IMDSv2 enforcement, EBS encryption, public IP exposure, public snapshots, IAM instance profiles, and default VPC usage.

---

## ✨ Features

- IMDSv2 enforcement — flags instances still allowing IMDSv1 token-optional access
- EBS root and data volume encryption status
- Public IP assignment — flags instances with a public IP
- Public AMI snapshots — identifies snapshots shared with all AWS accounts
- IAM instance profile — flags instances with no profile attached
- Default VPC usage — flags instances running inside the default VPC
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
    "ec2:DescribeInstances",
    "ec2:DescribeSnapshots",
    "ec2:DescribeVolumes",
    "ec2:DescribeVpcs",
    "ec2:DescribeRegions",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

---

## 🚀 Usage

### AWS CloudShell
1. Upload `ec2_auditor.py` via **Actions → Upload file**
2. Run:
```bash
python3 ec2_auditor.py
```

### Options

```bash
python3 ec2_auditor.py --format html --output ec2_report     # HTML only
python3 ec2_auditor.py --format all                          # JSON + CSV + HTML
python3 ec2_auditor.py --regions eu-west-1 us-east-1         # Specific regions
python3 ec2_auditor.py --profile prod-account                # Specific AWS profile
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| IMDSv1 still allowed (token-optional) | +3 |
| Public IP assigned | +2 |
| EBS volume unencrypted | +2 |
| No IAM instance profile | +2 |
| Running in default VPC | +1 |
| Public snapshot found | +3 |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Public snapshot or multiple critical misconfigs |
| 5–7 | HIGH | IMDSv1 + public IP or unencrypted volumes |
| 2–4 | MEDIUM | Missing profile or default VPC usage |
| 0–1 | LOW | Minor gaps only |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
