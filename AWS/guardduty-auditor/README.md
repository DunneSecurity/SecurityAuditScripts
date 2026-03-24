# 🛡️ GuardDuty Auditor

Audits AWS GuardDuty enablement and active threat findings across all regions. One finding per region — regions with no detector are flagged CRITICAL; regions with active HIGH-severity findings are flagged HIGH.

---

## ✨ Features

- Detector enablement check across all 18 standard AWS regions
- Active finding counts by severity band (HIGH ≥7.0, MEDIUM ≥4.0, LOW <4.0)
- Protection plan coverage:
  - S3 Protection
  - EKS Audit Log Monitoring
  - Malware Protection
  - RDS Login Activity Monitoring
  - Runtime Monitoring
- Findings export destination check (S3/EventBridge)
- Auto-archive rule detection
- Per-region risk level and severity score
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
    "guardduty:ListDetectors",
    "guardduty:GetDetector",
    "guardduty:ListFindings",
    "guardduty:GetFindings",
    "guardduty:GetFindingsStatistics",
    "ec2:DescribeRegions",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

---

## 🚀 Usage

### AWS CloudShell
1. Upload `guardduty_auditor.py` via **Actions → Upload file**
2. Run:
```bash
python3 guardduty_auditor.py
```

### Options

```bash
python3 guardduty_auditor.py --format html --output gd_report    # HTML only
python3 guardduty_auditor.py --format all                        # JSON + CSV + HTML
python3 guardduty_auditor.py --regions eu-west-1 us-east-1       # Specific regions
python3 guardduty_auditor.py --profile prod-account              # Specific AWS profile
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| No GuardDuty detector in region | +8 (CRITICAL) |
| Active HIGH-severity findings | +4 per region |
| Active MEDIUM-severity findings | +2 per region |
| S3 Protection disabled | +1 |
| Malware Protection disabled | +1 |
| No findings export configured | +1 |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | GuardDuty not enabled in region |
| 5–7 | HIGH | Active HIGH findings in region |
| 2–4 | MEDIUM | Active MEDIUM findings or missing protection plans |
| 0–1 | LOW | GuardDuty enabled, no significant findings |

---

## 📋 Output Fields

Each finding (one per region) includes:

| Field | Description |
|-------|-------------|
| `region` | AWS region name |
| `detector_id` | GuardDuty detector ID (if enabled) |
| `enabled` | Whether a detector exists in this region |
| `high_findings` | Count of active HIGH-severity findings |
| `medium_findings` | Count of active MEDIUM-severity findings |
| `low_findings` | Count of active LOW-severity findings |
| `s3_protection` | S3 Protection plan enabled |
| `eks_protection` | EKS Audit Log Monitoring enabled |
| `malware_protection` | Malware Protection enabled |
| `rds_protection` | RDS Login Activity Monitoring enabled |
| `runtime_monitoring` | Runtime Monitoring enabled |
| `findings_export_enabled` | Findings export to S3/EventBridge configured |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
