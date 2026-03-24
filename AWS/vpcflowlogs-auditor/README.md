# 🌐 VPC Flow Logs Auditor

Audits VPC flow log coverage per VPC across all AWS regions. Flags VPCs with no flow logs (CRITICAL), logs capturing only ACCEPT or REJECT traffic rather than ALL, default log format usage, and short CloudWatch log retention.

---

## ✨ Features

- Flow log coverage check — flags VPCs with no active flow logs (CRITICAL)
- Traffic type coverage — identifies ACCEPT-only or REJECT-only logs (HIGH); ALL traffic is best practice
- Log format check — flags use of the default log format vs custom fields
- CloudWatch retention — flags log groups with retention below 90 days
- Only `ACTIVE` flow logs counted — ERROR-status logs are excluded
- VPC name tag resolution
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
    "ec2:DescribeVpcs",
    "ec2:DescribeFlowLogs",
    "ec2:DescribeRegions",
    "logs:DescribeLogGroups",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

---

## 🚀 Usage

### AWS CloudShell
1. Upload `vpcflowlogs_auditor.py` via **Actions → Upload file**
2. Run:
```bash
python3 vpcflowlogs_auditor.py
```

### Options

```bash
python3 vpcflowlogs_auditor.py --format html --output vpc_report    # HTML only
python3 vpcflowlogs_auditor.py --format all                         # JSON + CSV + HTML
python3 vpcflowlogs_auditor.py --regions eu-west-1 us-east-1        # Specific regions
python3 vpcflowlogs_auditor.py --profile prod-account               # Specific AWS profile
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| No flow logs on VPC | +8 (CRITICAL) |
| Logs capture ACCEPT or REJECT only | +4 |
| Default log format in use | +1 (informational) |
| CloudWatch retention < 90 days | +1 (informational) |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | VPC has no active flow logs |
| 5–7 | HIGH | Partial traffic capture only |
| 2–4 | MEDIUM | Flow logs active but limited coverage |
| 0–1 | LOW | Flow logs active, capturing ALL traffic |

---

## 📋 Output Fields

Each finding (one per VPC) includes:

| Field | Description |
|-------|-------------|
| `vpc_id` | VPC resource ID |
| `vpc_name` | Name tag (if set) |
| `region` | AWS region |
| `has_flow_logs` | Whether any ACTIVE flow logs exist |
| `flow_log_count` | Number of active flow logs |
| `traffic_types` | Set of traffic types captured (ACCEPT/REJECT/ALL) |
| `log_destinations` | Destination types (cloud-watch-logs/s3) |
| `default_format` | Whether default log format is in use |
| `short_retention` | Whether any CW log group retention is < 90 days |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
