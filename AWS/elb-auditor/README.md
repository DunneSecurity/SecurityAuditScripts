# 🛡️ ELB Auditor

Audits AWS Application Load Balancers (ALB) and Network Load Balancers (NLB) for security misconfigurations across all regions. One finding per load balancer — missing access logging, absent deletion protection, unencrypted listeners, and missing WAF associations are all flagged by risk level.

---

## ✨ Features

- Access logging to S3 enabled check (ALB and NLB)
- Deletion protection enabled check (ALB and NLB)
- HTTP → HTTPS redirect configured (ALB only)
- SSL/TLS policy currency check (ALB HTTPS listeners and NLB TLS listeners)
- WAF WebACL association check (ALB only)
- Internet-facing vs internal scheme (informational)
- Per-load-balancer risk level and severity score
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
    "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:DescribeListeners",
    "elasticloadbalancing:DescribeRules",
    "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:DescribeLoadBalancerAttributes",
    "wafv2:GetWebACLForResource",
    "ec2:DescribeRegions",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

---

## 🚀 Usage

### AWS CloudShell
1. Upload `elb_auditor.py` via **Actions → Upload file**
2. Run:
```bash
python3 elb_auditor.py
```

### Options

```bash
python3 elb_auditor.py --output report --format all          # JSON + CSV + HTML
python3 elb_auditor.py --format html                         # HTML only
python3 elb_auditor.py --profile prod --regions eu-west-1 us-east-1  # Profile + regions
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| Access logging disabled | +3 |
| Deletion protection disabled | +2 |
| HTTP listener with no HTTPS redirect (ALB) | +3 |
| Outdated SSL/TLS policy | +3 |
| No WAF WebACL associated (ALB) | +2 |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Multiple critical misconfigurations present |
| 5–7 | HIGH | Unencrypted traffic or no WAF on internet-facing ALB |
| 2–4 | MEDIUM | Logging or deletion protection missing |
| 0–1 | LOW | Load balancer meets baseline security requirements |

---

## 📋 Output Fields

Each finding (one per load balancer) includes:

| Field | Description |
|-------|-------------|
| `region` | AWS region name |
| `name` | Load balancer name |
| `type` | Load balancer type (application or network) |
| `scheme` | internet-facing or internal |
| `access_logging_enabled` | Access logs being sent to S3 |
| `deletion_protection_enabled` | Deletion protection active |
| `http_to_https_redirect` | All HTTP listeners redirect to HTTPS (ALB only) |
| `ssl_policy_ok` | SSL/TLS policy is current on HTTPS/TLS listeners |
| `waf_associated` | WAF WebACL attached to load balancer (ALB only) |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
