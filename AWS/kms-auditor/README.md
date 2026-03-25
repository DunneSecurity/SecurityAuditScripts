# 🔑 KMS Auditor

Audits AWS customer-managed KMS keys across all regions. One finding per key — keys with public or cross-account wildcard access in their policy are flagged CRITICAL; keys with rotation disabled or no alias are flagged based on risk scoring.

---

## ✨ Features

- Key rotation status check (symmetric keys only)
- Key state detection (enabled vs disabled/pending_deletion/pending_import)
- Key policy analysis for public or cross-account wildcard access
- Alias presence check (unaliased keys flagged as harder to manage)
- Key spec classification (SYMMETRIC_DEFAULT, RSA_*, ECC_*, HMAC_*)
- Per-key risk level and severity score
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
    "kms:ListKeys",
    "kms:DescribeKey",
    "kms:GetKeyRotationStatus",
    "kms:GetKeyPolicy",
    "kms:ListAliases",
    "ec2:DescribeRegions",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

---

## 🚀 Usage

### AWS CloudShell
1. Upload `kms_auditor.py` via **Actions → Upload file**
2. Run:
```bash
python3 kms_auditor.py
```

### Options

```bash
python3 kms_auditor.py --output report --format html    # HTML only
python3 kms_auditor.py --format all                     # JSON + CSV + HTML
python3 kms_auditor.py --regions us-east-1 eu-west-1    # Specific regions
python3 kms_auditor.py --profile prod                   # Specific AWS profile
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| Public or cross-account wildcard access in key policy | +8 (CRITICAL) |
| Key rotation disabled (symmetric keys) | +4 |
| Key in non-enabled state (disabled/pending_deletion/pending_import) | +4 |
| No alias assigned to key | +2 |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Key policy allows public or wildcard cross-account access |
| 5–7 | HIGH | Rotation disabled or key in bad state |
| 2–4 | MEDIUM | Missing alias or minor policy concerns |
| 0–1 | LOW | Key is healthy and well-configured |

---

## 📋 Output Fields

Each finding (one per key) includes:

| Field | Description |
|-------|-------------|
| `region` | AWS region where the key exists |
| `key_id` | KMS key ID |
| `key_alias` | Alias assigned to the key (if any) |
| `key_state` | Current state (Enabled, Disabled, PendingDeletion, PendingImport) |
| `key_spec` | Key spec (SYMMETRIC_DEFAULT, RSA_2048, ECC_NIST_P256, HMAC_256, etc.) |
| `rotation_enabled` | Whether automatic key rotation is enabled |
| `public_access` | Whether key policy allows public (`*`) access |
| `cross_account_wildcard` | Whether key policy allows wildcard cross-account access |
| `has_alias` | Whether the key has at least one alias |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
