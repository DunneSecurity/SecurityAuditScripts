# λ Lambda Auditor

Audits AWS Lambda functions across all regions for security misconfigurations. Checks for public function URLs with no authentication, overly-permissive IAM execution roles, secrets exposed in environment variable names, deprecated runtimes, missing dead-letter queues, and disabled X-Ray tracing.

---

## ✨ Features

- Function URL check — flags URLs with `AuthType: NONE` (publicly invocable)
- IAM role analysis — detects admin policies (AdministratorAccess, FullAccess wildcards) attached to the execution role
- Secret environment variable detection — scans env var key names for patterns like `PASSWORD`, `API_KEY`, `TOKEN`, `SECRET`, etc.
- Deprecated runtime detection — flags EOL runtimes (Python 2.7–3.8, Node.js 6–14.x, Java 8/11, .NET Core 1–3.1, Ruby 2.5/2.7, Go 1.x)
- Dead-letter queue (DLQ) presence check
- X-Ray active tracing check
- Reserved concurrency zero detection (function throttled to zero invocations)
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
    "lambda:ListFunctions",
    "lambda:GetFunctionUrlConfig",
    "lambda:GetFunctionConcurrency",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies",
    "iam:GetRolePolicy",
    "ec2:DescribeRegions",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

---

## 🚀 Usage

### AWS CloudShell
1. Upload `lambda_auditor.py` via **Actions → Upload file**
2. Run:
```bash
python3 lambda_auditor.py
```

### Options

```bash
python3 lambda_auditor.py --format html --output lambda_report    # HTML only
python3 lambda_auditor.py --format all                            # JSON + CSV + HTML
python3 lambda_auditor.py --regions eu-west-1 us-east-1           # Specific regions
python3 lambda_auditor.py --profile prod-account                  # Specific AWS profile
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| Public function URL (AuthType: NONE) | +4 |
| Admin or wildcard IAM execution role | +4 |
| Secrets in environment variable names | +3 |
| Deprecated / EOL runtime | +2 |
| Reserved concurrency set to 0 | +1 |

Score is capped at 10. DLQ missing and X-Ray disabled are informational flags (ℹ️) and do not affect the score.

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Public URL + admin role (or equivalent combination) |
| 5–7 | HIGH | Public URL or admin role alone |
| 3–4 | MEDIUM | Secrets in env vars or deprecated runtime |
| 0–2 | LOW | Minor gaps only |

---

## 🔍 Secret Detection

The auditor scans environment variable **key names** (not values) against these patterns:

`password`, `passwd`, `secret`, `api_key`, `token`, `credential`, `auth`, `private_key`, `access_key`, `db_pass`, `database_pass`, `smtp_pass`

Matching keys are listed in the finding. Values are never read or logged.

---

## 📋 Deprecated Runtimes

The following runtimes are flagged as deprecated:

| Runtime family | Deprecated versions |
|----------------|---------------------|
| Python | 2.7, 3.6, 3.7, 3.8 |
| Node.js | 6.x, 8.x, 10.x, 12.x, 14.x |
| Java | 8, 11 |
| .NET Core | 1.0, 2.0, 2.1, 3.1 |
| Ruby | 2.5, 2.7 |
| Go | 1.x |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
