# AWS Security Audit Scripts

Python scripts for auditing AWS infrastructure security posture across all regions. Each script is standalone, read-only, and designed to run in AWS CloudShell or locally with a configured AWS profile.

---

## Scripts

| Script | Service | Description |
|--------|---------|-------------|
| [iam-privilege-mapper](./iam-privilege-mapper/) | IAM | Users, roles, groups — privilege escalation, MFA gaps, stale keys, admin policies |
| [s3-auditor](./s3-auditor/) | S3 | Bucket public access, encryption, versioning, logging, bucket policy analysis |
| [cloudtrail-auditor](./cloudtrail-auditor/) | CloudTrail | Logging coverage across all regions, KMS encryption, CloudWatch integration |
| [sg-auditor](./sg-auditor/) | EC2/VPC | Security groups with dangerous open ports, unrestricted ingress, unused groups |
| [root-auditor](./root-auditor/) | IAM | Root account MFA, access keys, password policy, alternate contacts |
| [ec2-auditor](./ec2-auditor/) | EC2 | IMDSv2 enforcement, EBS encryption, public IPs, public snapshots, default VPC |
| [rds-auditor](./rds-auditor/) | RDS | Public accessibility, encryption, backup retention, deletion protection, multi-AZ |
| [guardduty-auditor](./guardduty-auditor/) | GuardDuty | Detector enablement, finding counts by severity, protection plan coverage |
| [vpcflowlogs-auditor](./vpcflowlogs-auditor/) | VPC | Flow log coverage per VPC, traffic type, CloudWatch retention |
| [lambda-auditor](./lambda-auditor/) | Lambda | Public function URLs, IAM role permissions, secrets in env vars, deprecated runtimes |
| [securityhub-auditor](./securityhub-auditor/) | Security Hub | Hub enablement across all regions, finding counts by severity, CIS/PCI/FSBP standard pass rates |
| [kms-auditor](./kms-auditor/) | KMS | CMK rotation, key policy (public/wildcard access), key state, unaliased keys |
| [elb-auditor](./elb-auditor/) | ELB | ALB/NLB access logging, deletion protection, HTTP→HTTPS redirect, TLS policy, WAF association |

---

## Requirements

- Python 3.7+
- `boto3` — `pip install boto3`
- AWS credentials configured (CloudShell, environment variables, `aws configure`, or IAM role)

---

## Authentication

```bash
# Option 1: Environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=eu-west-1

# Option 2: AWS CLI profile
aws configure --profile my-profile

# Option 3: AWS CloudShell — credentials pre-configured, just upload and run
```

---

## Usage Pattern

All scripts share the same interface:

```bash
python3 <script>.py                              # Default: all formats
python3 <script>.py --format html               # HTML only
python3 <script>.py --format json               # JSON only
python3 <script>.py --format csv                # CSV only
python3 <script>.py --format all                # JSON + CSV + HTML
python3 <script>.py --format stdout             # Print JSON to terminal
python3 <script>.py --profile my-profile        # Specific AWS profile
python3 <script>.py --output my_report          # Custom output prefix
```

EC2, RDS, GuardDuty, VPC Flow Logs, and Lambda auditors also support `--regions` to limit scope:

```bash
python3 ec2_auditor.py --regions eu-west-1 us-east-1
```

---

## Output

Each run produces (with `--format all`):
- `<prefix>.json` — machine-readable findings with summary block
- `<prefix>.csv` — one row per finding, importable to Excel/SIEM
- `<prefix>.html` — colour-coded report with severity cards

All output files are created with owner-only permissions (mode 600).

---

## Running Tests

```bash
cd SecurityAuditScripts
pip install pytest boto3 botocore
pytest AWS/ -v
```

---

## Notes

- All scripts are **read-only** — they query configuration and make no changes
- Designed to run in **AWS CloudShell** but work anywhere with valid credentials
- Multi-region scripts enumerate all 18 standard AWS regions by default
- Each finding includes `flags` (emoji-prefixed observations) and `remediations` (actionable steps) for use with the [executive summary tool](../tools/)
