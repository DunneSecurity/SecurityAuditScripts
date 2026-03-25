# Email Security Auditor

Audits a domain's email security DNS configuration — SPF, DKIM, and DMARC.
No cloud credentials required. DNS queries only.

## Prerequisites

```bash
pip install dnspython
```

## Usage

```bash
# Basic audit — auto-probes for DKIM selectors
python3 email_security_auditor.py --domain acme.ie

# Provide known DKIM selector
python3 email_security_auditor.py --domain acme.ie --selector google

# JSON output only
python3 email_security_auditor.py --domain acme.ie --format json

# Print to terminal
python3 email_security_auditor.py --domain acme.ie --format stdout
```

## Checks

| ID | Check | Risk if Failing |
|---|---|---|
| MX-01 | MX record exists | LOW — domain may not send email |
| SPF-01 | SPF record exists | HIGH — anyone can spoof the domain |
| SPF-02 | SPF not permissive | CRITICAL — `+all` makes SPF useless |
| SPF-03 | SPF lookup count ≤10 | MEDIUM — may break legitimate mail |
| DKIM-01 | DKIM record exists | HIGH — emails are unsigned, easily forged |
| DKIM-02 | DKIM key ≥1024 bits | MEDIUM — weak keys can be cracked |
| DMARC-01 | DMARC record exists | HIGH — no policy, spoofed mail delivered |
| DMARC-02 | DMARC policy enforced | HIGH — `p=none` means no enforcement |
| DMARC-03 | DMARC reporting configured | MEDIUM — no visibility into spoofing attempts |

## Output

Produces `email_report.json`, `email_report.html`, and `email_report.csv` by default.

The JSON report is consumed by `tools/exec_summary.py` when aggregating results across all auditors.

## Running via orchestrator

```bash
python3 audit.py --client "Acme Corp" --email --domain acme.ie
```
