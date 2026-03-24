# 📊 Executive Summary Tool

Aggregates JSON report files from all AWS, Azure, and on-premises auditors into a single HTML executive summary. Computes an overall security score (0–100) with a letter grade, per-pillar risk cards, top findings, and quick wins.

---

## ✨ Features

- Auto-discovers all `*_report.json` files in a target directory
- Supports all 21 auditor report types across AWS, Azure, and on-premises
- Per-pillar risk summary cards (CRITICAL / HIGH / MEDIUM / LOW counts)
- Overall security score (0–100) with letter grade (A–F)
- Top 10 findings sorted by severity score
- Quick wins table — low-effort, high-impact actions from ℹ️-prefixed flags on HIGH/CRITICAL findings
- Output written to a single HTML file (mode 600)
- Score calibrated for SMB environments: 13 CRITICAL findings = score 0

---

## ⚙️ Requirements

- Python 3.7+
- No additional dependencies — stdlib only

---

## 🚀 Usage

```bash
# Run all auditors first, then:
python3 tools/exec_summary.py --input-dir . --output exec_summary.html

# Specify a directory containing report JSON files
python3 tools/exec_summary.py --input-dir /path/to/reports/

# Custom output path
python3 tools/exec_summary.py --input-dir . --output /tmp/my_summary.html
```

---

## 📊 Scoring Algorithm

| Finding Level | Deduction per finding |
|--------------|----------------------|
| CRITICAL | −8 points |
| HIGH | −4 points |
| MEDIUM | −2 points |
| LOW | −0.5 points |

Starting from 100, score is clamped to [0, 100].

| Score | Grade | Interpretation |
|-------|-------|---------------|
| 90–100 | A | Strong posture, minor gaps only |
| 80–89 | B | Good posture with some issues to address |
| 70–79 | C | Notable gaps requiring attention |
| 60–69 | D | Significant security debt |
| 0–59 | F | Critical issues requiring immediate action |

---

## 📋 Supported Report Files

The tool auto-discovers any of these filenames in the input directory:

**AWS:** `s3_report.json`, `sg_report.json`, `cloudtrail_report.json`, `root_report.json`, `iam_report.json`, `ec2_report.json`, `rds_report.json`, `guardduty_report.json`, `vpcflowlogs_report.json`, `lambda_report.json`

**Azure:** `keyvault_report.json`, `storage_report.json`, `nsg_report.json`, `activitylog_report.json`, `subscription_report.json`, `entra_report.json`

**On-Premises (Windows):** `ad_report.json`, `localuser_report.json`, `winfirewall_report.json`

**On-Premises (Linux):** `user_report.json`, `fw_report.json`

---

## 🔧 Quick Wins

The quick wins table surfaces ℹ️-prefixed flags from HIGH or CRITICAL findings. These are low-effort configuration changes (e.g. enabling versioning, adding a DLQ, enabling X-Ray) that reduce risk quickly without requiring architectural changes.

---

## Running Tests

```bash
pytest tools/tests/test_exec_summary.py -v
```
