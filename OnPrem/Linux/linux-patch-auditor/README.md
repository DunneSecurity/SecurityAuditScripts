# 🩹 Linux Patch & Update Auditor

Audits package update status, kernel currency, and automatic update configuration on Linux systems.

---

## ⚙️ Requirements

- Python 3.7+
- Run as root (`sudo`) for package manager commands that require elevated access (`apt-get -s upgrade`, `yum check-update`)

---

## 🚀 Usage

```bash
# Full audit — writes patch_report.json, .csv, .html
sudo python3 linux_patch_auditor.py

# HTML report only
sudo python3 linux_patch_auditor.py --format html --output patch_report

# All formats
sudo python3 linux_patch_auditor.py --format all
```

---

## ✨ Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--output`, `-o` | `patch_report` | Output file prefix |
| `--format`, `-f` | `all` | `json` \| `csv` \| `html` \| `all` \| `stdout` |

---

## 📋 Checks

| Finding | Score | Severity | Description |
|---------|-------|----------|-------------|
| `SecurityUpdatesAvailable` | 9 | CRITICAL | One or more security-classified updates are pending |
| `KernelUpdateAvailable` | 8 | CRITICAL | A newer kernel package is available than the running kernel |
| `NeverUpdated` | 8 | CRITICAL | No record of a successful package manager update run |
| `AutoUpdateAgentMissing` | 7 | HIGH | No automatic update agent installed (unattended-upgrades / yum-cron / dnf-automatic / zypper auto_update) |
| `AutoUpdateAgentDisabled` | 6 | HIGH | Automatic update agent is installed but not enabled or not running |
| `LargeUpdateBacklog` | 6 | HIGH | 50 or more total package updates are pending |
| `UpdatesAvailable` | 4 | MEDIUM | Non-security updates are pending (fewer than 50) |
| `LastUpdateStale` | 5 | MEDIUM | Last successful update was more than 30 days ago |

---

## 🐧 Supported Package Managers

The auditor detects the package manager automatically at runtime.

| Distro Family | Package Manager | Auto-Update Agent |
|---------------|----------------|-------------------|
| Debian / Ubuntu | `apt` / `apt-get` | `unattended-upgrades` |
| RHEL / CentOS 7 | `yum` | `yum-cron` |
| RHEL / CentOS 8+ / Fedora | `dnf` | `dnf-automatic` |
| SUSE / openSUSE | `zypper` | `zypper` auto update timer |

---

## 🔍 Data Sources

- `apt-get -s upgrade` / `yum check-update` / `dnf check-update` / `zypper list-updates` — pending updates
- `/var/log/apt/history.log`, `/var/log/yum.log`, `/var/log/dnf.log`, `zypper log` — last update timestamps
- `systemctl` / `dpkg -l` / `rpm -q` — auto-update agent status
- `uname -r` — running kernel version
- Package manager query for available kernel packages — kernel update comparison

---

## 📊 Output Files

All files are created with owner-only permissions (mode 600).

- `patch_report.json` — machine-readable full report
- `patch_report.csv` — one row per finding
- `patch_report.html` — colour-coded HTML summary

---

## 🧪 Running Tests

```bash
# From repo root
pip install pytest
pytest OnPrem/Linux/linux-patch-auditor/tests/ -v
```

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
