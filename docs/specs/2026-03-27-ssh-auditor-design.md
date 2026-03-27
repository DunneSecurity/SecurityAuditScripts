# SSH Auditor Design

**Date:** 2026-03-27
**Status:** Approved

---

## Overview

A new Linux auditor — `linux_ssh_auditor.py` — that checks SSH daemon hardening by reading the effective running configuration via `sshd -T`. Follows the identical structure and output conventions of existing Linux auditors (`linux_sysctl_auditor.py`, `linux_patch_auditor.py`, etc.).

---

## Architecture

### File structure

```
OnPrem/Linux/linux-ssh-auditor/
├── linux_ssh_auditor.py
└── tests/
    └── test_linux_ssh_auditor.py
```

### Module structure

Mirrors the existing auditor pattern exactly:

- **`run_command(cmd)`** — thin subprocess wrapper, returns `(stdout, returncode)`, swallows exceptions. Mockable in tests.
- **`get_effective_config()`** — calls `sshd -T`, parses each `key value` line into a lowercase dict. Returns `{}` on failure (e.g. sshd not installed).
- **`SSH_CHECKS`** — table of check tuples: `(key, check_fn, severity, description, remediation)`. `check_fn` is a callable that takes the value string and returns `(compliant: bool, detail: str)`.
- **`analyse_ssh(config)`** — iterates `SSH_CHECKS`, looks up each key in the config dict, calls `check_fn`. Returns a findings list in the standard format.
- **`compute_risk(findings)`** — same scoring formula as all other auditors: `CRITICAL×8 + HIGH×4 + MEDIUM×2 + LOW×0.5`, capped at 10.
- **`write_json / write_csv / write_html`** — identical pattern to existing auditors. HTML uses green gradient header (`#2c3e50` → `#28a745`), Bootstrap colour palette for severity badges.
- **`run(output_prefix, fmt)`** — orchestrates analysis, scoring, output. Returns the report dict.
- **`if __name__ == '__main__'`** — argparse with `--output` / `--format` flags.

### Output filenames

| Format | File |
|--------|------|
| JSON | `ssh_report.json` |
| CSV | `ssh_report.csv` |
| HTML | `ssh_report.html` |

### Report JSON shape

```json
{
  "generated_at": "<ISO timestamp>",
  "hostname": "<hostname>",
  "pillar": "ssh",
  "risk_level": "HIGH",
  "summary": {
    "total_checks": 21,
    "compliant": 15,
    "non_compliant": 4,
    "unavailable": 2,
    "critical": 0,
    "high": 2,
    "medium": 2,
    "low": 0,
    "overall_risk": "HIGH",
    "severity_score": 6
  },
  "findings": [ ... ]
}
```

Each finding:

```json
{
  "param": "permitrootlogin",
  "expected": "no",
  "actual": "prohibit-password",
  "compliant": false,
  "severity_if_wrong": "CRITICAL",
  "description": "Root login must be fully disabled",
  "flag": "⚠️ permitrootlogin = prohibit-password (expected no)",
  "remediation": "Set PermitRootLogin no in /etc/ssh/sshd_config",
  "risk_level": "CRITICAL"
}
```

`compliant` is `True` (pass), `False` (fail), or `None` (key absent from sshd -T output — skip scoring).

---

## Checks (21 total)

### Config checks (16)

| Key | Expected | Severity | Description |
|-----|----------|----------|-------------|
| `permitrootlogin` | `no` | CRITICAL | Root login fully disabled |
| `permitemptypasswords` | `no` | CRITICAL | Empty password login blocked |
| `passwordauthentication` | `no` | HIGH | Key-based auth enforced |
| `pubkeyauthentication` | `yes` | HIGH | Public key auth enabled |
| `strictmodes` | `yes` | HIGH | Enforce .ssh directory permissions |
| `hostbasedauthentication` | `no` | MEDIUM | Host-based trust disabled |
| `ignorerhosts` | `yes` | MEDIUM | .rhosts/.shosts ignored |
| `x11forwarding` | `no` | MEDIUM | X11 tunnelling disabled |
| `loglevel` | `VERBOSE` or `INFO` | MEDIUM | Audit-grade logging active |
| `maxauthtries` | `≤ 4` | MEDIUM | Brute-force throttle |
| `logingracetime` | `≤ 60` | MEDIUM | Unauthenticated connection timeout |
| `allowagentforwarding` | `no` | LOW | Agent forwarding disabled |
| `allowtcpforwarding` | `no` | LOW | TCP tunnelling disabled |
| `usepam` | `yes` | LOW | PAM integration active |
| `clientaliveinterval` | `≤ 300` | LOW | Idle session timeout |
| `clientalivecountmax` | `≤ 3` | LOW | Max keepalive misses |

### Crypto checks (5)

Crypto checks use a **denylist** approach: FAIL if any weak algorithm appears in the value. If the key is absent from `sshd -T` output (compiled-in modern defaults), mark as `compliant=None` (SKIP) rather than FAIL — OpenSSH 8+ defaults are already secure.

| Key | Weak algorithms to reject | Severity |
|-----|--------------------------|----------|
| `ciphers` | `arcfour*`, `3des-cbc`, `*-cbc` | HIGH |
| `macs` | `hmac-md5*`, `hmac-sha1`, `umac-64*` | HIGH |
| `kexalgorithms` | `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1` | HIGH |
| `hostkeyalgorithms` | `ssh-dss` | HIGH |
| `pubkeyacceptedalgorithms` | `ssh-dss` | MEDIUM |

---

## `audit.py` Integration

Add to `AUDITOR_MAP`:

```python
"linux_ssh": AuditorDef(
    REPO_ROOT / "OnPrem/Linux/linux-ssh-auditor/linux_ssh_auditor.py",
    "ssh_report",
    False,
),
```

Add `"linux_ssh"` to `LINUX_GROUP`.

Add `"ssh_report.json"` to `KNOWN_PATTERNS` in `exec_summary.py`.

Add `"linux_ssh"` help text to the argparse Linux group:

```
--linux_ssh  SSH daemon configuration and crypto hardening
```

---

## Testing (~35 tests)

All tests mock `run_command` — no live SSH daemon required. Test groups:

- **`run_command` / `get_effective_config`** — parse valid output, handle empty output, handle non-zero rc
- **`analyse_ssh`** — compliant value, non-compliant value, missing key (None), numeric threshold boundary cases (maxauthtries=4 pass, =5 fail), loglevel case-insensitivity
- **`compute_risk`** — zero findings, critical-only, mixed severity, score cap at 10
- **`write_json`** — file written, chmod 600, valid JSON
- **`write_html`** — file written, contains green gradient colour `#28a745`, contains hostname
- **`run()`** — happy path returns correct report shape, sshd unavailable returns report with 0 findings scored LOW
- **`audit.py` integration** — `linux_ssh` present in `AUDITOR_MAP`, `ssh_report` output prefix correct, `linux_ssh` in `LINUX_GROUP`
- **`exec_summary.py`** — `ssh_report.json` in `KNOWN_PATTERNS`

---

## Conventions

- Header gradient: `linear-gradient(135deg, #2c3e50, #28a745)` (Linux green, matches sysctl/patch/firewall/user auditors)
- Severity badge colours: `#dc3545` CRITICAL, `#fd7e14` HIGH, `#ffc107` MEDIUM, `#28a745` LOW
- `os.chmod(path, 0o600)` on all output files
- Findings sorted: non-compliant first, then unavailable (None), then compliant
- Console summary box using Unicode box-drawing characters, matching existing auditors
- `sudo python3 linux_ssh_auditor.py` required (sshd -T may need root on some distros)
