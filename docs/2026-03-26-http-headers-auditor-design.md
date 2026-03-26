# HTTP Security Headers Auditor — Design Spec

**Date:** 2026-03-26
**Location:** `Network/http-headers-auditor/`
**Status:** Approved

---

## Overview

A new auditor in SecurityAuditScripts that checks HTTP security response headers for a given domain over HTTPS. Follows the identical pattern established by the SSL/TLS auditor: thin mockable I/O wrapper → `_finding()` dict → `check_*()` functions → `run_audit()` → `run()` → JSON/CSV/HTML output. Integrates with `audit.py` orchestrator and `tools/exec_summary.py`.

---

## File Structure

```
Network/http-headers-auditor/
├── http_headers_auditor.py
└── tests/
    ├── __init__.py
    └── test_http_headers_auditor.py
```

---

## Architecture

### Layer 1 — I/O Wrapper (sole mock target)

```python
def get_http_headers(host: str, port: int = 443, timeout: int = 10) -> Optional[dict]:
```

Uses `http.client.HTTPSConnection` (stdlib, always HTTPS). Sends `GET /`, collects response headers, returns `{"headers": {lowercased_name: value, ...}}`. Returns `None` on any connection error (`ConnectionRefusedError`, `socket.timeout`, `socket.gaierror`, `http.client.HTTPException`, `OSError`). This is the **only** function tests mock.

### Layer 2 — Finding Helper

```python
def _finding(check_id, name, status, risk_level, severity_score, detail, remediation) -> dict:
```

Identical signature to the SSL/TLS auditor. Sets `pillar="headers"`. Returns `severity_score=0` when `status != "FAIL"`.

### Layer 3 — Six Check Functions

Each accepts `conn: Optional[dict]` (the result of `get_http_headers()`) and returns one finding dict.

### Layer 4 — `run_audit(domain, port=443)`

Calls `get_http_headers()` once. Passes result to all 6 check functions. Returns list of exactly 6 findings.

### Layer 5 — `run()`

CLI entry point. Parses `--domain`, `--port`, `--format`, `--output`. Calls `run_audit()`. Writes output files. Exits with error if `--domain` not provided.

---

## Checks

| ID | Name | PASS | WARN | FAIL | Risk | Score |
|----|------|------|------|------|------|-------|
| HDR-00 | Connectivity | Connected to host:port | — | Cannot connect | CRITICAL | 10 |
| HDR-01 | X-Frame-Options | DENY or SAMEORIGIN | ALLOWFROM (deprecated, browser-ignored) | Absent | HIGH | 7 |
| HDR-02 | X-Content-Type-Options | nosniff | — | Absent or wrong value | MEDIUM | 5 |
| HDR-03 | Content-Security-Policy | Present, no unsafe-inline/unsafe-eval | Present with unsafe-inline or unsafe-eval | Absent | HIGH | 8 |
| HDR-04 | Referrer-Policy | Any value except unsafe-url or origin | — | Absent, unsafe-url, or origin | MEDIUM | 4 |
| HDR-05 | Permissions-Policy | Present | Absent | — | LOW | 2 |

**Severity scores for WARN states:** HDR-03 WARN = 3, HDR-01 WARN = 2.

**Connectivity short-circuit:** If HDR-00 FAILs, remaining 5 checks return FAIL with `"Could not connect — skipped"` detail (consistent with SSL/TLS auditor pattern).

**Referrer-Policy safe values (PASS):** `no-referrer`, `no-referrer-when-downgrade`, `strict-origin`, `strict-origin-when-cross-origin`, `same-origin`, `origin-when-cross-origin`.
**Unsafe values (FAIL):** `unsafe-url`, `origin`.

---

## Data Flow

```
--domain acme.ie
     │
     ▼
get_http_headers("acme.ie", 443)
  HTTPSConnection → GET / HTTP/1.1
  returns {"headers": {"x-frame-options": "SAMEORIGIN", ...}}   or None
     │
     ▼
run_audit() → 6 check_*() functions → list of 6 finding dicts
     │
     ├── JSON  → {output}_report.json
     ├── CSV   → {output}_report.csv
     └── HTML  → {output}_report.html  (html.escape() on all user-supplied data)
```

**CLI example:**
```bash
python3 http_headers_auditor.py --domain acme.ie --format all --output http_headers_report
```

---

## Integration

### audit.py

- New entry in `AUDITOR_MAP`:
  ```python
  "http_headers": AuditorDef(
      REPO_ROOT / "Network/http-headers-auditor/http_headers_auditor.py",
      "http_headers_report",
      supports_regions=False,
      requires_domain=True,
  ),
  ```
- New `--http-headers` CLI flag (argparse maps to `args.http_headers`).

### tools/exec_summary.py

- Add `"http_headers_report.json"` to `KNOWN_PATTERNS`.
- Add `"http_headers": "HTTP Security Headers"` to `PILLAR_LABELS`.

Note: exec_summary.py derives `pillar_name` from filename (`http_headers_report.json` → `"http_headers"`), overwriting the `pillar` field in individual findings. The `_finding()` pillar value `"headers"` is meaningful only in standalone JSON output.

---

## Testing Strategy

**Single mock target:** `http_headers_auditor.get_http_headers`

**~28 tests total:**

| Check | Cases |
|-------|-------|
| HDR-00 | PASS (conn returned), FAIL (None) |
| HDR-01 | PASS (SAMEORIGIN), PASS (DENY), WARN (ALLOWFROM), FAIL (absent) |
| HDR-02 | PASS (nosniff), FAIL (absent), FAIL (wrong value) |
| HDR-03 | PASS (clean policy), WARN (unsafe-inline), WARN (unsafe-eval), FAIL (absent) |
| HDR-04 | PASS (strict-origin), PASS (no-referrer-when-downgrade), FAIL (absent), FAIL (unsafe-url), FAIL (origin) |
| HDR-05 | PASS (present), WARN (absent) |
| run_audit | Returns exactly 6 findings |
| run_audit | Connectivity FAIL short-circuits all 5 remaining checks to FAIL |
| _finding | All findings have `pillar == "headers"` |

Zero live network calls — all tests patch `get_http_headers` at the module level.

---

## Dependencies

- Python stdlib only: `http.client`, `socket`, `csv`, `json`, `argparse`, `pathlib`, `logging`
- No third-party packages

---

## Out of Scope

- HTTP→HTTPS redirect checking (separate check if needed later)
- HSTS header (already covered by TLS-07 in ssl_tls_auditor.py)
- Cookie security flags (separate auditor if needed)
- Port 80 / plaintext HTTP checks
