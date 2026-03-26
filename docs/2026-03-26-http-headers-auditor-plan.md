# HTTP Security Headers Auditor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `Network/http-headers-auditor/http_headers_auditor.py` — checks 6 HTTP security response headers over HTTPS, with full tests and orchestrator integration.

**Architecture:** Thin `get_http_headers()` wrapper (sole mock target) → `_finding()` helper → 6 `check_*()` functions → `run_audit()` → `run()` + `__main__` CLI. Identical pattern to ssl_tls_auditor.py. Integrates into audit.py and exec_summary.py.

**Tech Stack:** Python 3.10+ stdlib only (`http.client`, `socket`, `csv`, `json`, `argparse`, `pathlib`, `logging`, `html`). Tests use `unittest.mock.patch`. No third-party dependencies.

---

### Task 1: Scaffold — file structure + wrapper + `_finding()`

**Files:**
- Create: `Network/http-headers-auditor/http_headers_auditor.py`
- Create: `Network/http-headers-auditor/tests/__init__.py`
- Create: `Network/http-headers-auditor/tests/test_http_headers_auditor.py`

- [ ] **Step 1: Create the directory structure**

```bash
mkdir -p Network/http-headers-auditor/tests
touch Network/http-headers-auditor/tests/__init__.py
```

- [ ] **Step 2: Write the failing wrapper test**

Create `Network/http-headers-auditor/tests/test_http_headers_auditor.py`:

```python
"""Tests for http_headers_auditor.py"""
import sys
import os
import socket
import http.client
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import http_headers_auditor as hha


# ── Fixture helpers ───────────────────────────────────────────────────────────

def make_conn(**header_overrides) -> dict:
    """Build a get_http_headers() result. Pass header_name=None to remove it."""
    headers = {
        "x-frame-options": "SAMEORIGIN",
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'self'",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=()",
    }
    for k, v in header_overrides.items():
        if v is None:
            headers.pop(k, None)
        else:
            headers[k] = v
    return {"headers": headers}


# ── get_http_headers() wrapper tests ─────────────────────────────────────────

def test_get_http_headers_returns_none_on_connection_refused():
    with patch('http.client.HTTPSConnection') as mock_cls:
        mock_cls.return_value.request.side_effect = ConnectionRefusedError
        result = hha.get_http_headers('refused.example.com', 443)
    assert result is None


def test_get_http_headers_returns_none_on_timeout():
    with patch('http.client.HTTPSConnection') as mock_cls:
        mock_cls.return_value.request.side_effect = socket.timeout
        result = hha.get_http_headers('timeout.example.com', 443)
    assert result is None


def test_get_http_headers_returns_none_on_gaierror():
    with patch('http.client.HTTPSConnection') as mock_cls:
        mock_cls.return_value.request.side_effect = socket.gaierror
        result = hha.get_http_headers('notexist.example.com', 443)
    assert result is None


def test_get_http_headers_returns_none_on_http_exception():
    with patch('http.client.HTTPSConnection') as mock_cls:
        mock_cls.return_value.request.side_effect = http.client.HTTPException
        result = hha.get_http_headers('badhttp.example.com', 443)
    assert result is None


def test_get_http_headers_returns_dict_with_lowercased_headers():
    mock_resp = MagicMock()
    mock_resp.getheaders.return_value = [
        ("X-Frame-Options", "SAMEORIGIN"),
        ("Content-Security-Policy", "default-src 'self'"),
    ]
    with patch('http.client.HTTPSConnection') as mock_cls:
        mock_cls.return_value.getresponse.return_value = mock_resp
        result = hha.get_http_headers('acme.ie', 443)
    assert result is not None
    assert result["headers"]["x-frame-options"] == "SAMEORIGIN"
    assert result["headers"]["content-security-policy"] == "default-src 'self'"


# ── _finding() helper tests ───────────────────────────────────────────────────

def test_finding_structure():
    f = hha._finding("HDR-01", "X-Frame-Options", "FAIL", "HIGH", 7, "detail", "fix it")
    assert f["check_id"] == "HDR-01"
    assert f["name"] == "X-Frame-Options"
    assert f["status"] == "FAIL"
    assert f["risk_level"] == "HIGH"
    assert f["severity_score"] == 7
    assert f["detail"] == "detail"
    assert f["remediation"] == "fix it"
    assert f["pillar"] == "headers"


def test_finding_severity_score_zero_for_pass():
    f = hha._finding("HDR-01", "X-Frame-Options", "PASS", "HIGH", 7, "ok", "")
    assert f["severity_score"] == 0


def test_finding_severity_score_zero_for_warn():
    f = hha._finding("HDR-01", "X-Frame-Options", "WARN", "HIGH", 7, "weak", "fix")
    assert f["severity_score"] == 0
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd Network/http-headers-auditor
pytest tests/test_http_headers_auditor.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'http_headers_auditor'`

- [ ] **Step 4: Create `http_headers_auditor.py` with wrapper + `_finding()`**

Create `Network/http-headers-auditor/http_headers_auditor.py`:

```python
#!/usr/bin/env python3
"""
HTTP Security Headers Auditor
==============================
Audits a domain's HTTP security response headers over HTTPS:
- HDR-00: Connectivity (can we connect at all?)
- HDR-01: X-Frame-Options (absent = FAIL; ALLOWFROM = WARN)
- HDR-02: X-Content-Type-Options (nosniff required)
- HDR-03: Content-Security-Policy (absent = FAIL; unsafe-inline/eval = WARN)
- HDR-04: Referrer-Policy (unsafe-url/origin = FAIL; absent = FAIL)
- HDR-05: Permissions-Policy (absent = WARN)

Usage:
    python3 http_headers_auditor.py --domain acme.ie
    python3 http_headers_auditor.py --domain acme.ie --port 8443
    python3 http_headers_auditor.py --domain acme.ie --format all --output http_headers_report
"""

import argparse
import csv
import html as html_lib
import http.client
import json
import logging
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)


# ── HTTPS wrapper (thin — mock this in tests) ─────────────────────────────────

def get_http_headers(host: str, port: int = 443, timeout: int = 10) -> Optional[dict]:
    """
    Open HTTPS connection to host:port, send GET /, return response headers.

    Returns dict with key:
        headers  - response headers with names lowercased

    Returns None on ConnectionRefusedError, socket.timeout, socket.gaierror,
    http.client.HTTPException, or OSError.
    """
    try:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        conn.request("GET", "/", headers={"Host": host, "Connection": "close"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return {"headers": headers}
    except (ConnectionRefusedError, socket.timeout, socket.gaierror,
            http.client.HTTPException, OSError):
        return None


# ── Finding helper ─────────────────────────────────────────────────────────────

def _finding(check_id: str, name: str, status: str, risk_level: str,
             severity_score: int, detail: str, remediation: str) -> dict:
    return {
        "check_id": check_id,
        "name": name,
        "status": status,
        "risk_level": risk_level,
        "severity_score": severity_score if status == "FAIL" else 0,
        "detail": detail,
        "remediation": remediation,
        "pillar": "headers",
    }
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_http_headers_auditor.py -v 2>&1 | tail -20
```

Expected: All 10 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add Network/http-headers-auditor/
git commit -m "feat(http-headers): scaffold auditor with wrapper and _finding() helper"
```

---

### Task 2: HDR-00 Connectivity check

**Files:**
- Modify: `Network/http-headers-auditor/tests/test_http_headers_auditor.py`
- Modify: `Network/http-headers-auditor/http_headers_auditor.py`

- [ ] **Step 1: Add connectivity check tests**

Append to `tests/test_http_headers_auditor.py`:

```python
# ── HDR-00: Connectivity ──────────────────────────────────────────────────────

def test_check_connectivity_pass():
    conn = make_conn()
    f = hha.check_connectivity(conn, "acme.ie", 443)
    assert f["check_id"] == "HDR-00"
    assert f["status"] == "PASS"
    assert f["severity_score"] == 0


def test_check_connectivity_fail_on_none():
    f = hha.check_connectivity(None, "acme.ie", 443)
    assert f["check_id"] == "HDR-00"
    assert f["status"] == "FAIL"
    assert f["risk_level"] == "CRITICAL"
    assert f["severity_score"] == 10
    assert "acme.ie" in f["detail"]
    assert "443" in f["detail"]
```

- [ ] **Step 2: Run to verify tests fail**

```bash
pytest tests/test_http_headers_auditor.py::test_check_connectivity_pass tests/test_http_headers_auditor.py::test_check_connectivity_fail_on_none -v
```

Expected: `AttributeError: module 'http_headers_auditor' has no attribute 'check_connectivity'`

- [ ] **Step 3: Add `check_connectivity()` to `http_headers_auditor.py`**

Append after `_finding()`:

```python
# ── HDR-00: Connectivity ───────────────────────────────────────────────────────

def check_connectivity(conn: Optional[dict], domain: str, port: int) -> dict:
    """HDR-00: Verify we can establish an HTTPS connection to domain:port."""
    if conn is None:
        return _finding(
            "HDR-00", "HTTP Headers Connectivity", "FAIL", "CRITICAL", 10,
            f"Could not establish HTTPS connection to {domain}:{port}. "
            "Host may be unreachable, port closed, or TLS not enabled.",
            "Verify the server is running and accessible on port 443. "
            "Check firewall rules and that TLS is configured.",
        )
    return _finding(
        "HDR-00", "HTTP Headers Connectivity", "PASS", "CRITICAL", 0,
        f"HTTPS connection established to {domain}:{port}", "",
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_http_headers_auditor.py -v 2>&1 | tail -15
```

Expected: All 12 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add Network/http-headers-auditor/
git commit -m "feat(http-headers): add HDR-00 connectivity check"
```

---

### Task 3: HDR-01 X-Frame-Options check

**Files:**
- Modify: `Network/http-headers-auditor/tests/test_http_headers_auditor.py`
- Modify: `Network/http-headers-auditor/http_headers_auditor.py`

- [ ] **Step 1: Add X-Frame-Options tests**

Append to `tests/test_http_headers_auditor.py`:

```python
# ── HDR-01: X-Frame-Options ───────────────────────────────────────────────────

def test_check_x_frame_options_pass_sameorigin():
    f = hha.check_x_frame_options(make_conn(**{"x-frame-options": "SAMEORIGIN"}))
    assert f["check_id"] == "HDR-01"
    assert f["status"] == "PASS"


def test_check_x_frame_options_pass_deny():
    f = hha.check_x_frame_options(make_conn(**{"x-frame-options": "DENY"}))
    assert f["status"] == "PASS"


def test_check_x_frame_options_warn_allowfrom():
    f = hha.check_x_frame_options(make_conn(**{"x-frame-options": "ALLOWFROM https://trusted.com"}))
    assert f["status"] == "WARN"
    assert f["severity_score"] == 0
    assert "deprecated" in f["detail"].lower()


def test_check_x_frame_options_fail_absent():
    f = hha.check_x_frame_options(make_conn(**{"x-frame-options": None}))
    assert f["status"] == "FAIL"
    assert f["risk_level"] == "HIGH"
    assert f["severity_score"] == 7
```

- [ ] **Step 2: Run to verify tests fail**

```bash
pytest tests/test_http_headers_auditor.py -k "x_frame" -v
```

Expected: `AttributeError: module 'http_headers_auditor' has no attribute 'check_x_frame_options'`

- [ ] **Step 3: Add `check_x_frame_options()` to `http_headers_auditor.py`**

Append after `check_connectivity()`:

```python
# ── HDR-01: X-Frame-Options ───────────────────────────────────────────────────

_SAFE_XFO = frozenset({"deny", "sameorigin"})


def check_x_frame_options(conn: dict) -> dict:
    """HDR-01: X-Frame-Options header — DENY or SAMEORIGIN required."""
    val = conn.get("headers", {}).get("x-frame-options", "").strip()
    if not val:
        return _finding(
            "HDR-01", "X-Frame-Options", "FAIL", "HIGH", 7,
            "X-Frame-Options header is absent. The site may be embeddable in iframes, "
            "enabling clickjacking attacks.",
            "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to all responses. "
            "Prefer Content-Security-Policy frame-ancestors for modern browsers.",
        )
    if val.lower() in _SAFE_XFO:
        return _finding(
            "HDR-01", "X-Frame-Options", "PASS", "HIGH", 0,
            f"X-Frame-Options: {val}", "",
        )
    if val.lower().startswith("allowfrom"):
        return _finding(
            "HDR-01", "X-Frame-Options", "WARN", "HIGH", 0,
            f"X-Frame-Options: {val} — ALLOWFROM is deprecated and ignored by Chrome and Firefox.",
            "Replace with 'Content-Security-Policy: frame-ancestors \\'self\\' https://trusted.com'",
        )
    return _finding(
        "HDR-01", "X-Frame-Options", "FAIL", "HIGH", 7,
        f"X-Frame-Options value '{val}' is not recognised. Expected DENY or SAMEORIGIN.",
        "Set X-Frame-Options to DENY or SAMEORIGIN.",
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_http_headers_auditor.py -v 2>&1 | tail -20
```

Expected: All 16 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add Network/http-headers-auditor/
git commit -m "feat(http-headers): add HDR-01 X-Frame-Options check"
```

---

### Task 4: HDR-02 X-Content-Type-Options check

**Files:**
- Modify: `Network/http-headers-auditor/tests/test_http_headers_auditor.py`
- Modify: `Network/http-headers-auditor/http_headers_auditor.py`

- [ ] **Step 1: Add X-Content-Type-Options tests**

Append to `tests/test_http_headers_auditor.py`:

```python
# ── HDR-02: X-Content-Type-Options ───────────────────────────────────────────

def test_check_x_content_type_options_pass():
    f = hha.check_x_content_type_options(make_conn(**{"x-content-type-options": "nosniff"}))
    assert f["check_id"] == "HDR-02"
    assert f["status"] == "PASS"


def test_check_x_content_type_options_fail_absent():
    f = hha.check_x_content_type_options(make_conn(**{"x-content-type-options": None}))
    assert f["status"] == "FAIL"
    assert f["risk_level"] == "MEDIUM"
    assert f["severity_score"] == 5


def test_check_x_content_type_options_fail_wrong_value():
    f = hha.check_x_content_type_options(make_conn(**{"x-content-type-options": "sniff"}))
    assert f["status"] == "FAIL"
    assert f["severity_score"] == 5
```

- [ ] **Step 2: Run to verify tests fail**

```bash
pytest tests/test_http_headers_auditor.py -k "content_type" -v
```

Expected: `AttributeError: module 'http_headers_auditor' has no attribute 'check_x_content_type_options'`

- [ ] **Step 3: Add `check_x_content_type_options()` to `http_headers_auditor.py`**

Append after `check_x_frame_options()`:

```python
# ── HDR-02: X-Content-Type-Options ───────────────────────────────────────────

def check_x_content_type_options(conn: dict) -> dict:
    """HDR-02: X-Content-Type-Options must be 'nosniff'."""
    val = conn.get("headers", {}).get("x-content-type-options", "").strip().lower()
    if val == "nosniff":
        return _finding(
            "HDR-02", "X-Content-Type-Options", "PASS", "MEDIUM", 0,
            "X-Content-Type-Options: nosniff", "",
        )
    if not val:
        return _finding(
            "HDR-02", "X-Content-Type-Options", "FAIL", "MEDIUM", 5,
            "X-Content-Type-Options header is absent. Browsers may MIME-sniff responses, "
            "enabling content injection attacks.",
            "Add 'X-Content-Type-Options: nosniff' to all responses.",
        )
    return _finding(
        "HDR-02", "X-Content-Type-Options", "FAIL", "MEDIUM", 5,
        f"X-Content-Type-Options value '{val}' is not 'nosniff'.",
        "Set X-Content-Type-Options to exactly 'nosniff'.",
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_http_headers_auditor.py -v 2>&1 | tail -20
```

Expected: All 19 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add Network/http-headers-auditor/
git commit -m "feat(http-headers): add HDR-02 X-Content-Type-Options check"
```

---

### Task 5: HDR-03 Content-Security-Policy check

**Files:**
- Modify: `Network/http-headers-auditor/tests/test_http_headers_auditor.py`
- Modify: `Network/http-headers-auditor/http_headers_auditor.py`

- [ ] **Step 1: Add CSP tests**

Append to `tests/test_http_headers_auditor.py`:

```python
# ── HDR-03: Content-Security-Policy ──────────────────────────────────────────

def test_check_csp_pass_clean_policy():
    f = hha.check_content_security_policy(
        make_conn(**{"content-security-policy": "default-src 'self'; script-src 'self'"})
    )
    assert f["check_id"] == "HDR-03"
    assert f["status"] == "PASS"


def test_check_csp_warn_unsafe_inline():
    f = hha.check_content_security_policy(
        make_conn(**{"content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"})
    )
    assert f["status"] == "WARN"
    assert f["severity_score"] == 0
    assert "unsafe-inline" in f["detail"]


def test_check_csp_warn_unsafe_eval():
    f = hha.check_content_security_policy(
        make_conn(**{"content-security-policy": "default-src 'self'; script-src 'unsafe-eval'"})
    )
    assert f["status"] == "WARN"
    assert "unsafe-eval" in f["detail"]


def test_check_csp_fail_absent():
    f = hha.check_content_security_policy(make_conn(**{"content-security-policy": None}))
    assert f["status"] == "FAIL"
    assert f["risk_level"] == "HIGH"
    assert f["severity_score"] == 8
```

- [ ] **Step 2: Run to verify tests fail**

```bash
pytest tests/test_http_headers_auditor.py -k "csp" -v
```

Expected: `AttributeError: module 'http_headers_auditor' has no attribute 'check_content_security_policy'`

- [ ] **Step 3: Add `check_content_security_policy()` to `http_headers_auditor.py`**

Append after `check_x_content_type_options()`:

```python
# ── HDR-03: Content-Security-Policy ──────────────────────────────────────────

_WEAK_CSP = frozenset({"'unsafe-inline'", "'unsafe-eval'"})


def check_content_security_policy(conn: dict) -> dict:
    """HDR-03: CSP must be present and not contain unsafe directives."""
    val = conn.get("headers", {}).get("content-security-policy", "").strip()
    if not val:
        return _finding(
            "HDR-03", "Content-Security-Policy", "FAIL", "HIGH", 8,
            "Content-Security-Policy header is absent. No XSS mitigation policy is enforced.",
            "Define a Content-Security-Policy that restricts script sources. "
            "Start with: Content-Security-Policy: default-src 'self'",
        )
    weak = [kw for kw in _WEAK_CSP if kw in val]
    if weak:
        return _finding(
            "HDR-03", "Content-Security-Policy", "WARN", "HIGH", 0,
            f"Content-Security-Policy present but contains {', '.join(sorted(weak))}, "
            "which weakens XSS protection.",
            "Remove 'unsafe-inline' and 'unsafe-eval'. "
            "Use nonces or hashes for inline scripts instead.",
        )
    return _finding(
        "HDR-03", "Content-Security-Policy", "PASS", "HIGH", 0,
        f"Content-Security-Policy present without unsafe directives: {val[:120]}", "",
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_http_headers_auditor.py -v 2>&1 | tail -25
```

Expected: All 23 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add Network/http-headers-auditor/
git commit -m "feat(http-headers): add HDR-03 Content-Security-Policy check"
```

---

### Task 6: HDR-04 Referrer-Policy check

**Files:**
- Modify: `Network/http-headers-auditor/tests/test_http_headers_auditor.py`
- Modify: `Network/http-headers-auditor/http_headers_auditor.py`

- [ ] **Step 1: Add Referrer-Policy tests**

Append to `tests/test_http_headers_auditor.py`:

```python
# ── HDR-04: Referrer-Policy ───────────────────────────────────────────────────

def test_check_referrer_policy_pass_strict_origin():
    f = hha.check_referrer_policy(
        make_conn(**{"referrer-policy": "strict-origin-when-cross-origin"})
    )
    assert f["check_id"] == "HDR-04"
    assert f["status"] == "PASS"


def test_check_referrer_policy_pass_no_referrer_when_downgrade():
    # Explicitly PASS per design decision
    f = hha.check_referrer_policy(
        make_conn(**{"referrer-policy": "no-referrer-when-downgrade"})
    )
    assert f["status"] == "PASS"


def test_check_referrer_policy_fail_absent():
    f = hha.check_referrer_policy(make_conn(**{"referrer-policy": None}))
    assert f["status"] == "FAIL"
    assert f["risk_level"] == "MEDIUM"
    assert f["severity_score"] == 4


def test_check_referrer_policy_fail_unsafe_url():
    f = hha.check_referrer_policy(make_conn(**{"referrer-policy": "unsafe-url"}))
    assert f["status"] == "FAIL"
    assert f["severity_score"] == 4


def test_check_referrer_policy_fail_origin():
    f = hha.check_referrer_policy(make_conn(**{"referrer-policy": "origin"}))
    assert f["status"] == "FAIL"
```

- [ ] **Step 2: Run to verify tests fail**

```bash
pytest tests/test_http_headers_auditor.py -k "referrer" -v
```

Expected: `AttributeError: module 'http_headers_auditor' has no attribute 'check_referrer_policy'`

- [ ] **Step 3: Add `check_referrer_policy()` to `http_headers_auditor.py`**

Append after `check_content_security_policy()`:

```python
# ── HDR-04: Referrer-Policy ───────────────────────────────────────────────────

_SAFE_REFERRER = frozenset({
    "no-referrer",
    "no-referrer-when-downgrade",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "same-origin",
    "origin-when-cross-origin",
})
_UNSAFE_REFERRER = frozenset({"unsafe-url", "origin"})


def check_referrer_policy(conn: dict) -> dict:
    """HDR-04: Referrer-Policy must be present and not leak full URLs cross-site."""
    val = conn.get("headers", {}).get("referrer-policy", "").strip().lower()
    if not val:
        return _finding(
            "HDR-04", "Referrer-Policy", "FAIL", "MEDIUM", 4,
            "Referrer-Policy header is absent. Browsers use their default policy, "
            "which may send full URLs as referrers to third-party sites.",
            "Add 'Referrer-Policy: strict-origin-when-cross-origin' to all responses.",
        )
    if val in _SAFE_REFERRER:
        return _finding(
            "HDR-04", "Referrer-Policy", "PASS", "MEDIUM", 0,
            f"Referrer-Policy: {val}", "",
        )
    return _finding(
        "HDR-04", "Referrer-Policy", "FAIL", "MEDIUM", 4,
        f"Referrer-Policy: '{val}' leaks full URLs to third-party origins.",
        "Use 'strict-origin-when-cross-origin' or 'no-referrer'.",
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_http_headers_auditor.py -v 2>&1 | tail -30
```

Expected: All 28 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add Network/http-headers-auditor/
git commit -m "feat(http-headers): add HDR-04 Referrer-Policy check"
```

---

### Task 7: HDR-05 Permissions-Policy check

**Files:**
- Modify: `Network/http-headers-auditor/tests/test_http_headers_auditor.py`
- Modify: `Network/http-headers-auditor/http_headers_auditor.py`

- [ ] **Step 1: Add Permissions-Policy tests**

Append to `tests/test_http_headers_auditor.py`:

```python
# ── HDR-05: Permissions-Policy ───────────────────────────────────────────────

def test_check_permissions_policy_pass():
    f = hha.check_permissions_policy(
        make_conn(**{"permissions-policy": "camera=(), microphone=()"})
    )
    assert f["check_id"] == "HDR-05"
    assert f["status"] == "PASS"


def test_check_permissions_policy_warn_absent():
    f = hha.check_permissions_policy(make_conn(**{"permissions-policy": None}))
    assert f["status"] == "WARN"
    assert f["risk_level"] == "LOW"
    assert f["severity_score"] == 0  # WARN → score always 0
```

- [ ] **Step 2: Run to verify tests fail**

```bash
pytest tests/test_http_headers_auditor.py -k "permissions" -v
```

Expected: `AttributeError: module 'http_headers_auditor' has no attribute 'check_permissions_policy'`

- [ ] **Step 3: Add `check_permissions_policy()` to `http_headers_auditor.py`**

Append after `check_referrer_policy()`:

```python
# ── HDR-05: Permissions-Policy ───────────────────────────────────────────────

def check_permissions_policy(conn: dict) -> dict:
    """HDR-05: Permissions-Policy should be present to restrict browser features."""
    val = conn.get("headers", {}).get("permissions-policy", "").strip()
    if val:
        return _finding(
            "HDR-05", "Permissions-Policy", "PASS", "LOW", 0,
            f"Permissions-Policy present: {val[:120]}", "",
        )
    return _finding(
        "HDR-05", "Permissions-Policy", "WARN", "LOW", 0,
        "Permissions-Policy header is absent. Browser features (camera, microphone, "
        "geolocation) are unrestricted.",
        "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to disable "
        "unused browser features.",
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_http_headers_auditor.py -v 2>&1 | tail -35
```

Expected: All 30 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add Network/http-headers-auditor/
git commit -m "feat(http-headers): add HDR-05 Permissions-Policy check"
```

---

### Task 8: `run_audit()` + `compute_overall_risk()` with connectivity short-circuit

**Files:**
- Modify: `Network/http-headers-auditor/tests/test_http_headers_auditor.py`
- Modify: `Network/http-headers-auditor/http_headers_auditor.py`

- [ ] **Step 1: Add `run_audit()` tests**

Append to `tests/test_http_headers_auditor.py`:

```python
# ── run_audit() ───────────────────────────────────────────────────────────────

def test_run_audit_returns_6_findings():
    with patch('http_headers_auditor.get_http_headers', return_value=make_conn()):
        findings = hha.run_audit("acme.ie", 443)
    assert len(findings) == 6


def test_run_audit_all_check_ids_present():
    with patch('http_headers_auditor.get_http_headers', return_value=make_conn()):
        findings = hha.run_audit("acme.ie", 443)
    ids = {f["check_id"] for f in findings}
    assert ids == {"HDR-00", "HDR-01", "HDR-02", "HDR-03", "HDR-04", "HDR-05"}


def test_run_audit_connectivity_fail_short_circuits_to_6_findings():
    with patch('http_headers_auditor.get_http_headers', return_value=None):
        findings = hha.run_audit("unreachable.ie", 443)
    assert len(findings) == 6
    assert findings[0]["check_id"] == "HDR-00"
    assert findings[0]["status"] == "FAIL"
    # Remaining 5 should all be FAIL with skip message
    for f in findings[1:]:
        assert f["status"] == "FAIL"
        assert "skipped" in f["detail"].lower()


def test_run_audit_all_findings_have_pillar_headers():
    with patch('http_headers_auditor.get_http_headers', return_value=make_conn()):
        findings = hha.run_audit("acme.ie", 443)
    for f in findings:
        assert f["pillar"] == "headers", f"Expected pillar='headers', got '{f['pillar']}' for {f['check_id']}"
```

- [ ] **Step 2: Run to verify tests fail**

```bash
pytest tests/test_http_headers_auditor.py -k "run_audit" -v
```

Expected: `AttributeError: module 'http_headers_auditor' has no attribute 'run_audit'`

- [ ] **Step 3: Add `run_audit()` and `compute_overall_risk()` to `http_headers_auditor.py`**

Append after `check_permissions_policy()`:

```python
# ── Orchestration ─────────────────────────────────────────────────────────────

_SKIP = "Could not connect — skipped."


def run_audit(domain: str, port: int = 443) -> list:
    """Run all HTTP header checks for domain:port. Always returns exactly 6 findings."""
    conn = get_http_headers(domain, port)
    findings = [check_connectivity(conn, domain, port)]
    if conn is None:
        findings.extend([
            _finding("HDR-01", "X-Frame-Options",         "FAIL", "HIGH",   0, _SKIP, ""),
            _finding("HDR-02", "X-Content-Type-Options",  "FAIL", "MEDIUM", 0, _SKIP, ""),
            _finding("HDR-03", "Content-Security-Policy", "FAIL", "HIGH",   0, _SKIP, ""),
            _finding("HDR-04", "Referrer-Policy",         "FAIL", "MEDIUM", 0, _SKIP, ""),
            _finding("HDR-05", "Permissions-Policy",      "FAIL", "LOW",    0, _SKIP, ""),
        ])
        return findings
    findings.extend([
        check_x_frame_options(conn),
        check_x_content_type_options(conn),
        check_content_security_policy(conn),
        check_referrer_policy(conn),
        check_permissions_policy(conn),
    ])
    return findings


def compute_overall_risk(findings: list) -> tuple:
    """Return (overall_risk_level, total_severity_score) from findings list."""
    score = sum(f.get("severity_score", 0) for f in findings)
    has_critical = any(
        f.get("risk_level") == "CRITICAL" and f.get("status") == "FAIL"
        for f in findings
    )
    if has_critical or score >= 10:
        return "CRITICAL", score
    if score >= 6:
        return "HIGH", score
    if score >= 3:
        return "MEDIUM", score
    return "LOW", score
```

- [ ] **Step 4: Run full test suite to verify all pass**

```bash
pytest tests/test_http_headers_auditor.py -v 2>&1 | tail -40
```

Expected: All 34 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add Network/http-headers-auditor/
git commit -m "feat(http-headers): add run_audit() with connectivity short-circuit"
```

---

### Task 9: Output writers + `run()` CLI entry point

**Files:**
- Modify: `Network/http-headers-auditor/http_headers_auditor.py`

No TDD for output writers — they produce files and are tested via a light smoke test.

- [ ] **Step 1: Append output writers and `run()` to `http_headers_auditor.py`**

Append after `compute_overall_risk()`:

```python
# ── Output ─────────────────────────────────────────────────────────────────────

def write_json(report: dict, prefix: str) -> None:
    path = Path(f"{prefix}.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    log.info("JSON report: %s", path)


def write_csv(findings: list, prefix: str) -> None:
    path = Path(f"{prefix}.csv")
    path.parent.mkdir(parents=True, exist_ok=True)
    if not findings:
        return
    fields = ["check_id", "name", "status", "risk_level", "severity_score", "detail", "remediation"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)
    log.info("CSV report: %s", path)


def write_html(report: dict, prefix: str) -> None:
    path = Path(f"{prefix}.html")
    path.parent.mkdir(parents=True, exist_ok=True)
    domain = report.get("domain", "")
    summary = report.get("summary", {})
    overall = summary.get("overall_risk", "UNKNOWN")
    score = summary.get("severity_score", 0)
    generated = report.get("generated_at", "")

    risk_colour = {
        "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107", "LOW": "#28a745",
    }.get(overall, "#6c757d")
    status_colour = {"PASS": "#28a745", "FAIL": "#dc3545", "WARN": "#ffc107"}

    rows = ""
    for f in report.get("findings", []):
        sc = status_colour.get(f.get("status", ""), "#6c757d")
        rows += (
            f"<tr>"
            f"<td>{html_lib.escape(f.get('check_id', ''))}</td>"
            f"<td>{html_lib.escape(f.get('name', ''))}</td>"
            f"<td style='color:{sc};font-weight:700'>{html_lib.escape(f.get('status', ''))}</td>"
            f"<td>{html_lib.escape(f.get('risk_level', ''))}</td>"
            f"<td>{html_lib.escape(f.get('detail', ''))}</td>"
            f"<td>{html_lib.escape(f.get('remediation', ''))}</td>"
            f"</tr>\n"
        )

    html_content = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>HTTP Headers Audit \u2014 {html_lib.escape(domain)}</title>
<style>
  body{{font-family:sans-serif;margin:2rem;background:#f8f9fa}}
  h1{{color:#212529}} .badge{{display:inline-block;padding:4px 12px;border-radius:4px;
  color:#fff;font-weight:700;background:{risk_colour}}}
  table{{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;overflow:hidden;
  box-shadow:0 2px 8px rgba(0,0,0,.06)}}
  th{{background:#343a40;color:#fff;padding:10px 14px;text-align:left}}
  td{{padding:10px 14px;border-bottom:1px solid #dee2e6;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
</style></head><body>
<h1>HTTP Security Headers Audit</h1>
<p><strong>Domain:</strong> {html_lib.escape(domain)} &nbsp;
   <strong>Risk:</strong> <span class="badge">{html_lib.escape(overall)}</span> &nbsp;
   <strong>Score:</strong> {score} &nbsp;
   <strong>Generated:</strong> {html_lib.escape(generated)}</p>
<table>
<thead><tr><th>ID</th><th>Check</th><th>Status</th><th>Risk</th><th>Detail</th><th>Remediation</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""

    path.write_text(html_content)
    log.info("HTML report: %s", path)


# ── Entry point ────────────────────────────────────────────────────────────────

def run(domain: str, port: int, output_prefix: str, fmt: str) -> dict:
    """Run all HTTP header checks for domain and write reports. Returns report dict."""
    findings = run_audit(domain, port)
    overall_risk, score = compute_overall_risk(findings)

    report = {
        "domain": domain,
        "port": port,
        "generated_at": NOW.isoformat(),
        "summary": {
            "overall_risk": overall_risk,
            "severity_score": score,
            "connected": any(
                f["check_id"] == "HDR-00" and f["status"] == "PASS" for f in findings
            ),
        },
        "findings": findings,
        "pillar": "headers",
        "risk_level": overall_risk,
    }

    if fmt in ("json", "all"):
        write_json(report, output_prefix)
    if fmt in ("csv", "all"):
        write_csv(findings, output_prefix)
    if fmt in ("html", "all"):
        write_html(report, output_prefix)
    if fmt == "stdout":
        print(json.dumps(report, indent=2, default=str))

    col = {
        "CRITICAL": "\033[91m", "HIGH": "\033[33m",
        "MEDIUM": "\033[93m", "LOW": "\033[92m",
    }.get(overall_risk, "")
    end = "\033[0m"
    print(f"\n{'='*44}")
    print(f"  HTTP HEADERS AUDIT -- {domain}:{port}")
    print(f"{'-'*44}")
    print(f"  Overall risk:    {col}{overall_risk}{end}")
    print(f"  Score:           {score}")
    print(f"  Connected:       {'Yes' if report['summary']['connected'] else 'No'}")
    print(f"{'='*44}\n")

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Security Headers Auditor")
    parser.add_argument("--domain", required=True, help="Domain to audit (e.g. acme.ie)")
    parser.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument("--output", "-o", default="http_headers_report",
                        help="Output filename prefix (default: http_headers_report)")
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "html", "all", "stdout"],
        default="json",
        help="Output format (default: json)",
    )
    args = parser.parse_args()
    run(args.domain, args.port, args.output, args.format)
```

- [ ] **Step 2: Run full test suite to confirm nothing regressed**

```bash
pytest tests/test_http_headers_auditor.py -v 2>&1 | tail -40
```

Expected: All 34 tests PASS.

- [ ] **Step 3: Smoke-test the CLI with stdout format (no live network calls needed)**

```bash
cd Network/http-headers-auditor
python3 -c "
import http_headers_auditor as h
from unittest.mock import patch
conn = {
    'headers': {
        'x-frame-options': 'SAMEORIGIN',
        'x-content-type-options': 'nosniff',
        'content-security-policy': \"default-src 'self'\",
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=()',
    }
}
with patch('http_headers_auditor.get_http_headers', return_value=conn):
    report = h.run('acme.ie', 443, '/tmp/smoke_test', 'json')
print('findings count:', len(report['findings']))
print('all check IDs:', sorted(f['check_id'] for f in report['findings']))
"
```

Expected output:
```
findings count: 6
all check IDs: ['HDR-00', 'HDR-01', 'HDR-02', 'HDR-03', 'HDR-04', 'HDR-05']
```

- [ ] **Step 4: Commit**

```bash
git add Network/http-headers-auditor/
git commit -m "feat(http-headers): add output writers and run() CLI entry point"
```

---

### Task 10: `audit.py` orchestrator integration

**Files:**
- Modify: `audit.py`

- [ ] **Step 1: Add `"http_headers"` to `AUDITOR_MAP` in `audit.py`**

In `audit.py`, find the `# ── Network ───` section (around line 89) and add after the `"ssl"` entry:

```python
    # ── Network ───────────────────────────────────────────────────────────────
    "ssl": AuditorDef(
        REPO_ROOT / "Network/ssl-tls-auditor/ssl_tls_auditor.py",
        "ssl_report",
        supports_regions=False,
        requires_domain=True,
    ),
    "http_headers": AuditorDef(
        REPO_ROOT / "Network/http-headers-auditor/http_headers_auditor.py",
        "http_headers_report",
        supports_regions=False,
        requires_domain=True,
    ),
```

- [ ] **Step 2: Add `--http-headers` CLI flag in `parse_args()`**

In `audit.py`, find the `--ssl` flag line (around line 241) and add immediately after:

```python
    groups.add_argument("--ssl",          action="store_true", help="Run SSL/TLS certificate auditor (requires --domain)")
    groups.add_argument("--http-headers", action="store_true", help="Run HTTP security headers auditor (requires --domain)")
```

- [ ] **Step 3: Add `--http-headers` to the epilog usage section**

In `audit.py`, find the SSL/TLS section in the epilog (around line 185) and add an HTTP HEADERS section immediately after the SSL/TLS block:

```
━━━ HTTP HEADERS AUDITOR (--http-headers requires --domain) ━━━━━━━━━━━━━━━━━

  --http-headers  X-Frame-Options, X-Content-Type-Options, Content-Security-Policy,
                  Referrer-Policy, Permissions-Policy
                  Requires: --domain acme.ie
                  No cloud credentials needed — HTTPS port 443 only

  Example:
    python3 audit.py --client "Acme Corp" --http-headers --domain acme.ie
    python3 audit.py --client "Acme Corp" --ssl --http-headers --domain acme.ie

```

- [ ] **Step 4: Verify audit.py syntax is valid**

```bash
python3 -c "import audit; print('AUDITOR_MAP keys:', list(audit.AUDITOR_MAP.keys())[-3:])"
```

Expected: `AUDITOR_MAP keys: ['...', 'ssl', 'http_headers']`

- [ ] **Step 5: Verify `--http-headers` flag is recognised**

```bash
python3 audit.py --help | grep http-headers
```

Expected: Line containing `--http-headers` with the description.

- [ ] **Step 6: Commit**

```bash
git add audit.py
git commit -m "feat(http-headers): integrate into audit.py orchestrator"
```

---

### Task 11: `exec_summary.py` integration

**Files:**
- Modify: `tools/exec_summary.py`

- [ ] **Step 1: Add `"http_headers_report.json"` to `KNOWN_PATTERNS`**

In `tools/exec_summary.py`, find the `# Network / SSL-TLS` comment (around line 64) and add after `"ssl_report.json"`:

```python
    # Network / SSL-TLS
    "ssl_report.json",
    # Network / HTTP Headers
    "http_headers_report.json",
```

- [ ] **Step 2: Add `"http_headers"` to `PILLAR_LABELS`**

In `tools/exec_summary.py`, find the `"tls": "SSL/TLS Certificates"` line (around line 101) and add immediately after:

```python
    "tls":          "SSL/TLS Certificates",
    "http_headers": "HTTP Security Headers",
```

- [ ] **Step 3: Verify exec_summary.py syntax is valid**

```bash
python3 -c "import sys; sys.path.insert(0,'tools'); import exec_summary; print('http_headers' in exec_summary.PILLAR_LABELS, 'http_headers_report.json' in exec_summary.KNOWN_PATTERNS)"
```

Expected: `True True`

- [ ] **Step 4: Commit**

```bash
git add tools/exec_summary.py
git commit -m "feat(http-headers): integrate into exec_summary.py"
```

---

### Task 12: README updates

**Files:**
- Modify: `Network/README.md`
- Modify: `README.md`

- [ ] **Step 1: Update `Network/README.md`**

Replace the entire content of `Network/README.md` with:

```markdown
# Network

Network security auditors. These auditors check network-exposed services — no cloud credentials are required.

## Auditors

| Auditor | Script | What it checks |
|---|---|---|
| [ssl-tls-auditor](ssl-tls-auditor/) | `ssl_tls_auditor.py` | Cert expiry · Hostname match · Self-signed · Key algorithm · TLS version · Weak cipher · HSTS |
| [http-headers-auditor](http-headers-auditor/) | `http_headers_auditor.py` | X-Frame-Options · X-Content-Type-Options · Content-Security-Policy · Referrer-Policy · Permissions-Policy |
```

- [ ] **Step 2: Update root `README.md` — architecture diagram**

In `README.md`, find the Network subgraph line (around line 37):

```
    subgraph Network["🌐 Network  —  1 auditor  (Python · stdlib)"]
        N["SSL/TLS Certificates"]
    end
```

Replace with:

```
    subgraph Network["🌐 Network  —  2 auditors  (Python · stdlib)"]
        N["SSL/TLS Certificates · HTTP Security Headers"]
    end
```

- [ ] **Step 3: Update root `README.md` — orchestrator flag line**

Find (around line 81):

```
**Flags:** `--aws` (all 13 AWS) · `--linux` (all 4 Linux) · `--windows` (Azure/Windows PS1 guide) · `--all` (everything) · `--profile` · `--regions` · `--output` · `--format` · `--workers` · `--open`
```

Add `--http-headers` to the flags list (after `--ssl`):

```
**Flags:** `--aws` (all 13 AWS) · `--linux` (all 4 Linux) · `--windows` (Azure/Windows PS1 guide) · `--all` (everything) · `--ssl --domain` · `--http-headers --domain` · `--email --domain` · `--profile` · `--regions` · `--output` · `--format` · `--workers` · `--open`
```

- [ ] **Step 4: Update root `README.md` — Network table in Scripts section**

Find (around line 201):

```markdown
### Network

| Script | Description | Output |
|--------|-------------|--------|
| [SSL/TLS Auditor](./Network/ssl-tls-auditor/) | Audits a domain's SSL/TLS certificate and TLS configuration — cert expiry, hostname match, self-signed detection, key algorithm, TLS version (min 1.2), weak cipher suite, and HSTS header. No credentials required; TCP port 443 only. | JSON, CSV, HTML |
```

Replace with:

```markdown
### Network

| Script | Description | Output |
|--------|-------------|--------|
| [SSL/TLS Auditor](./Network/ssl-tls-auditor/) | Audits a domain's SSL/TLS certificate and TLS configuration — cert expiry, hostname match, self-signed detection, key algorithm, TLS version (min 1.2), weak cipher suite, and HSTS header. No credentials required; TCP port 443 only. | JSON, CSV, HTML |
| [HTTP Security Headers Auditor](./Network/http-headers-auditor/) | Audits a domain's HTTP security response headers over HTTPS — X-Frame-Options, X-Content-Type-Options, Content-Security-Policy (with unsafe-inline/eval detection), Referrer-Policy, and Permissions-Policy. No credentials required; HTTPS port 443 only. | JSON, CSV, HTML |
```

- [ ] **Step 5: Update root `README.md` — repository structure**

Find (around line 122):

```
├── Network/
│   ├── README.md
│   └── ssl-tls-auditor/         # SSL/TLS cert expiry, hostname, TLS version, cipher, HSTS
```

Replace with:

```
├── Network/
│   ├── README.md
│   ├── ssl-tls-auditor/         # SSL/TLS cert expiry, hostname, TLS version, cipher, HSTS
│   └── http-headers-auditor/    # X-Frame-Options, CSP, Referrer-Policy, Permissions-Policy
```

- [ ] **Step 6: Run the full test suite one final time**

```bash
pytest Network/http-headers-auditor/tests/ -v
```

Expected: All 34 tests PASS, 0 failures.

- [ ] **Step 7: Commit**

```bash
git add Network/README.md README.md
git commit -m "docs: update READMEs for HTTP security headers auditor"
```

---

## Final verification

```bash
# All tests pass
pytest Network/http-headers-auditor/tests/ -v

# audit.py recognises the new flag
python3 audit.py --help | grep -A3 "http-headers"

# exec_summary picks up the new pattern
python3 -c "import sys; sys.path.insert(0,'tools'); import exec_summary; print('http_headers' in exec_summary.PILLAR_LABELS)"

# Auditor module has no syntax errors
python3 -m py_compile Network/http-headers-auditor/http_headers_auditor.py && echo "syntax OK"
```
