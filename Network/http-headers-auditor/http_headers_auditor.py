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
            "Replace with: Content-Security-Policy: frame-ancestors 'self' https://trusted.com",
        )
    return _finding(
        "HDR-01", "X-Frame-Options", "FAIL", "HIGH", 7,
        f"X-Frame-Options value '{val}' is not recognised. Expected DENY or SAMEORIGIN.",
        "Set X-Frame-Options to DENY or SAMEORIGIN.",
    )


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


# ── HDR-04: Referrer-Policy ───────────────────────────────────────────────────

_SAFE_REFERRER = frozenset({
    "no-referrer",
    "no-referrer-when-downgrade",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "same-origin",
    "origin-when-cross-origin",
})


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
