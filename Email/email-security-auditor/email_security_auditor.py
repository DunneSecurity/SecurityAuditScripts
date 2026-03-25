#!/usr/bin/env python3
"""
Email Security Auditor
=======================
Audits a domain's email security DNS configuration:
- MX record presence
- SPF: existence, permissiveness, lookup count (shallow)
- DKIM: record presence, key length
- DMARC: existence, policy enforcement, reporting configuration

Usage:
    python3 email_security_auditor.py --domain acme.ie
    python3 email_security_auditor.py --domain acme.ie --selector google
    python3 email_security_auditor.py --domain acme.ie --format all --output email_report
"""

import argparse
import base64
import csv
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import dns.resolver
import dns.exception

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

NOW = datetime.now(timezone.utc)

# DKIM selectors to probe in order (M365-first for Irish SMB market)
DKIM_SELECTORS = [
    "selector1", "selector2", "google", "default", "mail", "k1",
    "dkim", "mailjet", "sendgrid", "amazonses", "mandrill", "smtp",
    "email", "zoho", "protonmail",
]


# ── DNS wrappers (thin — mock these in tests) ─────────────────────────────────

def query_txt(name: str) -> Optional[list]:
    """
    Query TXT records for name.
    Returns list of strings on success, [] on NXDOMAIN/NoAnswer, None on transient error.
    """
    try:
        answer = dns.resolver.resolve(name, 'TXT')
        result = []
        for rdata in answer:
            for s in rdata.strings:
                result.append(s.decode('utf-8', errors='replace') if isinstance(s, bytes) else s)
        return result
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
        return None


def query_mx(domain: str) -> Optional[list]:
    """
    Query MX records for domain.
    Returns list of exchange hostname strings, [] on NXDOMAIN/NoAnswer, None on transient error.
    """
    try:
        answer = dns.resolver.resolve(domain, 'MX')
        return [str(rdata.exchange) for rdata in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
        return None
