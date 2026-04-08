"""Adversarial HTML escaping tests for all auditor write_html functions.

Each test injects an XSS payload into every user-controlled field of a
report fixture and asserts the raw payload does not appear in the HTML
output.  The fixed output must contain the html-escaped form instead.
"""
import sys
import os
import html
from pathlib import Path
from unittest.mock import patch

# Repo root and all auditor dirs on path before any module imports
_REPO = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "tools"))
sys.path.insert(0, str(_REPO / "OnPrem" / "Linux" / "linux-ssh-auditor"))
sys.path.insert(0, str(_REPO / "OnPrem" / "Linux" / "linux-sysctl-auditor"))
sys.path.insert(0, str(_REPO / "OnPrem" / "Linux" / "linux-firewall-auditor"))
sys.path.insert(0, str(_REPO / "OnPrem" / "Linux" / "linux-user-auditor"))
sys.path.insert(0, str(_REPO / "OnPrem" / "Linux" / "linux-patch-auditor"))
sys.path.insert(0, str(_REPO / "Email" / "email-security-auditor"))
sys.path.insert(0, str(_REPO / "Network" / "ssl-tls-auditor"))
sys.path.insert(0, str(_REPO / "Network" / "http-headers-auditor"))

import linux_ssh_auditor as lsa
import linux_sysctl_auditor as lsys
import linux_firewall_auditor as lfw
import linux_user_auditor as lua
import linux_patch_auditor as lpa
import exec_summary as es
import email_security_auditor as esa
import ssl_tls_auditor as sta
import http_headers_auditor as hha

XSS = "<script>alert('xss')</script>"


def _assert_escaped(content: str):
    """Assert the raw XSS payload does not appear verbatim in HTML."""
    assert XSS not in content, (
        f"Raw XSS payload found in HTML output — escaping missing.\n"
        f"Payload: {XSS!r}"
    )


# ── Linux SSH auditor ──────────────────────────────────────────────────────────

def test_ssh_write_html_escapes_hostname(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': XSS,
        'findings': [],
        'summary': {
            'total_checks': 0, 'compliant': 0, 'non_compliant': 0,
            'unavailable': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'overall_risk': 'LOW', 'severity_score': 0,
        },
    }
    path = str(tmp_path / 'ssh.html')
    with patch('os.chmod'):
        lsa.write_html(report, path)
    _assert_escaped(Path(path).read_text())


def test_ssh_write_html_escapes_finding_fields(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': 'testhost',
        'findings': [{
            'param': XSS, 'actual': XSS, 'expected': 'no',
            'description': XSS, 'recommendation': XSS,
            'compliant': False, 'severity_if_wrong': 'HIGH', 'risk_level': 'HIGH',
        }],
        'summary': {
            'total_checks': 1, 'compliant': 0, 'non_compliant': 1,
            'unavailable': 0, 'critical': 0, 'high': 1, 'medium': 0, 'low': 0,
            'overall_risk': 'HIGH', 'severity_score': 7,
        },
    }
    path = str(tmp_path / 'ssh.html')
    with patch('os.chmod'):
        lsa.write_html(report, path)
    _assert_escaped(Path(path).read_text())


# ── Linux sysctl auditor ───────────────────────────────────────────────────────

def test_sysctl_write_html_escapes_hostname(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': XSS,
        'findings': [],
        'summary': {
            'total_checks': 0, 'compliant': 0, 'non_compliant': 0,
            'unavailable': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'overall_risk': 'LOW', 'severity_score': 0,
        },
    }
    path = str(tmp_path / 'sysctl.html')
    with patch('os.chmod'):
        lsys.write_html(report, path)
    _assert_escaped(Path(path).read_text())


def test_sysctl_write_html_escapes_finding_fields(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': 'testhost',
        'findings': [{
            'param': XSS, 'expected': '0', 'actual': XSS,
            'description': XSS, 'remediation': XSS,
            'compliant': False, 'severity_if_wrong': 'HIGH',
        }],
        'summary': {
            'total_checks': 1, 'compliant': 0, 'non_compliant': 1,
            'unavailable': 0, 'critical': 0, 'high': 1, 'medium': 0, 'low': 0,
            'overall_risk': 'HIGH', 'severity_score': 7,
        },
    }
    path = str(tmp_path / 'sysctl.html')
    with patch('os.chmod'):
        lsys.write_html(report, path)
    _assert_escaped(Path(path).read_text())


# ── Linux firewall auditor ─────────────────────────────────────────────────────

def test_firewall_write_html_escapes_hostname_and_backend(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': XSS, 'firewall_backend': XSS,
        'findings': [],
        'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
                    'default_policy': 'DROP', 'overall_risk': 'LOW'},
    }
    path = str(tmp_path / 'fw.html')
    with patch('os.chmod'):
        lfw.write_html(report, path)
    _assert_escaped(Path(path).read_text())


def test_firewall_write_html_escapes_finding_fields(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': 'testhost', 'firewall_backend': 'iptables',
        'findings': [{
            'finding_type': XSS, 'severity': 'HIGH', 'score': 7,
            'detail': XSS, 'recommendation': XSS,
            'port': XSS, 'service': XSS,
        }],
        'summary': {'total': 1, 'critical': 0, 'high': 1, 'medium': 0, 'low': 0,
                    'default_policy': 'DROP', 'overall_risk': 'HIGH'},
    }
    path = str(tmp_path / 'fw.html')
    with patch('os.chmod'):
        lfw.write_html(report, path)
    _assert_escaped(Path(path).read_text())


# ── Linux user auditor ─────────────────────────────────────────────────────────

def test_user_write_html_escapes_hostname(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': XSS,
        'findings': [],
        'summary': {'total_findings': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
                    'overall_risk': 'LOW'},
    }
    path = str(tmp_path / 'user.html')
    with patch('os.chmod'):
        lua.write_html(report, path)
    _assert_escaped(Path(path).read_text())


def test_user_write_html_escapes_finding_fields(tmp_path):
    report = {
        'generated_at': '2026-01-01', 'hostname': 'testhost',
        'findings': [{
            'finding_type': XSS, 'severity': 'HIGH', 'score': 7,
            'username': XSS, 'detail': XSS, 'recommendation': XSS,
        }],
        'summary': {'total_findings': 1, 'critical': 0, 'high': 1, 'medium': 0, 'low': 0,
                    'overall_risk': 'HIGH'},
    }
    path = str(tmp_path / 'user.html')
    with patch('os.chmod'):
        lua.write_html(report, path)
    _assert_escaped(Path(path).read_text())


# ── Linux patch auditor ────────────────────────────────────────────────────────

def test_patch_write_html_escapes_hostname_and_kernel(tmp_path):
    finding = {
        'hostname': 'testhost', 'kernel': 'testkernel',
        'package_manager': 'apt', 'total_updates': 0, 'security_updates': 0,
        'pending_packages': [], 'last_update': None, 'days_since_update': None,
        'auto_updates_enabled': True, 'auto_update_agent': 'unattended-upgrades',
        'risk_level': 'LOW', 'severity_score': 0, 'flags': [], 'remediations': [],
    }
    report = {
        'generated_at': '2026-01-01', 'hostname': XSS, 'kernel': XSS,
        'package_manager': 'apt',
        'summary': {'total_updates': 0, 'security_updates': 0, 'days_since_update': None,
                    'auto_updates_enabled': True, 'overall_risk': 'LOW', 'severity_score': 0},
        'findings': [finding], 'pillar': 'patch', 'risk_level': 'LOW',
    }
    path = str(tmp_path / 'patch.html')
    with patch('os.chmod'):
        lpa.write_html(report, path)
    _assert_escaped(Path(path).read_text())


def test_patch_write_html_escapes_finding_flags_and_packages(tmp_path):
    finding = {
        'hostname': 'testhost', 'kernel': '5.15.0',
        'package_manager': XSS, 'total_updates': 3, 'security_updates': 2,
        'pending_packages': [XSS], 'last_update': None, 'days_since_update': 30,
        'auto_updates_enabled': False, 'auto_update_agent': XSS,
        'risk_level': 'HIGH', 'severity_score': 7,
        'flags': [XSS], 'remediations': [XSS],
    }
    report = {
        'generated_at': '2026-01-01', 'hostname': 'testhost', 'kernel': '5.15.0',
        'package_manager': XSS,
        'summary': {'total_updates': 3, 'security_updates': 2, 'days_since_update': 30,
                    'auto_updates_enabled': False, 'overall_risk': 'HIGH', 'severity_score': 7},
        'findings': [finding], 'pillar': 'patch', 'risk_level': 'HIGH',
    }
    path = str(tmp_path / 'patch.html')
    with patch('os.chmod'):
        lpa.write_html(report, path)
    _assert_escaped(Path(path).read_text())


# ── exec_summary write_html ────────────────────────────────────────────────────

def test_exec_summary_write_html_escapes_pillar_label(tmp_path):
    pillar_stats = [
        {'pillar': 's3', 'label': XSS, 'critical': 1, 'high': 0, 'medium': 0, 'low': 0,
         'total': 1, 'pillar_risk': 'CRITICAL', 'generated_at': '2026-01-01'},
    ]
    out = str(tmp_path / 'exec.html')
    es.write_html(
        overall_score=90.0, grade='A',
        pillar_stats=pillar_stats,
        top_findings=[], quick_wins=[],
        generated_at='2026-01-01T00:00:00+00:00',
        path=out,
    )
    _assert_escaped(Path(out).read_text())


def test_exec_summary_write_html_escapes_finding_flag_and_remediation(tmp_path):
    top_findings = [{
        'pillar': 's3', 'risk_level': 'CRITICAL', 'severity_score': 9,
        'name': XSS,
        'flags': [XSS],
        'remediations': [XSS],
    }]
    out = str(tmp_path / 'exec.html')
    es.write_html(
        overall_score=90.0, grade='A',
        pillar_stats=[],
        top_findings=top_findings,
        quick_wins=[],
        generated_at='2026-01-01T00:00:00+00:00',
        path=out,
    )
    _assert_escaped(Path(out).read_text())


def test_exec_summary_write_html_escapes_client_name(tmp_path):
    out = str(tmp_path / 'exec.html')
    es.write_html(
        overall_score=90.0, grade='A',
        pillar_stats=[], top_findings=[], quick_wins=[],
        generated_at='2026-01-01T00:00:00+00:00',
        path=out,
        client_name=XSS,
    )
    _assert_escaped(Path(out).read_text())


# ── Email security auditor ────────────────────────────────────────────────────

def test_email_write_html_escapes_domain_and_findings(tmp_path):
    report = {
        'domain': XSS,
        'generated_at': '2026-01-01',
        'findings': [{
            'check_id': XSS, 'name': XSS,
            'status': 'FAIL', 'risk_level': 'CRITICAL', 'severity_score': 8,
            'detail': XSS, 'remediation': XSS,
            'pillar': 'email', 'cis_control': 'CIS 9',
        }],
        'summary': {'overall_risk': 'CRITICAL', 'severity_score': 8,
                    'spf': 'FAIL', 'dkim': 'FAIL', 'dmarc': 'FAIL',
                    'critical': 1, 'high': 0, 'medium': 0, 'low': 0, 'total': 1},
    }
    prefix = str(tmp_path / 'email_report')
    with patch('pathlib.Path.chmod'):
        esa.write_html(report, prefix)
    content = (tmp_path / 'email_report.html').read_text()
    _assert_escaped(content)


# ── SSL/TLS auditor ────────────────────────────────────────────────────────────

def test_ssl_write_html_escapes_domain_and_findings(tmp_path):
    report = {
        'domain': XSS, 'port': 443,
        'generated_at': '2026-01-01',
        'findings': [{
            'check_id': XSS, 'name': XSS,
            'status': 'FAIL', 'risk_level': 'CRITICAL', 'severity_score': 8,
            'detail': XSS, 'remediation': XSS,
            'pillar': 'tls', 'cis_control': 'CIS 4',
        }],
        'summary': {'overall_risk': 'CRITICAL', 'severity_score': 8,
                    'critical': 1, 'high': 0, 'medium': 0, 'low': 0},
    }
    prefix = str(tmp_path / 'ssl_report')
    with patch('pathlib.Path.chmod'):
        sta.write_html(report, prefix, client_name=XSS, assessor=XSS)
    content = (tmp_path / 'ssl_report.html').read_text()
    _assert_escaped(content)


# ── HTTP headers auditor ───────────────────────────────────────────────────────

def test_http_headers_write_html_escapes_domain_and_findings(tmp_path):
    report = {
        'domain': XSS, 'port': 443,
        'generated_at': '2026-01-01',
        'findings': [{
            'check_id': XSS, 'name': XSS,
            'status': 'FAIL', 'risk_level': 'HIGH', 'severity_score': 4,
            'detail': XSS, 'remediation': XSS,
            'pillar': 'http_headers', 'cis_control': 'CIS 14',
        }],
        'summary': {'overall_risk': 'HIGH', 'severity_score': 4,
                    'critical': 0, 'high': 1, 'medium': 0, 'low': 0},
    }
    prefix = str(tmp_path / 'http_headers_report')
    with patch('pathlib.Path.chmod'):
        hha.write_html(report, prefix)
    content = (tmp_path / 'http_headers_report.html').read_text()
    _assert_escaped(content)
