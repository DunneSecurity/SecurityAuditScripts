"""Tests for iam_mapper_v2.py — remediation hints in HTML output."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import iam_mapper_v2 as iam_mapper


def test_write_html_includes_remediation_for_mfa_warning(tmp_path):
    """write_html should include remediation text for MFA warning."""
    report = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "account_id": "123456789012",
        "scp_analysis": False,
        "summary": {
            "total_principals": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "users_without_mfa": 1,
            "stale_keys": 0,
            "cross_account_roles": 0,
            "admin_policy_holders": 0,
        },
        "findings": [{
            "type": "user",
            "name": "alice",
            "arn": "arn:aws:iam::123:user/alice",
            "risk_level": "CRITICAL",
            "severity_score": 8,
            "console_access": True,
            "password_last_used": None,
            "mfa_enabled": False,
            "mfa_warning": True,
            "groups": [],
            "has_admin_policy": False,
            "permission_boundary": None,
            "high_risk_actions": [],
            "privilege_escalation_paths": [],
            "access_key_issues": [],
            "access_keys": [],
            "total_actions_count": 5,
            "scp_restrictions_applied": False,
            "cross_account_trust": False,
        }],
    }
    path = str(tmp_path / "test.html")
    iam_mapper.write_html(report, path)
    content = open(path).read()
    assert "IAM Console" in content
    assert "MFA device" in content
    assert "rem-text" in content


def test_write_html_includes_remediation_for_admin_policy(tmp_path):
    """write_html should include remediation text for admin policy warning."""
    report = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "account_id": "123456789012",
        "scp_analysis": False,
        "summary": {
            "total_principals": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "users_without_mfa": 0,
            "stale_keys": 0,
            "cross_account_roles": 0,
            "admin_policy_holders": 1,
        },
        "findings": [{
            "type": "user",
            "name": "admin-user",
            "arn": "arn:aws:iam::123:user/admin-user",
            "risk_level": "CRITICAL",
            "severity_score": 9,
            "console_access": True,
            "password_last_used": None,
            "mfa_enabled": True,
            "mfa_warning": False,
            "groups": [],
            "has_admin_policy": True,
            "permission_boundary": None,
            "high_risk_actions": ["*"],
            "privilege_escalation_paths": [],
            "access_key_issues": [],
            "access_keys": [],
            "total_actions_count": 1,
            "scp_restrictions_applied": False,
            "cross_account_trust": False,
        }],
    }
    path = str(tmp_path / "test.html")
    iam_mapper.write_html(report, path)
    content = open(path).read()
    assert "AdministratorAccess" in content
    assert "least-privilege" in content
