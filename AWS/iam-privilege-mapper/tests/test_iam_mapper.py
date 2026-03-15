"""Tests for iam_mapper_v2.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import stat
import pytest
from unittest.mock import MagicMock, patch
import iam_mapper_v2 as iam


# ── extract_actions ────────────────────────────────────────────────────────────

def test_extract_actions_allow():
    doc = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"]}]}
    assert iam.extract_actions(doc) == {"s3:getobject", "s3:putobject"}


def test_extract_actions_skips_deny():
    doc = {"Statement": [{"Effect": "Deny", "Action": "s3:*"}]}
    assert iam.extract_actions(doc) == set()


def test_extract_actions_string_action():
    doc = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole"}]}
    assert "iam:passrole" in iam.extract_actions(doc)


def test_extract_actions_dict_statement():
    doc = {"Statement": {"Effect": "Allow", "Action": ["ec2:*"]}}
    assert "ec2:*" in iam.extract_actions(doc)


# ── score_actions ──────────────────────────────────────────────────────────────

def test_score_actions_wildcard():
    assert "*" in iam.score_actions({"*"})


def test_score_actions_service_wildcard():
    assert "iam:*" in iam.score_actions({"iam:*"})


def test_score_actions_no_risk():
    result = iam.score_actions({"s3:getobject", "cloudwatch:putmetricdata"})
    assert result == []


# ── check_privesc ──────────────────────────────────────────────────────────────

def test_check_privesc_passrole_lambda():
    actions = {"iam:passrole", "lambda:createfunction", "lambda:invokefunction"}
    paths = iam.check_privesc(actions)
    assert any("PassRole" in p and "Lambda" in p for p in paths)


def test_check_privesc_no_match():
    actions = {"s3:getobject"}
    assert iam.check_privesc(actions) == []


def test_check_privesc_wildcard_covers_all():
    actions = {"*"}
    paths = iam.check_privesc(actions)
    assert len(paths) > 0


# ── calculate_score ────────────────────────────────────────────────────────────

def test_calculate_score_critical():
    score, level = iam.calculate_score({"*", "iam:*"}, ["path1", "path2"], True, True, True, True, False, True)
    assert level == "CRITICAL"
    assert score >= 8


def test_calculate_score_low():
    score, level = iam.calculate_score(set(), [], False, False, False, False, False, False)
    assert level == "LOW"
    assert score == 0


def test_calculate_score_boundary_reduces_score():
    score_no_boundary, _ = iam.calculate_score({"iam:*"}, [], False, False, False, False, False, False)
    score_with_boundary, _ = iam.calculate_score({"iam:*"}, [], False, False, False, False, True, False)
    assert score_with_boundary < score_no_boundary


# ── paginate ───────────────────────────────────────────────────────────────────

def test_paginate_single_page():
    mock_fn = MagicMock(return_value={"Users": [{"UserName": "alice"}]})
    result = iam.paginate(mock_fn, "Users")
    assert result == [{"UserName": "alice"}]


def test_paginate_multiple_pages():
    mock_fn = MagicMock(side_effect=[
        {"Users": [{"UserName": "alice"}], "Marker": "token1"},
        {"Users": [{"UserName": "bob"}]},
    ])
    result = iam.paginate(mock_fn, "Users")
    assert len(result) == 2


# ── check_access_keys ──────────────────────────────────────────────────────────

from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_client_error(code="AccessDenied", message="Access denied"):
    """Helper to create a ClientError for mocking."""
    error_response = {"Error": {"Code": code, "Message": message}}
    return ClientError(error_response, "TestOperation")


def test_check_access_keys_stale_key():
    """A single active key older than 90 days should produce a stale-key issue."""
    stale_date = FIXED_NOW - timedelta(days=100)
    mock_iam = MagicMock()
    mock_iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "Status": "Active",
                "CreateDate": stale_date,
            }
        ]
    }
    mock_iam.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {"ServiceName": "s3"}
        # No LastUsedDate — never used
    }

    # Patch NOW so age_days is computed relative to a fixed point
    with patch.object(iam, "NOW", FIXED_NOW):
        issues, keys = iam.check_access_keys(mock_iam, "alice")

    stale_issues = [i for i in issues if "days old" in i]
    assert len(stale_issues) >= 1, f"Expected stale-key issue, got: {issues}"
    assert keys[0]["age_days"] == 100


def test_check_access_keys_unused_key():
    """An active key with last-used date >90 days ago should produce an unused-key issue."""
    create_date = FIXED_NOW - timedelta(days=10)
    last_used_date = FIXED_NOW - timedelta(days=100)
    mock_iam = MagicMock()
    mock_iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "Status": "Active",
                "CreateDate": create_date,
            }
        ]
    }
    mock_iam.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {
            "LastUsedDate": last_used_date,
            "ServiceName": "iam",
        }
    }

    with patch.object(iam, "NOW", FIXED_NOW):
        issues, keys = iam.check_access_keys(mock_iam, "alice")

    unused_issues = [i for i in issues if "unused for" in i]
    assert len(unused_issues) >= 1, f"Expected unused-key issue, got: {issues}"
    assert keys[0]["days_since_used"] == 100


def test_check_access_keys_multiple_active():
    """Two active keys should produce a multiple-active-keys issue."""
    create_date = FIXED_NOW - timedelta(days=5)
    mock_iam = MagicMock()
    mock_iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {"AccessKeyId": "AKIA1111", "Status": "Active", "CreateDate": create_date},
            {"AccessKeyId": "AKIA2222", "Status": "Active", "CreateDate": create_date},
        ]
    }
    mock_iam.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {"ServiceName": "iam"}
    }

    with patch.object(iam, "NOW", FIXED_NOW):
        issues, keys = iam.check_access_keys(mock_iam, "alice")

    multi_issues = [i for i in issues if "Multiple active" in i]
    assert len(multi_issues) == 1, f"Expected exactly one multiple-active-keys issue, got: {issues}"
    assert len(keys) == 2


# ── check_permission_boundary ──────────────────────────────────────────────────

def test_check_permission_boundary_present():
    """When PermissionsBoundary is present on a user, boundary ARN should be returned."""
    mock_iam = MagicMock()
    boundary_arn = "arn:aws:iam::123456789012:policy/MyBoundary"
    mock_iam.get_user.return_value = {
        "User": {
            "UserName": "alice",
            "PermissionsBoundary": {
                "PermissionsBoundaryArn": boundary_arn,
            },
        }
    }

    result = iam.check_permission_boundary(mock_iam, "user", "alice")
    assert result == boundary_arn


def test_check_permission_boundary_absent():
    """When PermissionsBoundary is absent, None should be returned."""
    mock_iam = MagicMock()
    mock_iam.get_user.return_value = {
        "User": {"UserName": "alice"}
    }

    result = iam.check_permission_boundary(mock_iam, "user", "alice")
    assert result is None


def test_check_permission_boundary_api_error():
    """ClientError from get_user/get_role should be handled gracefully (return None)."""
    mock_iam = MagicMock()
    mock_iam.get_user.side_effect = _make_client_error("NoSuchEntity", "User does not exist")

    result = iam.check_permission_boundary(mock_iam, "user", "nonexistent")
    assert result is None


def test_check_permission_boundary_role_present():
    """When PermissionsBoundary is present on a role, boundary ARN should be returned."""
    mock_iam = MagicMock()
    boundary_arn = "arn:aws:iam::123456789012:policy/RoleBoundary"
    mock_iam.get_role.return_value = {
        "Role": {
            "RoleName": "my-role",
            "PermissionsBoundary": {
                "PermissionsBoundaryArn": boundary_arn,
            },
        }
    }

    result = iam.check_permission_boundary(mock_iam, "role", "my-role")
    assert result == boundary_arn


# ── analyse_user ───────────────────────────────────────────────────────────────

def _build_mock_iam_for_user(
    username="alice",
    attached_policies=None,
    inline_policy_names=None,
    groups=None,
    stale_key_date=None,
    has_console=True,
    mfa_devices=None,
    boundary_arn=None,
):
    """Build a MagicMock IAM client configured for analyse_user tests."""
    mock_iam = MagicMock()
    attached = attached_policies or []
    mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": attached}
    mock_iam.list_user_policies.return_value = {"PolicyNames": inline_policy_names or []}
    mock_iam.list_groups_for_user.return_value = {"Groups": groups or []}
    mock_iam.list_mfa_devices.return_value = {"MFADevices": mfa_devices or []}

    if has_console:
        mock_iam.get_login_profile.return_value = {"LoginProfile": {"UserName": username}}
    else:
        mock_iam.get_login_profile.side_effect = _make_client_error("NoSuchEntity", "No login profile")

    # Access keys — default to no keys
    if stale_key_date is not None:
        mock_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIASTALE", "Status": "Active", "CreateDate": stale_key_date}
            ]
        }
        mock_iam.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {"ServiceName": "iam"}
        }
    else:
        mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": []}

    # Permission boundary
    mock_iam.get_user.return_value = {
        "User": {
            "UserName": username,
            **({"PermissionsBoundary": {"PermissionsBoundaryArn": boundary_arn}} if boundary_arn else {}),
        }
    }

    # Admin policy document for AdministratorAccess
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }
        }
    }

    return mock_iam


def test_analyse_user_admin_stale_keys_no_mfa():
    """User with AdministratorAccess, stale key, and no MFA should be HIGH or CRITICAL risk."""
    stale_date = FIXED_NOW - timedelta(days=100)
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"

    mock_iam = _build_mock_iam_for_user(
        username="alice",
        attached_policies=[{"PolicyName": "AdministratorAccess", "PolicyArn": admin_arn}],
        stale_key_date=stale_date,
        has_console=True,
        mfa_devices=[],  # no MFA
    )

    user = {
        "UserName": "alice",
        "Arn": "arn:aws:iam::123456789012:user/alice",
    }

    with patch.object(iam, "NOW", FIXED_NOW):
        result = iam.analyse_user(mock_iam, user, set())

    assert result["type"] == "user"
    assert result["name"] == "alice"
    assert len(result["high_risk_actions"]) > 0, "Expected high_risk_actions to be non-empty"
    assert result["risk_level"] in ("HIGH", "CRITICAL"), (
        f"Expected HIGH or CRITICAL, got {result['risk_level']}"
    )
    assert result["has_admin_policy"] is True
    assert result["mfa_warning"] is True  # console access + no MFA


def test_analyse_user_clean():
    """User with no policies and no access keys should be LOW risk with score 0."""
    mock_iam = _build_mock_iam_for_user(
        username="bob",
        attached_policies=[],
        inline_policy_names=[],
        groups=[],
        stale_key_date=None,
        has_console=False,
        mfa_devices=[],
    )

    user = {
        "UserName": "bob",
        "Arn": "arn:aws:iam::123456789012:user/bob",
    }

    result = iam.analyse_user(mock_iam, user, set())

    assert result["risk_level"] == "LOW"
    assert result["severity_score"] == 0
    assert result["high_risk_actions"] == []
    assert result["access_key_issues"] == []


# ── analyse_role ───────────────────────────────────────────────────────────────

def test_analyse_role_cross_account_trust():
    """Role with cross-account trust principal should have cross_account_trust=True."""
    mock_iam = MagicMock()
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.get_role.return_value = {"Role": {"RoleName": "CrossAccountRole"}}

    trust_doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:AssumeRole",
            }
        ]
    }
    role = {
        "RoleName": "CrossAccountRole",
        "Arn": "arn:aws:iam::123456789012:role/CrossAccountRole",
        "AssumeRolePolicyDocument": trust_doc,
    }

    result = iam.analyse_role(mock_iam, role, set())

    assert result["cross_account_trust"] is True
    assert "arn:aws:iam::999999999999:root" in result["trust_principals"]
    # Cross-account trust adds 1 point to score; no policies means score=1 -> LOW (threshold for MEDIUM is 2)
    assert result["risk_level"] == "LOW"


def test_analyse_role_with_boundary():
    """Role with a permission boundary should have permission_boundary set."""
    boundary_arn = "arn:aws:iam::123456789012:policy/RoleBoundary"
    mock_iam = MagicMock()
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.get_role.return_value = {
        "Role": {
            "RoleName": "BoundedRole",
            "PermissionsBoundary": {"PermissionsBoundaryArn": boundary_arn},
        }
    }

    role = {
        "RoleName": "BoundedRole",
        "Arn": "arn:aws:iam::123456789012:role/BoundedRole",
        "AssumeRolePolicyDocument": {"Statement": []},
    }

    result = iam.analyse_role(mock_iam, role, set())

    assert result["permission_boundary"] == boundary_arn
    # No policies attached, so score is 0 regardless of boundary -> LOW
    assert result["risk_level"] == "LOW"


# ── analyse_group ──────────────────────────────────────────────────────────────

def test_analyse_group_admin_policy():
    """Group with AdministratorAccess should have high_risk_actions and HIGH/CRITICAL risk."""
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    mock_iam = MagicMock()
    mock_iam.list_attached_group_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": admin_arn}]
    }
    mock_iam.list_group_policies.return_value = {"PolicyNames": []}
    mock_iam.get_group.return_value = {"Users": []}
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }
        }
    }

    group = {
        "GroupName": "AdminGroup",
        "Arn": "arn:aws:iam::123456789012:group/AdminGroup",
    }

    result = iam.analyse_group(mock_iam, group, set())

    assert result["type"] == "group"
    assert len(result["high_risk_actions"]) > 0, "Expected high_risk_actions to be non-empty"
    assert result["has_admin_policy"] is True
    assert result["risk_level"] in ("HIGH", "CRITICAL")


def test_analyse_group_clean():
    """Group with no policies should have empty high_risk_actions and LOW risk."""
    mock_iam = MagicMock()
    mock_iam.list_attached_group_policies.return_value = {"AttachedPolicies": []}
    mock_iam.list_group_policies.return_value = {"PolicyNames": []}
    mock_iam.get_group.return_value = {"Users": []}

    group = {
        "GroupName": "EmptyGroup",
        "Arn": "arn:aws:iam::123456789012:group/EmptyGroup",
    }

    result = iam.analyse_group(mock_iam, group, set())

    assert result["high_risk_actions"] == []
    assert result["risk_level"] == "LOW"
    assert result["severity_score"] == 0


# ── get_effective_scps ─────────────────────────────────────────────────────────

def test_get_effective_scps_with_deny():
    """SCP with a Deny statement should return the denied actions as a set."""
    policy_doc = json.dumps({
        "Statement": [
            {"Effect": "Deny", "Action": ["s3:DeleteObject", "s3:DeleteBucket"]}
        ]
    })

    mock_org = MagicMock()
    # Simulate paginator behaviour
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"Policies": [{"Id": "p-abc123", "Name": "DenyS3Delete"}]}
    ]
    mock_org.get_paginator.return_value = mock_paginator
    mock_org.describe_policy.return_value = {
        "Policy": {"Content": policy_doc}
    }

    denied = iam.get_effective_scps(mock_org, "123456789012")

    assert "s3:deleteobject" in denied
    assert "s3:deletebucket" in denied


def test_get_effective_scps_no_org_access():
    """AccessDeniedException from list_policies_for_target should result in an empty set."""
    mock_org = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.side_effect = _make_client_error(
        "AccessDeniedException", "User is not authorized to access this resource"
    )
    mock_org.get_paginator.return_value = mock_paginator

    denied = iam.get_effective_scps(mock_org, "123456789012")

    assert denied == set()


# ── write_json / write_csv ─────────────────────────────────────────────────────


def test_write_json_creates_file_with_600_perms(tmp_path):
    """write_json should create a file with 0o600 permissions."""
    report = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "account_id": "123456789012",
        "scp_analysis": False,
        "summary": {
            "total_principals": 1,
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "users_without_mfa": 0,
            "stale_keys": 0,
            "cross_account_roles": 0,
            "admin_policy_holders": 1,
        },
        "findings": [
            {
                "type": "user",
                "name": "alice",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "risk_level": "HIGH",
                "severity_score": 5,
            }
        ],
    }
    out_path = str(tmp_path / "report.json")
    iam.write_json(report, out_path)

    assert os.path.exists(out_path)
    file_mode = stat.S_IMODE(os.stat(out_path).st_mode)
    assert file_mode == 0o600, f"Expected 0o600, got {oct(file_mode)}"
    with open(out_path) as f:
        loaded = json.load(f)
    assert loaded["account_id"] == "123456789012"


def test_write_csv_creates_file_with_600_perms(tmp_path):
    """write_csv should create a file with 0o600 permissions."""
    findings = [
        {
            "type": "user",
            "name": "alice",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "risk_level": "HIGH",
            "severity_score": 5,
            "has_admin_policy": True,
            "console_access": False,
            "mfa_enabled": False,
            "mfa_warning": False,
            "permission_boundary": None,
            "cross_account_trust": False,
            "external_id_required": False,
            "high_risk_actions": ["*"],
            "privilege_escalation_paths": [],
            "access_key_issues": [],
            "total_actions_count": 1,
            "scp_restrictions_applied": False,
            "groups": [],
            "members": [],
            "trust_principals": [],
        }
    ]
    out_path = str(tmp_path / "report.csv")
    iam.write_csv(findings, out_path)

    assert os.path.exists(out_path)
    file_mode = stat.S_IMODE(os.stat(out_path).st_mode)
    assert file_mode == 0o600, f"Expected 0o600, got {oct(file_mode)}"
    with open(out_path) as f:
        content = f.read()
    assert "alice" in content
    assert "HIGH" in content
