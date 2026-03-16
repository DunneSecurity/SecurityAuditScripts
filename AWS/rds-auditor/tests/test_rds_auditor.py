"""Tests for rds_auditor.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import csv as csv_module
import json as json_module
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
import rds_auditor as rds


def _client_error(code):
    error = {"Error": {"Code": code, "Message": ""}}
    return ClientError(error, "test")


# ── is_publicly_accessible ────────────────────────────────────────────────────

def test_is_publicly_accessible_true():
    assert rds.is_publicly_accessible({"PubliclyAccessible": True}) is True

def test_is_publicly_accessible_false():
    assert rds.is_publicly_accessible({"PubliclyAccessible": False}) is False

def test_is_publicly_accessible_missing_key():
    assert rds.is_publicly_accessible({}) is False


# ── check_encryption ──────────────────────────────────────────────────────────

def test_check_encryption_enabled():
    assert rds.check_encryption({"StorageEncrypted": True}) is True

def test_check_encryption_disabled():
    assert rds.check_encryption({"StorageEncrypted": False}) is False

def test_check_encryption_missing():
    assert rds.check_encryption({}) is False


# ── check_backup_retention ────────────────────────────────────────────────────

def test_check_backup_retention_sufficient():
    ok, days = rds.check_backup_retention({"BackupRetentionPeriod": 7})
    assert ok is True
    assert days == 7

def test_check_backup_retention_zero():
    ok, days = rds.check_backup_retention({"BackupRetentionPeriod": 0})
    assert ok is False
    assert days == 0

def test_check_backup_retention_low():
    ok, days = rds.check_backup_retention({"BackupRetentionPeriod": 3})
    assert ok is False
    assert days == 3

def test_check_backup_retention_missing():
    ok, days = rds.check_backup_retention({})
    assert ok is False


# ── check_deletion_protection ─────────────────────────────────────────────────

def test_check_deletion_protection_enabled():
    assert rds.check_deletion_protection({"DeletionProtection": True}) is True

def test_check_deletion_protection_disabled():
    assert rds.check_deletion_protection({"DeletionProtection": False}) is False


# ── check_iam_auth ────────────────────────────────────────────────────────────

def test_check_iam_auth_enabled():
    assert rds.check_iam_auth({"IAMDatabaseAuthenticationEnabled": True}) is True

def test_check_iam_auth_disabled():
    assert rds.check_iam_auth({"IAMDatabaseAuthenticationEnabled": False}) is False


# ── check_multi_az ────────────────────────────────────────────────────────────

def test_check_multi_az_true():
    assert rds.check_multi_az({"MultiAZ": True}) is True

def test_check_multi_az_false():
    assert rds.check_multi_az({"MultiAZ": False}) is False


# ── check_auto_minor_version_upgrade ──────────────────────────────────────────

def test_check_auto_minor_version_upgrade_true():
    assert rds.check_auto_minor_version_upgrade({"AutoMinorVersionUpgrade": True}) is True

def test_check_auto_minor_version_upgrade_false():
    assert rds.check_auto_minor_version_upgrade({"AutoMinorVersionUpgrade": False}) is False


# ── check_public_snapshots ────────────────────────────────────────────────────

def test_check_public_snapshots_none():
    rds_client = MagicMock()
    rds_client.describe_db_snapshots.return_value = {
        "DBSnapshots": [
            {"DBSnapshotIdentifier": "snap-1", "SnapshotType": "manual"},
        ]
    }
    rds_client.describe_db_snapshot_attributes.return_value = {
        "DBSnapshotAttributesResult": {
            "DBSnapshotAttributes": [{"AttributeName": "restore", "AttributeValues": []}]
        }
    }
    result = rds.check_public_snapshots(rds_client, "db-prod")
    assert result == []

def test_check_public_snapshots_public_found():
    rds_client = MagicMock()
    rds_client.describe_db_snapshots.return_value = {
        "DBSnapshots": [
            {"DBSnapshotIdentifier": "snap-public", "SnapshotType": "manual"}
        ]
    }
    rds_client.describe_db_snapshot_attributes.return_value = {
        "DBSnapshotAttributesResult": {
            "DBSnapshotAttributes": [
                {"AttributeName": "restore", "AttributeValues": ["all"]}
            ]
        }
    }
    result = rds.check_public_snapshots(rds_client, "db-prod")
    assert "snap-public" in result


# ── calculate_score ───────────────────────────────────────────────────────────

def test_calculate_score_all_clean():
    score, level = rds.calculate_score(
        publicly_accessible=False, not_encrypted=False,
        backup_insufficient=False, no_deletion_protection=False,
        public_snapshots=[], no_iam_auth=False,
        no_auto_minor_upgrade=False, no_multi_az=False,
    )
    assert score == 0
    assert level == "LOW"

def test_calculate_score_publicly_accessible_raises():
    score, level = rds.calculate_score(
        publicly_accessible=True, not_encrypted=False,
        backup_insufficient=False, no_deletion_protection=False,
        public_snapshots=[], no_iam_auth=False,
        no_auto_minor_upgrade=False, no_multi_az=False,
    )
    assert score >= 4

def test_calculate_score_public_plus_unencrypted_critical():
    score, level = rds.calculate_score(
        publicly_accessible=True, not_encrypted=True,
        backup_insufficient=True, no_deletion_protection=True,
        public_snapshots=["snap-1"], no_iam_auth=False,
        no_auto_minor_upgrade=False, no_multi_az=False,
    )
    assert score >= 8
    assert level == "CRITICAL"

def test_calculate_score_capped_at_10():
    score, level = rds.calculate_score(
        publicly_accessible=True, not_encrypted=True,
        backup_insufficient=True, no_deletion_protection=True,
        public_snapshots=["snap-1", "snap-2"], no_iam_auth=True,
        no_auto_minor_upgrade=True, no_multi_az=True,
    )
    assert score <= 10


# ── analyse_instance ──────────────────────────────────────────────────────────

GOOD_DB = {
    "DBInstanceIdentifier": "prod-mysql",
    "DBInstanceClass": "db.t3.medium",
    "Engine": "mysql",
    "EngineVersion": "8.0.32",
    "DBInstanceStatus": "available",
    "PubliclyAccessible": False,
    "StorageEncrypted": True,
    "BackupRetentionPeriod": 7,
    "DeletionProtection": True,
    "IAMDatabaseAuthenticationEnabled": True,
    "AutoMinorVersionUpgrade": True,
    "MultiAZ": True,
    "DBParameterGroups": [{"DBParameterGroupName": "custom-mysql8", "ParameterApplyStatus": "in-sync"}],
    "DBSubnetGroup": {"DBSubnetGroupName": "private-subnet-group", "VpcId": "vpc-abc"},
    "Endpoint": {"Address": "prod-mysql.abc.eu-west-1.rds.amazonaws.com", "Port": 3306},
    "AllocatedStorage": 100,
    "KmsKeyId": "arn:aws:kms:eu-west-1:123:key/abc",
    "PreferredBackupWindow": "02:00-03:00",
}


def _make_rds_client_clean():
    mock = MagicMock()
    mock.describe_db_snapshots.return_value = {"DBSnapshots": []}
    return mock


def test_analyse_instance_fully_configured_low_risk():
    result = rds.analyse_instance(_make_rds_client_clean(), GOOD_DB.copy(), region="eu-west-1")
    assert result["risk_level"] == "LOW"
    assert result["publicly_accessible"] is False
    assert result["encrypted"] is True
    assert result["deletion_protection"] is True
    assert "remediations" in result
    assert isinstance(result["remediations"], list)

def test_analyse_instance_publicly_accessible_flagged():
    db = GOOD_DB.copy()
    db["PubliclyAccessible"] = True
    result = rds.analyse_instance(_make_rds_client_clean(), db, region="eu-west-1")
    assert result["publicly_accessible"] is True
    assert any("publicly accessible" in f.lower() for f in result["flags"])

def test_analyse_instance_not_encrypted_flagged():
    db = GOOD_DB.copy()
    db["StorageEncrypted"] = False
    db["KmsKeyId"] = None
    result = rds.analyse_instance(_make_rds_client_clean(), db, region="eu-west-1")
    assert result["encrypted"] is False
    assert any("encrypt" in f.lower() for f in result["flags"])

def test_analyse_instance_flagged_has_paired_remediations():
    """Every non-✅ flag must have a matching remediation."""
    db = GOOD_DB.copy()
    db["PubliclyAccessible"] = True
    db["StorageEncrypted"] = False
    db["BackupRetentionPeriod"] = 0
    db["DeletionProtection"] = False
    result = rds.analyse_instance(_make_rds_client_clean(), db, region="eu-west-1")
    warning_flags = [f for f in result["flags"] if not f.startswith("✅")]
    assert len(result["remediations"]) == len(warning_flags)
    assert all(len(r) > 0 for r in result["remediations"])

def test_analyse_instance_default_param_group_flagged():
    db = GOOD_DB.copy()
    db["DBParameterGroups"] = [
        {"DBParameterGroupName": "default.mysql8.0", "ParameterApplyStatus": "in-sync"}
    ]
    result = rds.analyse_instance(_make_rds_client_clean(), db, region="eu-west-1")
    assert any("default parameter group" in f.lower() for f in result["flags"])

def test_analyse_instance_backup_disabled_flagged():
    db = GOOD_DB.copy()
    db["BackupRetentionPeriod"] = 0
    result = rds.analyse_instance(_make_rds_client_clean(), db, region="eu-west-1")
    assert any("backup" in f.lower() for f in result["flags"])


# ── Writers ───────────────────────────────────────────────────────────────────

SAMPLE_FINDING = {
    "db_identifier": "prod-mysql",
    "db_class": "db.t3.medium",
    "engine": "mysql",
    "engine_version": "8.0.32",
    "status": "available",
    "region": "eu-west-1",
    "vpc_id": "vpc-abc",
    "endpoint": "prod-mysql.abc.eu-west-1.rds.amazonaws.com",
    "port": 3306,
    "publicly_accessible": False,
    "encrypted": True,
    "kms_key": "arn:aws:kms:eu-west-1:123:key/abc",
    "backup_retention_days": 7,
    "deletion_protection": True,
    "iam_auth": True,
    "auto_minor_upgrade": True,
    "multi_az": True,
    "public_snapshots": [],
    "using_default_parameter_group": False,
    "severity_score": 0,
    "risk_level": "LOW",
    "flags": ["✅ Not publicly accessible", "✅ Storage encrypted (KMS)"],
    "remediations": [],
}


def test_write_json_creates_file_with_600_perms(tmp_path):
    report = {"generated_at": "2026-01-01", "findings": [SAMPLE_FINDING]}
    out = str(tmp_path / "test.json")
    rds.write_json(report, out)
    assert (tmp_path / "test.json").exists()
    assert (tmp_path / "test.json").stat().st_mode & 0o777 == 0o600

def test_write_csv_creates_file_with_600_perms(tmp_path):
    out = str(tmp_path / "test.csv")
    rds.write_csv([SAMPLE_FINDING], out)
    assert (tmp_path / "test.csv").exists()
    assert (tmp_path / "test.csv").stat().st_mode & 0o777 == 0o600

def test_write_csv_empty_no_file(tmp_path):
    out = str(tmp_path / "empty.csv")
    rds.write_csv([], out)
    assert not (tmp_path / "empty.csv").exists()

def test_write_csv_includes_remediations_column(tmp_path):
    out = str(tmp_path / "test.csv")
    rds.write_csv([SAMPLE_FINDING], out)
    with open(out) as f:
        reader = csv_module.DictReader(f)
        assert "remediations" in reader.fieldnames

def test_write_html_creates_file_with_600_perms(tmp_path):
    report = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "account_id": "123456789012",
        "findings": [],
        "summary": {
            "total_instances": 0, "critical": 0, "high": 0,
            "medium": 0, "low": 0, "public_instances": 0,
            "unencrypted_instances": 0, "no_backups": 0,
        },
    }
    out = str(tmp_path / "test.html")
    rds.write_html(report, out)
    assert (tmp_path / "test.html").exists()
    assert (tmp_path / "test.html").stat().st_mode & 0o777 == 0o600
