"""Tests for sg_auditor.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import stat
import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
import sg_auditor as sg


def _client_error(code):
    error = {"Error": {"Code": code, "Message": ""}}
    return ClientError(error, "test")


# ── is_open_to_world ───────────────────────────────────────────────────────────

def test_is_open_to_world_ipv4():
    rule = {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}
    assert sg.is_open_to_world(rule) is True


def test_is_open_to_world_ipv6():
    rule = {"IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
    assert sg.is_open_to_world(rule) is True


def test_is_open_to_world_restricted():
    rule = {"IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": []}
    assert sg.is_open_to_world(rule) is False


def test_is_open_to_world_sg_reference():
    # SG-to-SG rules have no IpRanges/Ipv6Ranges — must NOT be flagged as world-open
    rule = {"UserIdGroupPairs": [{"GroupId": "sg-abc123"}], "IpRanges": [], "Ipv6Ranges": []}
    assert sg.is_open_to_world(rule) is False


# ── port_in_range ──────────────────────────────────────────────────────────────

def test_port_in_range_exact():
    assert sg.port_in_range(22, 22, 22) is True


def test_port_in_range_within():
    assert sg.port_in_range(80, 0, 65535) is True


def test_port_in_range_outside():
    assert sg.port_in_range(443, 80, 80) is False


def test_port_in_range_all_traffic():
    assert sg.port_in_range(22, -1, -1) is True


# ── analyse_rules ──────────────────────────────────────────────────────────────

def test_analyse_rules_ssh_open():
    rules = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
               "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]
    _, high_risk, _, open_ssh, _ = sg.analyse_rules(rules)
    assert open_ssh is True
    assert any("SSH" in p for p in high_risk)


def test_analyse_rules_rdp_open():
    rules = [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
               "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]
    _, high_risk, _, _, open_rdp = sg.analyse_rules(rules)
    assert open_rdp is True


def test_analyse_rules_all_traffic():
    rules = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]
    _, _, all_traffic, _, _ = sg.analyse_rules(rules)
    assert all_traffic is True


def test_analyse_rules_restricted_no_findings():
    rules = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
               "IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": []}]
    open_ports, high_risk, all_traffic, open_ssh, open_rdp = sg.analyse_rules(rules)
    assert open_ssh is False
    assert high_risk == []


# ── high risk ports coverage ───────────────────────────────────────────────────

def test_smtp_in_high_risk_ports():
    assert 25 in sg.HIGH_RISK_PORTS


def test_ldap_in_high_risk_ports():
    assert 389 in sg.HIGH_RISK_PORTS


def test_ldaps_in_high_risk_ports():
    assert 636 in sg.HIGH_RISK_PORTS


def test_nfs_in_high_risk_ports():
    assert 111 in sg.HIGH_RISK_PORTS


# ── calculate_score ────────────────────────────────────────────────────────────

def test_score_all_traffic_open():
    score, level = sg.calculate_score(False, False, True, [], False, False, 1)
    assert score >= 6


def test_score_ssh_open():
    score, level = sg.calculate_score(True, False, False, [], False, False, 1)
    assert score >= 4


def test_score_clean():
    score, level = sg.calculate_score(False, False, False, [], False, False, 0)
    assert score == 0


# ── analyse_sg integration tests ──────────────────────────────────────────────

def _make_sg_dict(group_id="sg-123", group_name="test", vpc_id="vpc-123",
                  description="test", owner_id="123456789",
                  ip_permissions=None, ip_permissions_egress=None, tags=None):
    """Helper to build a security group dict as returned by describe_security_groups."""
    return {
        "GroupId": group_id,
        "GroupName": group_name,
        "VpcId": vpc_id,
        "Description": description,
        "OwnerId": owner_id,
        "IpPermissions": ip_permissions or [],
        "IpPermissionsEgress": ip_permissions_egress or [],
        "Tags": tags or [],
    }


def _all_traffic_rule():
    return {
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [],
    }


def _ssh_rule():
    return {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [],
    }


def _private_ssh_rule():
    return {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
        "Ipv6Ranges": [],
    }


def test_analyse_sg_all_traffic_open():
    ec2 = MagicMock()
    # Unrestricted egress rule to push score above 8 (all_traffic=6 + egress=1 + default+open=2 = 9 → CRITICAL)
    unrestricted_egress_rule = {
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [],
    }
    sg_dict = _make_sg_dict(
        group_name="default",
        group_id="sg-123",
        ip_permissions=[_all_traffic_rule()],
        ip_permissions_egress=[unrestricted_egress_rule],
    )
    # attached_resources: sg-123 is attached
    result = sg.analyse_sg(ec2, sg_dict, "us-east-1", {"sg-123"})

    assert result["all_traffic_open"] is True
    assert result["risk_level"] == "CRITICAL"
    # Flags should contain the all-traffic flag
    flag_texts = " ".join(result["flags"])
    assert "All inbound traffic" in flag_texts


def test_analyse_sg_ssh_open():
    ec2 = MagicMock()
    sg_dict = _make_sg_dict(ip_permissions=[_ssh_rule()])
    result = sg.analyse_sg(ec2, sg_dict, "us-east-1", {"sg-123"})

    assert result["open_ssh"] is True
    # Bug 5 fix: only ONE SSH-related flag, not double-flagged
    ssh_flags = [f for f in result["flags"] if "SSH" in f]
    assert len(ssh_flags) == 1


def test_analyse_sg_clean():
    ec2 = MagicMock()
    sg_dict = _make_sg_dict(ip_permissions=[_private_ssh_rule()])
    result = sg.analyse_sg(ec2, sg_dict, "us-east-1", {"sg-123"})

    assert result["risk_level"] == "LOW"
    # No warning or critical flags
    bad_flags = [f for f in result["flags"] if f.startswith(("❌", "⚠️"))]
    assert bad_flags == []


def test_analyse_sg_default_with_rules():
    ec2 = MagicMock()
    # Use a port range (not a single high-risk port) so open_ports is non-empty,
    # which triggers the default SG warning in analyse_sg.
    port_range_rule = {
        "IpProtocol": "tcp",
        "FromPort": 8000,
        "ToPort": 9000,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [],
    }
    sg_dict = _make_sg_dict(
        group_name="default",
        group_id="sg-default",
        ip_permissions=[port_range_rule],
    )
    result = sg.analyse_sg(ec2, sg_dict, "us-east-1", {"sg-default"})

    flag_texts = " ".join(result["flags"])
    assert "Default security group" in flag_texts


# ── check_egress unit tests ────────────────────────────────────────────────────

def test_check_egress_unrestricted():
    rules = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]
    assert sg.check_egress(rules) is True


def test_check_egress_restricted():
    rules = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
               "IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": []}]
    assert sg.check_egress(rules) is False


# ── get_attached_resources unit test ──────────────────────────────────────────

def test_get_attached_resources():
    ec2 = MagicMock()
    # Build two fake ENIs each belonging to different security groups
    page = {
        "NetworkInterfaces": [
            {"Groups": [{"GroupId": "sg-aaa"}, {"GroupId": "sg-bbb"}]},
            {"Groups": [{"GroupId": "sg-ccc"}]},
        ]
    }
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [page]
    ec2.get_paginator.return_value = mock_paginator

    result = sg.get_attached_resources(ec2)

    assert isinstance(result, set)
    assert "sg-aaa" in result
    assert "sg-bbb" in result
    assert "sg-ccc" in result
    ec2.get_paginator.assert_called_once_with("describe_network_interfaces")


# ── write_json / write_csv file permission tests ───────────────────────────────

def test_write_json_creates_file_with_600_perms(tmp_path):
    sample_report = {"generated_at": "2026-01-01", "findings": [{"group_id": "sg-test"}]}
    out_path = str(tmp_path / "test.json")
    sg.write_json(sample_report, out_path)
    assert (tmp_path / "test.json").exists()
    mode = (tmp_path / "test.json").stat().st_mode & 0o777
    assert mode == 0o600


def test_write_csv_creates_file_with_600_perms(tmp_path):
    sample_findings = [{
        "group_id": "sg-test",
        "group_name": "test",
        "vpc_id": "vpc-123",
        "region": "us-east-1",
        "description": "test group",
        "risk_level": "LOW",
        "severity_score": 0,
        "is_default": False,
        "is_attached": True,
        "all_traffic_open": False,
        "open_ssh": False,
        "open_rdp": False,
        "high_risk_ports_open": [],
        "open_port_findings": [],
        "unrestricted_egress": False,
        "ingress_rule_count": 0,
        "egress_rule_count": 0,
        "flags": [],
    }]
    out_path = str(tmp_path / "test.csv")
    sg.write_csv(sample_findings, out_path)
    assert (tmp_path / "test.csv").exists()
    mode = (tmp_path / "test.csv").stat().st_mode & 0o777
    assert mode == 0o600
