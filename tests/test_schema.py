"""Unit tests for schema.py — validate_finding() normalisation and rejection."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from schema import validate_finding, VALID_RISK_LEVELS


class TestValidateFindingCanonical(unittest.TestCase):

    def test_canonical_finding_returned_unchanged(self):
        """Finding with all canonical fields passes through untouched."""
        f = {
            "risk_level": "HIGH",
            "remediation": "Fix it",
            "flag": "Port open",
            "cis_control": "CIS 9",
        }
        result = validate_finding(dict(f))
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertEqual(result["remediation"], "Fix it")
        self.assertEqual(result["flag"], "Port open")

    def test_all_valid_risk_levels_accepted(self):
        for level in VALID_RISK_LEVELS:
            result = validate_finding({"risk_level": level})
            self.assertEqual(result["risk_level"], level)


class TestValidateFindingAliases(unittest.TestCase):

    def test_severity_mapped_to_risk_level(self):
        """Legacy 'severity' field is copied to 'risk_level'."""
        f = {"severity": "CRITICAL", "remediation": "Fix now"}
        result = validate_finding(f)
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertEqual(result["severity"], "CRITICAL")  # original preserved

    def test_recommendation_mapped_to_remediation(self):
        """Legacy 'recommendation' field is copied to 'remediation'."""
        f = {"risk_level": "LOW", "recommendation": "Check config"}
        result = validate_finding(f)
        self.assertEqual(result["remediation"], "Check config")
        self.assertEqual(result["recommendation"], "Check config")  # original preserved

    def test_detail_mapped_to_flag(self):
        """Legacy 'detail' field is copied to 'flag' when flag absent."""
        f = {"risk_level": "MEDIUM", "detail": "sshd version 7.2"}
        result = validate_finding(f)
        self.assertEqual(result["flag"], "sshd version 7.2")

    def test_existing_flag_not_overwritten_by_detail(self):
        """If 'flag' already present, 'detail' does not overwrite it."""
        f = {"risk_level": "MEDIUM", "flag": "explicit flag", "detail": "ignored detail"}
        result = validate_finding(f)
        self.assertEqual(result["flag"], "explicit flag")


class TestValidateFindingRejection(unittest.TestCase):

    def test_raises_value_error_when_no_risk_level_or_severity(self):
        with self.assertRaises(ValueError) as ctx:
            validate_finding({"finding_type": "PortOpen", "remediation": "Close it"})
        self.assertIn("risk_level", str(ctx.exception))

    def test_raises_value_error_on_invalid_risk_level(self):
        with self.assertRaises(ValueError) as ctx:
            validate_finding({"risk_level": "SEVERE"})
        self.assertIn("SEVERE", str(ctx.exception))

    def test_raises_value_error_on_lowercase_risk_level(self):
        with self.assertRaises(ValueError):
            validate_finding({"risk_level": "high"})


if __name__ == "__main__":
    unittest.main()
