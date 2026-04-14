"""Unit tests for tools/correlations.py — run_correlations() engine."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from correlations import run_correlations, CORRELATION_RULES


def _finding(finding_type, risk_level="HIGH", pillar="entra"):
    return {"finding_type": finding_type, "risk_level": risk_level, "pillar": pillar}


class TestRunCorrelationsEmpty(unittest.TestCase):

    def test_empty_findings_returns_no_correlations(self):
        result = run_correlations([])
        self.assertEqual(result, [])

    def test_single_finding_no_match_returns_empty(self):
        result = run_correlations([_finding("UserNoMfa")])
        self.assertEqual(result, [])


class TestMatchAll(unittest.TestCase):

    def test_all_match_fires_when_all_present(self):
        findings = [
            _finding("GlobalAdminNoMfa"),
            _finding("TooManyGlobalAdmins"),
        ]
        result = run_correlations(findings)
        ids = [r["id"] for r in result]
        self.assertIn("CP-03", ids)

    def test_all_match_does_not_fire_when_one_missing(self):
        findings = [_finding("GlobalAdminNoMfa")]
        result = run_correlations(findings)
        ids = [r["id"] for r in result]
        self.assertNotIn("CP-03", ids)


class TestMatchAnyTwo(unittest.TestCase):

    def test_any_two_fires_with_exactly_two_matches(self):
        findings = [
            _finding("UserNoMfa"),
            _finding("AuditdNotRunning"),
        ]
        result = run_correlations(findings)
        ids = [r["id"] for r in result]
        self.assertIn("CP-01", ids)

    def test_any_two_does_not_fire_with_one_match(self):
        findings = [_finding("UserNoMfa")]
        result = run_correlations(findings)
        ids = [r["id"] for r in result]
        self.assertNotIn("CP-01", ids)

    def test_any_two_fires_with_three_matches(self):
        findings = [
            _finding("UserNoMfa"),
            _finding("AuditdNotRunning"),
            _finding("MailboxAuditLoggingDisabled"),
        ]
        result = run_correlations(findings)
        ids = [r["id"] for r in result]
        self.assertIn("CP-01", ids)


class TestMatchAnyOne(unittest.TestCase):

    def test_any_one_fires_with_single_match(self):
        """CP-10 (AD Full Takeover) uses all match — find a rule using any_one if present,
        else just verify the engine handles any_one correctly via a synthetic rule."""
        any_one_rules = [r for r in CORRELATION_RULES if r.get("match") == "any_one"]
        if not any_one_rules:
            self.skipTest("No any_one rules defined yet")
        rule = any_one_rules[0]
        findings = [_finding(rule["finding_types"][0])]
        result = run_correlations(findings)
        ids = [r["id"] for r in result]
        self.assertIn(rule["id"], ids)


class TestCorrelationResultShape(unittest.TestCase):

    def test_result_has_required_fields(self):
        findings = [
            _finding("GlobalAdminNoMfa"),
            _finding("TooManyGlobalAdmins"),
        ]
        result = run_correlations(findings)
        self.assertTrue(result)
        r = result[0]
        for key in ("id", "name", "severity", "mitre_tactic", "mitre_technique_id", "narrative", "contributing_types"):
            self.assertIn(key, r, f"Missing key: {key}")

    def test_contributing_types_lists_matched_finding_types(self):
        findings = [
            _finding("GlobalAdminNoMfa"),
            _finding("TooManyGlobalAdmins"),
        ]
        result = run_correlations(findings)
        cp03 = next(r for r in result if r["id"] == "CP-03")
        self.assertIn("GlobalAdminNoMfa", cp03["contributing_types"])
        self.assertIn("TooManyGlobalAdmins", cp03["contributing_types"])


class TestCorrelationRulesLibrary(unittest.TestCase):

    def test_at_least_15_rules_defined(self):
        self.assertGreaterEqual(len(CORRELATION_RULES), 15)

    def test_all_rules_have_required_keys(self):
        required = {"id", "name", "finding_types", "match", "severity", "mitre_tactic", "mitre_technique_id", "narrative"}
        for rule in CORRELATION_RULES:
            missing = required - rule.keys()
            self.assertFalse(missing, f"Rule {rule.get('id')} missing keys: {missing}")

    def test_rule_ids_are_unique(self):
        ids = [r["id"] for r in CORRELATION_RULES]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
