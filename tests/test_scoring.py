"""Unit tests for scoring.py — grade logic, deductions, and hard-caps."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scoring import compute_overall_score


def _pillar(name, pillar_risk, critical=0, high=0, medium=0, low=0):
    """Build a minimal pillar stats dict for testing."""
    return {
        "pillar": name,
        "pillar_risk": pillar_risk,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }


class TestScoreAndGrade(unittest.TestCase):

    def test_grade_a_all_low_pillars(self):
        """All LOW pillars → score 100, grade A, no note."""
        pillars = [_pillar("s3", "LOW"), _pillar("iam", "LOW"), _pillar("sg", "LOW"),
                   _pillar("ec2", "LOW"), _pillar("rds", "LOW")]
        score, grade, note = compute_overall_score(pillars)
        self.assertEqual(score, 100)
        self.assertEqual(grade, "A")
        self.assertEqual(note, "")

    def test_empty_pillars_returns_a(self):
        score, grade, note = compute_overall_score([])
        self.assertEqual(score, 100)
        self.assertEqual(grade, "A")

    def test_critical_pillar_deducts_8_pts(self):
        pillars = [_pillar("s3", "CRITICAL", critical=1)]
        score, grade, _ = compute_overall_score(pillars)
        self.assertEqual(score, 92)

    def test_high_pillar_deducts_3_pts(self):
        pillars = [_pillar("s3", "HIGH", high=1)]
        score, grade, _ = compute_overall_score(pillars)
        self.assertEqual(score, 97)

    def test_medium_pillar_deducts_1_pt(self):
        pillars = [_pillar("s3", "MEDIUM", medium=1)]
        score, grade, _ = compute_overall_score(pillars)
        self.assertEqual(score, 99)

    def test_score_floors_at_zero(self):
        """13 CRITICAL pillars → deduction 104 pts → score 0, not negative."""
        pillars = [_pillar(f"p{i}", "CRITICAL", critical=1) for i in range(13)]
        score, grade, _ = compute_overall_score(pillars)
        self.assertEqual(score, 0)
        self.assertEqual(grade, "F")


class TestGradeBCapCritical(unittest.TestCase):

    def test_grade_b_cap_fires_with_one_critical_pillar(self):
        """Score 92 would be A, but 1 CRITICAL pillar caps at B."""
        pillars = [_pillar("s3", "CRITICAL", critical=1)]
        score, grade, note = compute_overall_score(pillars)
        self.assertEqual(grade, "B")
        self.assertIn("CRITICAL", note)

    def test_grade_a_when_no_critical_pillars(self):
        pillars = [_pillar("s3", "HIGH", high=1)]
        score, grade, _ = compute_overall_score(pillars)
        self.assertNotEqual(grade, "B")  # grade A possible (score 97)
        self.assertEqual(grade, "A")


class TestGradeCCapTwoCritical(unittest.TestCase):

    def test_grade_c_cap_fires_with_two_critical_pillars(self):
        """Score 84 would be B, but 2+ CRITICAL pillars cap at C."""
        pillars = [
            _pillar("s3", "CRITICAL", critical=1),
            _pillar("iam", "CRITICAL", critical=1),
        ]
        score, grade, note = compute_overall_score(pillars)
        self.assertEqual(grade, "C")
        self.assertIn("CRITICAL", note)

    def test_grade_c_cap_does_not_fire_with_one_critical(self):
        pillars = [_pillar("s3", "CRITICAL", critical=1)]
        _, grade, _ = compute_overall_score(pillars)
        self.assertNotEqual(grade, "C")


class TestDFloorFirewall(unittest.TestCase):

    def test_d_floor_fires_when_fw_pillar_critical(self):
        """fw CRITICAL → grade ≤ D regardless of score."""
        pillars = [
            _pillar("fw", "CRITICAL", critical=1),
            _pillar("s3", "LOW"),
        ]
        _, grade, note = compute_overall_score(pillars)
        self.assertEqual(grade, "D")
        self.assertIn("firewall", note)

    def test_d_floor_does_not_fire_for_other_critical_pillars(self):
        """Non-fw CRITICAL does not trigger D-floor."""
        pillars = [_pillar("s3", "CRITICAL", critical=1)]
        _, grade, _ = compute_overall_score(pillars)
        self.assertNotEqual(grade, "D")


class TestUnknownPillar(unittest.TestCase):

    def test_unknown_pillar_deducts_3pts(self):
        pillars = [_pillar("ssh", "UNKNOWN")]
        score, _, _ = compute_overall_score(pillars)
        self.assertEqual(score, 97)

    def test_unknown_pillar_caps_grade_at_b(self):
        """Score 97 would be A, but UNKNOWN pillar caps at B."""
        pillars = [_pillar("ssh", "UNKNOWN")]
        _, grade, note = compute_overall_score(pillars)
        self.assertEqual(grade, "B")
        self.assertIn("unverifiable", note)

    def test_unknown_pillar_does_not_override_lower_grade(self):
        """If grade is already C due to 2+ CRITICAL, UNKNOWN B-cap doesn't raise it."""
        pillars = [
            _pillar("s3", "CRITICAL", critical=1),
            _pillar("iam", "CRITICAL", critical=1),
            _pillar("ssh", "UNKNOWN"),
        ]
        _, grade, _ = compute_overall_score(pillars)
        self.assertEqual(grade, "C")


class TestCoverageGate(unittest.TestCase):

    def test_coverage_gate_suppresses_grade_at_3_or_fewer_modules(self):
        pillars = [_pillar("s3", "LOW")]
        _, grade, note = compute_overall_score(pillars, modules_scanned=3)
        self.assertEqual(grade, "?")
        self.assertIn("Insufficient", note)

    def test_coverage_gate_does_not_fire_at_4_modules(self):
        pillars = [_pillar("s3", "LOW")]
        _, grade, _ = compute_overall_score(pillars, modules_scanned=4)
        self.assertNotEqual(grade, "?")


if __name__ == "__main__":
    unittest.main()
