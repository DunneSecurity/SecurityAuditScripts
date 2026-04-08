"""Tests for exec_summary.py"""
import sys
import os
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import exec_summary as es


# ── load_report ────────────────────────────────────────────────────────────────

def test_load_report_reads_valid_json(tmp_path):
    data = {"generated_at": "2026-01-01", "findings": [], "summary": {"total_buckets": 0}}
    p = tmp_path / "s3_report.json"
    p.write_text(json.dumps(data))
    result = es.load_report(str(p))
    assert result["generated_at"] == "2026-01-01"


def test_load_report_returns_none_on_missing_file():
    result = es.load_report("/nonexistent/path.json")
    assert result is None


def test_load_report_returns_none_on_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not json {{{")
    result = es.load_report(str(p))
    assert result is None


# ── discover_reports ───────────────────────────────────────────────────────────

REPORT_PATTERNS = es.KNOWN_PATTERNS


def test_discover_reports_finds_known_patterns(tmp_path):
    for fname in REPORT_PATTERNS[:3]:
        (tmp_path / fname).write_text('{"findings": [], "summary": {}}')
    (tmp_path / "unrelated.json").write_text('{}')
    found = es.discover_reports(str(tmp_path))
    assert len(found) == 3
    names = [os.path.basename(p) for p in found]
    assert "s3_report.json" in names
    assert "unrelated.json" not in names


def test_discover_reports_finds_all_onprem_patterns(tmp_path):
    onprem = ["ad_report.json", "localuser_report.json", "winfirewall_report.json",
              "user_report.json", "fw_report.json"]
    for fname in onprem:
        (tmp_path / fname).write_text('{"findings": [], "summary": {}}')
    found = es.discover_reports(str(tmp_path))
    names = [os.path.basename(p) for p in found]
    for fname in onprem:
        assert fname in names, f"{fname} not found by discover_reports"


def test_discover_reports_empty_dir(tmp_path):
    found = es.discover_reports(str(tmp_path))
    assert found == []


# ── compute_pillar_stats ───────────────────────────────────────────────────────

MOCK_REPORT = {
    "generated_at": "2026-01-01",
    "findings": [
        {"risk_level": "CRITICAL", "severity_score": 9, "flags": ["❌ bad"], "remediations": ["fix it"]},
        {"risk_level": "HIGH", "severity_score": 6, "flags": ["⚠️ warn"], "remediations": ["fix this"]},
        {"risk_level": "LOW", "severity_score": 1, "flags": ["✅ good"], "remediations": []},
    ],
    "summary": {"total_buckets": 3, "critical": 1, "high": 1, "medium": 0, "low": 1},
}


def test_compute_pillar_stats_returns_counts():
    stats = es.compute_pillar_stats("s3", MOCK_REPORT)
    assert stats["pillar"] == "s3"
    assert stats["critical"] == 1
    assert stats["high"] == 1
    assert stats["total"] == 3


def test_compute_pillar_stats_overall_risk():
    stats = es.compute_pillar_stats("s3", MOCK_REPORT)
    # Has a CRITICAL finding → pillar risk = CRITICAL
    assert stats["pillar_risk"] == "CRITICAL"


def test_compute_pillar_stats_all_low():
    report = {
        "findings": [{"risk_level": "LOW", "severity_score": 0}],
        "summary": {},
    }
    stats = es.compute_pillar_stats("cloudtrail", report)
    assert stats["pillar_risk"] == "LOW"


# ── compute_overall_score ──────────────────────────────────────────────────────

def test_compute_overall_score_no_findings():
    score, grade, _ = es.compute_overall_score([])
    assert score == 100
    assert grade == "A"


def test_compute_overall_score_all_critical():
    # 3 CRITICAL pillars × 8 pts each = 24 deducted → score 76
    # C-cap fires (2+ CRITICAL pillars → grade ≤ C) so grade = C despite 76 pts
    pillar_stats = [
        {"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1, "pillar_risk": "CRITICAL"},
        {"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1, "pillar_risk": "CRITICAL"},
        {"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1, "pillar_risk": "CRITICAL"},
    ]
    score, grade, _ = es.compute_overall_score(pillar_stats)
    assert score == 76.0
    assert grade == "C"


def test_compute_overall_score_severe_is_f():
    # 13 CRITICAL pillars × 8 pts each = 104 → clamped to 0 → F
    # Deductions are per-pillar, not per-finding (see compute_overall_score docstring)
    pillar_stats = [
        {"critical": 1, "high": 0, "medium": 0, "low": 0, "total": 1, "pillar_risk": "CRITICAL"}
        for _ in range(13)
    ]
    score, grade, _ = es.compute_overall_score(pillar_stats)
    assert score == 0
    assert grade == "F"


def test_compute_overall_score_mixed():
    pillar_stats = [
        {"critical": 1, "high": 2, "medium": 3, "low": 10, "total": 16, "pillar_risk": "CRITICAL"},
        {"critical": 0, "high": 0, "medium": 1, "low": 5, "total": 6, "pillar_risk": "MEDIUM"},
    ]
    score, grade, _ = es.compute_overall_score(pillar_stats)
    assert 0 <= score <= 100


def test_compute_overall_score_grade_a():
    pillar_stats = [
        {"critical": 0, "high": 0, "medium": 0, "low": 2, "total": 2, "pillar_risk": "LOW"},
    ]
    score, grade, _ = es.compute_overall_score(pillar_stats)
    assert grade == "A"
    assert score >= 85


# ── get_top_findings ───────────────────────────────────────────────────────────

def test_get_top_findings_returns_critical_first():
    all_findings = [
        {"risk_level": "LOW", "severity_score": 1, "pillar": "s3"},
        {"risk_level": "CRITICAL", "severity_score": 9, "pillar": "sg"},
        {"risk_level": "HIGH", "severity_score": 6, "pillar": "cloudtrail"},
    ]
    top = es.get_top_findings(all_findings, n=2)
    assert len(top) == 2
    assert top[0]["risk_level"] == "CRITICAL"
    assert top[1]["risk_level"] == "HIGH"


def test_get_top_findings_respects_n():
    findings = [{"risk_level": "HIGH", "severity_score": i, "pillar": "x"} for i in range(10)]
    top = es.get_top_findings(findings, n=3)
    assert len(top) == 3


# ── get_quick_wins ─────────────────────────────────────────────────────────────

def test_get_quick_wins_returns_informational_on_high():
    """ℹ️ flags on HIGH/CRITICAL findings are quick wins (low-effort, high-impact)."""
    findings = [
        {
            "risk_level": "HIGH",
            "severity_score": 6,
            "pillar": "s3",
            "flags": ["❌ no encryption", "ℹ️ versioning disabled"],
            "remediations": ["encrypt it", "enable versioning"],
        },
        {
            "risk_level": "LOW",
            "severity_score": 1,
            "pillar": "sg",
            "flags": ["ℹ️ unused group"],
            "remediations": ["delete it"],
        },
    ]
    wins = es.get_quick_wins(findings, max_wins=5)
    # Only ℹ️ flags on HIGH findings should be returned
    assert len(wins) >= 1
    assert all(w["risk_level"] in ("HIGH", "CRITICAL") for w in wins)


import stat


SAMPLE_PILLAR_STATS = [
    {"pillar": "s3", "label": "S3 Buckets", "critical": 1, "high": 2,
     "medium": 3, "low": 5, "total": 11, "pillar_risk": "CRITICAL", "generated_at": "2026-01-01"},
    {"pillar": "sg", "label": "Security Groups", "critical": 0, "high": 0,
     "medium": 2, "low": 8, "total": 10, "pillar_risk": "MEDIUM", "generated_at": "2026-01-01"},
]

SAMPLE_TOP_FINDINGS = [
    {"pillar": "s3", "risk_level": "CRITICAL", "severity_score": 9,
     "name": "my-public-bucket",
     "flags": ["❌ Public access", "⚠️ No encryption"],
     "remediations": ["Block public access", "Enable encryption"]},
]

SAMPLE_QUICK_WINS = [
    {"pillar": "s3", "risk_level": "HIGH", "resource": "my-bucket",
     "flag": "ℹ️ Versioning disabled",
     "remediation": "Enable versioning: S3 Console → Properties → Bucket Versioning → Enable"},
]


def test_write_html_creates_file_with_600_perms(tmp_path):
    out = str(tmp_path / "exec_summary.html")
    es.write_html(
        overall_score=72.5,
        grade="B",
        pillar_stats=SAMPLE_PILLAR_STATS,
        top_findings=SAMPLE_TOP_FINDINGS,
        quick_wins=SAMPLE_QUICK_WINS,
        generated_at="2026-01-01T00:00:00+00:00",
        path=out,
    )
    assert (tmp_path / "exec_summary.html").exists()
    assert (tmp_path / "exec_summary.html").stat().st_mode & 0o777 == 0o600


def test_write_html_contains_score(tmp_path):
    out = str(tmp_path / "exec_summary.html")
    es.write_html(
        overall_score=72.5, grade="B",
        pillar_stats=SAMPLE_PILLAR_STATS,
        top_findings=SAMPLE_TOP_FINDINGS,
        quick_wins=SAMPLE_QUICK_WINS,
        generated_at="2026-01-01T00:00:00+00:00",
        path=out,
    )
    content = (tmp_path / "exec_summary.html").read_text()
    assert "72.5" in content
    assert "Grade: B" in content


def test_write_html_contains_pillar_names(tmp_path):
    out = str(tmp_path / "exec_summary.html")
    es.write_html(
        overall_score=72.5, grade="B",
        pillar_stats=SAMPLE_PILLAR_STATS,
        top_findings=SAMPLE_TOP_FINDINGS,
        quick_wins=[],
        generated_at="2026-01-01T00:00:00+00:00",
        path=out,
    )
    content = (tmp_path / "exec_summary.html").read_text()
    assert "S3 Buckets" in content
    assert "Security Groups" in content


def test_write_html_contains_top_finding(tmp_path):
    out = str(tmp_path / "exec_summary.html")
    es.write_html(
        overall_score=50.0, grade="C",
        pillar_stats=SAMPLE_PILLAR_STATS,
        top_findings=SAMPLE_TOP_FINDINGS,
        quick_wins=SAMPLE_QUICK_WINS,
        generated_at="2026-01-01T00:00:00+00:00",
        path=out,
    )
    content = (tmp_path / "exec_summary.html").read_text()
    assert "my-public-bucket" in content


def test_write_html_empty_findings_still_creates_file(tmp_path):
    out = str(tmp_path / "exec_summary.html")
    es.write_html(
        overall_score=100.0, grade="A",
        pillar_stats=[],
        top_findings=[],
        quick_wins=[],
        generated_at="2026-01-01T00:00:00+00:00",
        path=out,
    )
    assert (tmp_path / "exec_summary.html").exists()


# ── warn_missing_azure_windows ─────────────────────────────────────────────────

def test_warn_missing_returns_empty_when_no_azure_windows_present(tmp_path):
    """Pure AWS/Linux run: no Azure or Windows files → no per-pattern warnings."""
    (tmp_path / "s3_report.json").write_text('{"findings":[],"summary":{}}')
    result = es.warn_missing_azure_windows(str(tmp_path))
    assert result == []


def test_warn_missing_returns_empty_when_all_azure_present(tmp_path):
    """All Azure patterns present → no Azure warnings."""
    for p in es.AZURE_PATTERNS:
        (tmp_path / p).write_text('{"findings":[],"summary":{}}')
    result = es.warn_missing_azure_windows(str(tmp_path))
    azure_warns = [w for w in result if "azure" in w.lower()]
    assert azure_warns == []


def test_warn_missing_returns_empty_when_all_windows_present(tmp_path):
    """All Windows patterns present → no Windows warnings."""
    for p in es.WINDOWS_PATTERNS:
        (tmp_path / p).write_text('{"findings":[],"summary":{}}')
    result = es.warn_missing_azure_windows(str(tmp_path))
    windows_warns = [w for w in result if "windows" in w.lower()]
    assert windows_warns == []


def test_warn_missing_azure_partial_run_warns_per_missing_azure(tmp_path):
    """Azure partial run: one Azure present, rest missing → one warning per missing Azure."""
    (tmp_path / "keyvault_report.json").write_text('{"findings":[],"summary":{}}')
    result = es.warn_missing_azure_windows(str(tmp_path))
    # Should have warnings for all other Azure patterns (AZURE_PATTERNS minus keyvault)
    expected_missing = len(es.AZURE_PATTERNS) - 1
    assert len(result) == expected_missing
    # Each warning should mention the missing filename
    for p in es.AZURE_PATTERNS:
        if p != "keyvault_report.json":
            assert any(p in w for w in result), f"No warning for missing Azure pattern: {p}"


def test_warn_missing_windows_partial_run_warns_per_missing_windows(tmp_path):
    """Windows partial run: one Windows present, rest missing → one warning per missing Windows."""
    (tmp_path / "ad_report.json").write_text('{"findings":[],"summary":{}}')
    result = es.warn_missing_azure_windows(str(tmp_path))
    expected_missing = len(es.WINDOWS_PATTERNS) - 1
    assert len(result) == expected_missing
    for p in es.WINDOWS_PATTERNS:
        if p != "ad_report.json":
            assert any(p in w for w in result), f"No warning for missing Windows pattern: {p}"


def test_warn_missing_azure_only_run_no_windows_warnings(tmp_path):
    """Azure ran (all present), Windows didn't → no Windows warnings."""
    for p in es.AZURE_PATTERNS:
        (tmp_path / p).write_text('{"findings":[],"summary":{}}')
    result = es.warn_missing_azure_windows(str(tmp_path))
    # No Windows warnings when Windows intentionally not run
    for w in result:
        for wp in es.WINDOWS_PATTERNS:
            assert wp not in w, f"Unexpected Windows warning when Windows not run: {w}"


def test_warn_missing_windows_only_run_no_azure_warnings(tmp_path):
    """Windows ran (all present), Azure didn't → no Azure warnings."""
    for p in es.WINDOWS_PATTERNS:
        (tmp_path / p).write_text('{"findings":[],"summary":{}}')
    result = es.warn_missing_azure_windows(str(tmp_path))
    # No Azure warnings when Azure intentionally not run
    for w in result:
        for ap in es.AZURE_PATTERNS:
            assert ap not in w, f"Unexpected Azure warning when Azure not run: {w}"


# ── write_html warnings parameter ──────────────────────────────────────────────

def test_write_html_renders_warning_section_when_warnings_provided(tmp_path):
    """Warnings list → HTML contains a warning section with the warning text."""
    out = str(tmp_path / "exec_summary.html")
    es.write_html(
        overall_score=80.0, grade="B",
        pillar_stats=SAMPLE_PILLAR_STATS,
        top_findings=[],
        quick_wins=[],
        generated_at="2026-01-01T00:00:00+00:00",
        path=out,
        warnings=["storage_report.json not found — copy from Windows machine"],
    )
    content = (tmp_path / "exec_summary.html").read_text()
    assert "storage_report.json" in content


def test_write_html_no_warning_section_when_warnings_empty(tmp_path):
    """Empty warnings → HTML does not contain warning section div."""
    out = str(tmp_path / "exec_summary.html")
    es.write_html(
        overall_score=80.0, grade="B",
        pillar_stats=SAMPLE_PILLAR_STATS,
        top_findings=[],
        quick_wins=[],
        generated_at="2026-01-01T00:00:00+00:00",
        path=out,
        warnings=[],
    )
    content = (tmp_path / "exec_summary.html").read_text()
    assert '<div class="warn-section">' not in content


# ── e2e integration tests (run() full pipeline) ────────────────────────────────

# Representative AWS-style report fixture (s3_auditor schema)
_S3_FIXTURE = {
    "generated_at": "2026-01-01T00:00:00+00:00",
    "findings": [
        {
            "risk_level": "CRITICAL",
            "severity_score": 9,
            "name": "acme-public-backup",
            "flags": ["❌ Public access enabled", "❌ No encryption"],
            "remediations": ["Block public access via S3 console", "Enable SSE-S3 encryption"],
        },
        {
            "risk_level": "HIGH",
            "severity_score": 7,
            "name": "acme-logs",
            "flags": ["ℹ️ Versioning disabled"],
            "remediations": ["Enable versioning: S3 Console → Properties → Bucket Versioning → Enable"],
        },
    ],
    "summary": {"total_buckets": 2, "critical": 1, "high": 1, "medium": 0, "low": 0},
}

# Representative AWS-style report fixture (cloudtrail_auditor schema)
_CLOUDTRAIL_FIXTURE = {
    "generated_at": "2026-01-01T00:00:00+00:00",
    "findings": [
        {
            "risk_level": "MEDIUM",
            "severity_score": 4,
            "name": "us-east-1-trail",
            "flags": ["⚠️ Multi-region disabled"],
            "remediations": ["Enable multi-region trail in CloudTrail console"],
        }
    ],
    "summary": {"total_trails": 1, "critical": 0, "high": 0, "medium": 1, "low": 0},
}

# Representative Linux-style report fixture (linux_ssh_auditor schema)
_SSH_FIXTURE = {
    "generated_at": "2026-01-01T00:00:00+00:00",
    "ssh_daemon_installed": True,
    "findings": [
        {
            "risk_level": "HIGH",
            "param": "PermitRootLogin",
            "actual": "yes",
            "expected": "no",
            "description": "Root login via SSH is permitted",
            "recommendation": "Set PermitRootLogin no in /etc/ssh/sshd_config",
        }
    ],
    "summary": {"host": "web01", "total": 1},
}


def _write_fixture(directory, filename, data):
    path = directory / filename
    path.write_text(json.dumps(data))
    return path


def test_run_creates_html_and_sidecar(tmp_path):
    """run() with two fixtures → HTML and sidecar JSON both created."""
    _write_fixture(tmp_path, "s3_report.json", _S3_FIXTURE)
    _write_fixture(tmp_path, "cloudtrail_report.json", _CLOUDTRAIL_FIXTURE)
    out = str(tmp_path / "exec_summary.html")
    es.run(input_dir=str(tmp_path), output_path=out)
    assert (tmp_path / "exec_summary.html").exists()
    assert (tmp_path / "exec_summary_data.json").exists()


def test_run_score_reflects_critical_findings(tmp_path):
    """Fixture with a CRITICAL finding → score < 100, grade not A."""
    _write_fixture(tmp_path, "s3_report.json", _S3_FIXTURE)
    out = str(tmp_path / "exec_summary.html")
    es.run(input_dir=str(tmp_path), output_path=out)
    sidecar = json.loads((tmp_path / "exec_summary_data.json").read_text())
    assert sidecar["score"] < 100
    assert sidecar["grade"] != "A"


def test_run_html_contains_pillar_names(tmp_path):
    """s3 + cloudtrail fixtures → HTML contains both pillar labels."""
    _write_fixture(tmp_path, "s3_report.json", _S3_FIXTURE)
    _write_fixture(tmp_path, "cloudtrail_report.json", _CLOUDTRAIL_FIXTURE)
    out = str(tmp_path / "exec_summary.html")
    es.run(input_dir=str(tmp_path), output_path=out)
    content = (tmp_path / "exec_summary.html").read_text()
    assert "S3 Buckets" in content
    assert "CloudTrail" in content


def test_run_html_contains_top_finding_resource(tmp_path):
    """CRITICAL finding with a named resource → resource name appears in HTML."""
    _write_fixture(tmp_path, "s3_report.json", _S3_FIXTURE)
    out = str(tmp_path / "exec_summary.html")
    es.run(input_dir=str(tmp_path), output_path=out)
    content = (tmp_path / "exec_summary.html").read_text()
    assert "acme-public-backup" in content


def test_run_empty_dir_still_creates_html(tmp_path):
    """No report files → run() completes without crashing and creates HTML."""
    out = str(tmp_path / "exec_summary.html")
    es.run(input_dir=str(tmp_path), output_path=out)
    assert (tmp_path / "exec_summary.html").exists()


def test_run_audit_manifest_not_run_pillar(tmp_path):
    """audit_manifest.json lists 'iam' but no iam_report.json → HTML shows NOT RUN."""
    _write_fixture(tmp_path, "s3_report.json", _S3_FIXTURE)
    manifest = {"auditors_attempted": ["s3", "iam"]}
    (tmp_path / "audit_manifest.json").write_text(json.dumps(manifest))
    out = str(tmp_path / "exec_summary.html")
    es.run(input_dir=str(tmp_path), output_path=out)
    content = (tmp_path / "exec_summary.html").read_text()
    assert "NOT RUN" in content


def test_run_partial_azure_warning_in_html(tmp_path):
    """One Azure report present, rest missing → partial-run warning appears in HTML."""
    _write_fixture(tmp_path, "keyvault_report.json",
                   {"generated_at": "2026-01-01", "findings": [], "summary": {}})
    out = str(tmp_path / "exec_summary.html")
    es.run(input_dir=str(tmp_path), output_path=out)
    content = (tmp_path / "exec_summary.html").read_text()
    # At least one missing Azure file name should appear in the warning section
    assert any(p in content for p in es.AZURE_PATTERNS if p != "keyvault_report.json")


def test_run_linux_style_finding_schema(tmp_path):
    """Linux-style finding (recommendation/param fields) → pipeline completes, score < 100."""
    _write_fixture(tmp_path, "ssh_report.json", _SSH_FIXTURE)
    out = str(tmp_path / "exec_summary.html")
    es.run(input_dir=str(tmp_path), output_path=out)
    assert (tmp_path / "exec_summary.html").exists()
    sidecar = json.loads((tmp_path / "exec_summary_data.json").read_text())
    assert sidecar["score"] < 100


def test_run_html_permissions(tmp_path):
    """Output HTML has 0o600 permissions."""
    _write_fixture(tmp_path, "s3_report.json", _S3_FIXTURE)
    out = str(tmp_path / "exec_summary.html")
    es.run(input_dir=str(tmp_path), output_path=out)
    assert (tmp_path / "exec_summary.html").stat().st_mode & 0o777 == 0o600


def test_run_sidecar_contains_score_and_grade(tmp_path):
    """Sidecar JSON has score, grade, and pillar_stats keys."""
    _write_fixture(tmp_path, "s3_report.json", _S3_FIXTURE)
    _write_fixture(tmp_path, "cloudtrail_report.json", _CLOUDTRAIL_FIXTURE)
    out = str(tmp_path / "exec_summary.html")
    es.run(input_dir=str(tmp_path), output_path=out)
    sidecar = json.loads((tmp_path / "exec_summary_data.json").read_text())
    assert "score" in sidecar
    assert "grade" in sidecar
    assert "pillar_stats" in sidecar
    assert len(sidecar["pillar_stats"]) == 2
