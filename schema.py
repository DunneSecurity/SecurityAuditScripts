"""
Canonical finding schema for SecurityAuditScripts.

All auditors must produce findings that conform to FindingSchema.
Use validate_finding() to normalise findings before writing JSON —
this ensures exec_summary.py can aggregate without silent field-name fallbacks.

Canonical fields
----------------
  risk_level    : "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  remediation   : plain-English fix instruction (string)
  flag          : one-line summary of what was found (string)
  cis_control   : e.g. "CIS 4"

Legacy aliases accepted by validate_finding()
---------------------------------------------
  severity       → risk_level
  recommendation → remediation
  detail         → flag   (if flag is absent)
"""

from __future__ import annotations
import os as _os
import sys as _sys

VALID_RISK_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

# Lazy-load MITRE map from tools/mitre_map.py; graceful fallback to empty dict
try:
    _tools_dir = _os.path.join(_os.path.dirname(__file__), "tools")
    if _tools_dir not in _sys.path:
        _sys.path.insert(0, _tools_dir)
    from mitre_map import MITRE_MAP as _MITRE_MAP
except (ImportError, ModuleNotFoundError):
    _MITRE_MAP = {}


def validate_finding(finding: dict) -> dict:
    """Normalise a finding dict to the canonical schema in-place.

    Adds canonical fields from legacy aliases if the canonical field is absent.
    Leaves the original alias fields untouched so individual auditor HTML
    renderers still work without modification.

    Raises ValueError if neither risk_level nor severity is present.
    """
    # risk_level ← severity (case-insensitive alias for PowerShell auditor compat)
    if "risk_level" not in finding:
        sev_key = next((k for k in finding if k.lower() == "severity"), None)
        if sev_key:
            finding["risk_level"] = finding[sev_key]
        else:
            raise ValueError(
                f"Finding missing both 'risk_level' and 'severity': {finding.get('finding_type', finding)}"
            )

    if finding["risk_level"] not in VALID_RISK_LEVELS:
        raise ValueError(
            f"Invalid risk_level '{finding['risk_level']}' — must be one of {VALID_RISK_LEVELS}"
        )

    # remediation ← recommendation
    if "remediation" not in finding:
        finding["remediation"] = finding.get("recommendation", "")

    # flag ← detail (informational summary line)
    if "flag" not in finding:
        finding["flag"] = finding.get("detail", "")

    # MITRE ATT&CK enrichment — adds tactic/technique fields when finding_type is mapped
    ft = finding.get("finding_type") or finding.get("FindingType", "")
    if ft and ft in _MITRE_MAP:
        entry = _MITRE_MAP[ft]
        finding.setdefault("mitre_tactic", entry["tactic"])
        finding.setdefault("mitre_technique_id", entry["technique_id"])
        finding.setdefault("mitre_technique_name", entry["technique_name"])

    return finding
