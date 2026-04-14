"""
Cross-pillar correlation engine for SecurityAuditScripts.

Detects compound attack paths that emerge when multiple finding types
co-occur across security pillars. Each rule maps to a real MITRE ATT&CK
tactic and fires based on one of three match strategies:

  all       — every listed finding_type must be present
  any_two   — any 2 or more of the listed finding_types must be present
  any_one   — any single listed finding_type triggers the rule
  all_groups — every group must contribute at least one match (AND logic)

Usage:
    from correlations import run_correlations
    triggered = run_correlations(all_findings_flat)
"""

from __future__ import annotations
from typing import List, Dict, Any


CORRELATION_RULES: List[Dict[str, Any]] = [
    {
        "id": "CP-01",
        "name": "Undetected Credential Theft Path",
        "finding_types": ["UserNoMfa", "AuditdNotRunning", "MailboxAuditLoggingDisabled",
                          "NoDiagnosticLogging", "AdminAuditLoggingDisabled"],
        "match": "any_two",
        "severity": "CRITICAL",
        "mitre_tactic": "Credential Access + Defense Evasion",
        "mitre_technique_id": "T1078 + T1562.008",
        "narrative": (
            "Accounts without MFA combined with disabled audit logging means credential "
            "theft goes completely undetected. An attacker can compromise accounts and "
            "operate for weeks without triggering any alerts."
        ),
    },
    {
        "id": "CP-02",
        "name": "Lateral Movement via Exposed Remote Services",
        "finding_types": ["RDPOpenToAll", "SMBOpenToAll", "WinRMOpenToAll", "DangerousPort",
                          "DangerousPortOpenToAll"],
        "match": "any_two",
        "severity": "CRITICAL",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique_id": "T1021.002",
        "narrative": (
            "Multiple remote access services are exposed to the internet. An attacker who "
            "gains any foothold can pivot laterally across the environment using these open "
            "channels, dramatically expanding their blast radius."
        ),
    },
    {
        "id": "CP-03",
        "name": "Privileged Account Compromise Blast Radius",
        "finding_types": ["GlobalAdminNoMfa", "TooManyGlobalAdmins"],
        "match": "all",
        "severity": "CRITICAL",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique_id": "T1078.004",
        "narrative": (
            "Multiple Global Administrator accounts without MFA means a single phished "
            "credential provides complete tenant control. The blast radius of one compromised "
            "account is the entire Microsoft 365 and Azure environment."
        ),
    },
    {
        "id": "CP-04",
        "name": "Stale Identity Attack Path",
        "finding_types": ["StaleUser", "UserNoMfa"],
        "match": "all",
        "severity": "HIGH",
        "mitre_tactic": "Initial Access",
        "mitre_technique_id": "T1078",
        "narrative": (
            "Forgotten accounts with no MFA are prime targets for credential stuffing and "
            "password spray attacks. These identities are often unmonitored and their "
            "compromise may go unnoticed for extended periods."
        ),
    },
    {
        "id": "CP-05",
        "name": "Cloud Data Exfiltration Path",
        "finding_types": ["PublicBlobAccess", "ServicePrincipalBroadScope"],
        "match": "all",
        "severity": "CRITICAL",
        "mitre_tactic": "Exfiltration",
        "mitre_technique_id": "T1530",
        "narrative": (
            "Publicly accessible storage combined with overpermissioned service principals "
            "enables mass data exfiltration. An attacker exploiting the service principal "
            "can access and export all data in the publicly reachable storage accounts."
        ),
    },
    {
        "id": "CP-06",
        "name": "Kerberos Offline Password Cracking Path",
        "finding_types": ["KerberoastableAccount", "WeakDomainPasswordPolicy"],
        "match": "all",
        "severity": "CRITICAL",
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1558.003",
        "narrative": (
            "Kerberoastable service accounts with a weak domain password policy means "
            "offline password cracking is viable and likely to succeed. An attacker with "
            "any domain user account can harvest service tickets and crack them offline."
        ),
    },
    {
        "id": "CP-07",
        "name": "Persistent External Identity Backdoor",
        "finding_types": ["PrivilegedGuest", "SecurityDefaultsDisabled"],
        "match": "all",
        "severity": "HIGH",
        "mitre_tactic": "Persistence",
        "mitre_technique_id": "T1078.004",
        "narrative": (
            "External guest identities with elevated privileges and no security baseline "
            "controls create a persistent backdoor. These accounts are harder to monitor "
            "and may survive off-boarding processes for internal staff."
        ),
    },
    {
        "id": "CP-08",
        "name": "Silent Email Exfiltration",
        "finding_types": ["ExternalMailboxForwarding", "MailboxAuditLoggingDisabled",
                          "AdminAuditLoggingDisabled", "ExternalInboxForwardRule",
                          "RemoteDomainAutoForwardEnabled"],
        "match": "any_two",
        "severity": "CRITICAL",
        "mitre_tactic": "Exfiltration",
        "mitre_technique_id": "T1114.003",
        "narrative": (
            "Email is being automatically forwarded to external domains with no audit trail "
            "in place. This is a classic data exfiltration technique — all email is silently "
            "copied to an attacker-controlled inbox with zero detection capability."
        ),
    },
    {
        "id": "CP-09",
        "name": "Ransomware Impact Path",
        "finding_types": ["SoftDeleteDisabled", "PurgeProtectionDisabled", "ImmutabilityDisabled",
                          "DefenderNotEnabled", "TamperProtectionDisabled", "RtpDisabled",
                          "VersioningDisabled", "RecycleBinDisabled"],
        "match": "any_two",
        "severity": "CRITICAL",
        "mitre_tactic": "Impact",
        "mitre_technique_id": "T1485",
        "narrative": (
            "Disabled defenses combined with no data recovery safeguards creates an ideal "
            "ransomware environment. An attacker can encrypt or destroy data with no detection "
            "and the organisation has no recovery path without paying the ransom."
        ),
    },
    {
        "id": "CP-10",
        "name": "Active Directory Full Takeover Path",
        "finding_types": ["ExcessiveDomainAdmins", "WeakDomainPasswordPolicy"],
        "match": "all",
        "severity": "CRITICAL",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique_id": "T1078.002",
        "narrative": (
            "Too many Domain Administrators combined with a weak password policy means one "
            "compromised domain admin account results in complete Active Directory takeover. "
            "Domain admin credentials are trivial to crack offline with a weak policy."
        ),
    },
    {
        "id": "CP-11",
        "name": "Internet Exposure Without Monitoring",
        "finding_types": [],
        "match": "all_groups",
        "groups": [
            ["RDPOpenToAll", "SMBOpenToAll", "WinRMOpenToAll", "NoFirewallActive",
             "DefaultPolicyAccept", "InboundDefaultAllow", "DangerousPort"],
            ["AuditdNotRunning", "NoDiagnosticSetting", "NoDiagnosticLogging",
             "AdminAuditLoggingDisabled"],
        ],
        "severity": "HIGH",
        "mitre_tactic": "Initial Access + Defense Evasion",
        "mitre_technique_id": "T1133 + T1562.008",
        "narrative": (
            "Internet-exposed services with no monitoring or logging capability means "
            "compromise attempts and successful breaches go completely undetected. There is "
            "no way to know if systems have already been accessed by an unauthorised party."
        ),
    },
    {
        "id": "CP-12",
        "name": "Stale App Credential with Broad Access",
        "finding_types": ["StaleAppCredential", "ServicePrincipalBroadScope"],
        "match": "all",
        "severity": "HIGH",
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1078.004",
        "narrative": (
            "Expired credentials on overpermissioned application registrations represent a "
            "dormant but high-impact risk. If those credentials were ever stolen or reused, "
            "the attacker inherits Directory-level access to your entire tenant."
        ),
    },
    {
        "id": "CP-13",
        "name": "NTLMv1 Credential Relay Attack Path",
        "finding_types": ["NtlmV1Enabled", "SMBOpenToAll"],
        "match": "all",
        "severity": "HIGH",
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1557",
        "narrative": (
            "NTLMv1 authentication with SMB exposed to the internet enables pass-the-hash "
            "and NTLM relay attacks. An attacker on the network can capture and relay "
            "credentials to authenticate as any user without knowing their password."
        ),
    },
    {
        "id": "CP-14",
        "name": "Comprehensive Audit Blindspot",
        "finding_types": ["AuditdNotRunning", "MailboxAuditLoggingDisabled",
                          "AdminAuditLoggingDisabled", "NoDiagnosticLogging",
                          "NoDiagnosticSetting", "SyslogNotConfigured", "NoLogDestination"],
        "match": "any_two",
        "severity": "HIGH",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique_id": "T1562.008",
        "narrative": (
            "Multiple audit and logging systems are disabled or unconfigured. An attacker "
            "operating in this environment has complete freedom of movement with no forensic "
            "trail. Incident response and breach investigation will be severely hampered."
        ),
    },
    {
        "id": "CP-15",
        "name": "Credential Stuffing Against Weak Identity Controls",
        "finding_types": ["UserPasswordNeverExpires", "UserNoMfa", "WeakPasswordPolicy",
                          "WeakDomainPasswordPolicy", "UsersMissingMfaRegistration",
                          "NoMfaCaPolicy"],
        "match": "any_two",
        "severity": "HIGH",
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1110",
        "narrative": (
            "A combination of weak password policies, non-expiring passwords, and missing "
            "MFA controls creates ideal conditions for credential stuffing and brute force "
            "attacks. Breached credential lists from other services are likely to succeed here."
        ),
    },
]


def _get_present_types(findings: List[Dict[str, Any]]) -> set:
    """Return set of all finding_type values present in the findings list."""
    types = set()
    for f in findings:
        ft = f.get("finding_type") or f.get("FindingType", "")
        if ft:
            types.add(ft)
    return types


def _matches(rule: Dict[str, Any], present_types: set) -> tuple[bool, list]:
    """Return (fired, contributing_types) for a single rule."""
    match = rule.get("match", "all")

    if match == "all":
        relevant = rule["finding_types"]
        matched = [ft for ft in relevant if ft in present_types]
        if set(relevant) <= present_types:
            return True, matched
        return False, []

    elif match == "any_two":
        relevant = rule["finding_types"]
        matched = [ft for ft in relevant if ft in present_types]
        if len(matched) >= 2:
            return True, matched
        return False, []

    elif match == "any_one":
        relevant = rule["finding_types"]
        matched = [ft for ft in relevant if ft in present_types]
        if matched:
            return True, matched
        return False, []

    elif match == "all_groups":
        groups = rule.get("groups", [])
        all_matched = []
        for group in groups:
            group_matches = [ft for ft in group if ft in present_types]
            if not group_matches:
                return False, []
            all_matched.extend(group_matches)
        return True, all_matched

    raise ValueError(f"Unknown match type '{match}' in rule '{rule.get('id')}'")  # pragma: no cover


def run_correlations(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Evaluate all correlation rules against a flat findings list.

    Args:
        findings: Flat list of finding dicts from any auditor (already enriched
                  by validate_finding if available).

    Returns:
        List of triggered correlation finding dicts, each with keys:
          id, name, severity, mitre_tactic, mitre_technique_id,
          narrative, contributing_types.
        Empty list when no rules fire or findings is empty.
    """
    if not findings:
        return []

    present_types = _get_present_types(findings)
    triggered = []

    for rule in CORRELATION_RULES:
        fired, contributing = _matches(rule, present_types)
        if fired:
            triggered.append({
                "id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "mitre_tactic": rule["mitre_tactic"],
                "mitre_technique_id": rule["mitre_technique_id"],
                "narrative": rule["narrative"],
                "contributing_types": contributing,
            })

    return triggered
