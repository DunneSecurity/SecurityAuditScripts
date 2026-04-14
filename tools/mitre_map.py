"""
MITRE ATT&CK mapping for SecurityAuditScripts finding types.

Maps finding_type strings to their most relevant MITRE ATT&CK tactic and
technique. Used by schema.validate_finding() to auto-enrich findings and
by correlations.py to label compound risk rules.

Keys match the exact finding_type strings used across all auditors.
"""

MITRE_MAP = {
    # ── Initial Access (TA0001) ──────────────────────────────────────────────
    "RDPOpenToAll": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique_id": "T1133", "technique_name": "External Remote Services",
    },
    "WinRMOpenToAll": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique_id": "T1133", "technique_name": "External Remote Services",
    },
    "SMBOpenToAll": {
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "technique_id": "T1021.002", "technique_name": "Remote Services: SMB/Windows Admin Shares",
    },
    "DangerousPort": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique_id": "T1133", "technique_name": "External Remote Services",
    },
    "DangerousPortOpenToAll": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique_id": "T1133", "technique_name": "External Remote Services",
    },
    "ICMPEchoPublicOpen": {
        "tactic": "Discovery", "tactic_id": "TA0007",
        "technique_id": "T1018", "technique_name": "Remote System Discovery",
    },
    "NoFirewallActive": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique_id": "T1133", "technique_name": "External Remote Services",
    },
    "DefaultPolicyAccept": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique_id": "T1133", "technique_name": "External Remote Services",
    },
    "InboundDefaultAllow": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique_id": "T1133", "technique_name": "External Remote Services",
    },
    "NoDenyRules": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique_id": "T1133", "technique_name": "External Remote Services",
    },

    # ── Persistence (TA0003) ─────────────────────────────────────────────────
    "StaleAppCredential": {
        "tactic": "Persistence", "tactic_id": "TA0003",
        "technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts",
    },
    "ServicePrincipalBroadScope": {
        "tactic": "Persistence", "tactic_id": "TA0003",
        "technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts",
    },
    "PrivilegedGuest": {
        "tactic": "Persistence", "tactic_id": "TA0003",
        "technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts",
    },
    "StaleUser": {
        "tactic": "Persistence", "tactic_id": "TA0003",
        "technique_id": "T1078", "technique_name": "Valid Accounts",
    },

    # ── Privilege Escalation (TA0004) ────────────────────────────────────────
    "TooManyGlobalAdmins": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts",
    },
    "OverpermissiveCustomRole": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique_id": "T1078", "technique_name": "Valid Accounts",
    },
    "SudoAllCommandsGranted": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique_id": "T1548.003", "technique_name": "Abuse Elevation Control: Sudo and Sudo Caching",
    },
    "SudoAllNopasswd": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique_id": "T1548.003", "technique_name": "Abuse Elevation Control: Sudo and Sudo Caching",
    },
    "PasswordlessRootEquivalent": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique_id": "T1548", "technique_name": "Abuse Elevation Control Mechanism",
    },
    "PermanentOwnerAssignment": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique_id": "T1078", "technique_name": "Valid Accounts",
    },
    "ExcessiveDomainAdmins": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique_id": "T1078.002", "technique_name": "Valid Accounts: Domain Accounts",
    },
    "KerberoastableAccount": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1558.003", "technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
    },
    "ASREPRoastableAccount": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1558.004", "technique_name": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
    },
    "PrivilegeEscalationPath": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique_id": "T1078", "technique_name": "Valid Accounts",
    },
    "UidZeroNonRoot": {
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "technique_id": "T1548", "technique_name": "Abuse Elevation Control Mechanism",
    },

    # ── Defense Evasion (TA0005) ─────────────────────────────────────────────
    "AuditdNotRunning": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools",
    },
    "AuditdNoExecRules": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools",
    },
    "AdminAuditLoggingDisabled": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562.008", "technique_name": "Impair Defenses: Disable Cloud Logs",
    },
    "MailboxAuditLoggingDisabled": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562.008", "technique_name": "Impair Defenses: Disable Cloud Logs",
    },
    "DefenderNotEnabled": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools",
    },
    "TamperProtectionDisabled": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools",
    },
    "SecurityDefaultsDisabled": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562", "technique_name": "Impair Defenses",
    },
    "RtpDisabled": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools",
    },
    "NoDiagnosticLogging": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562.008", "technique_name": "Impair Defenses: Disable Cloud Logs",
    },
    "NoDiagnosticSetting": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562.008", "technique_name": "Impair Defenses: Disable Cloud Logs",
    },
    "SyslogNotConfigured": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562.008", "technique_name": "Impair Defenses: Disable Cloud Logs",
    },
    "NoLogDestination": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562.008", "technique_name": "Impair Defenses: Disable Cloud Logs",
    },

    # ── Credential Access (TA0006) ───────────────────────────────────────────
    "UserNoMfa": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1078", "technique_name": "Valid Accounts",
    },
    "GlobalAdminNoMfa": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1078", "technique_name": "Valid Accounts",
    },
    "UserPasswordNeverExpires": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1078", "technique_name": "Valid Accounts",
    },
    "WeakDomainPasswordPolicy": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1110", "technique_name": "Brute Force",
    },
    "WeakPasswordPolicy": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1110", "technique_name": "Brute Force",
    },
    "SSHPasswordAuthEnabled": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1110.003", "technique_name": "Brute Force: Password Spraying",
    },
    "EmptyPasswordHash": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1078.003", "technique_name": "Valid Accounts: Local Accounts",
    },
    "WDigestAuthEnabled": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1003.001", "technique_name": "OS Credential Dumping: LSASS Memory",
    },
    "NtlmV1Enabled": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1557", "technique_name": "Adversary-in-the-Middle",
    },
    "DirectRootSSH": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1078.003", "technique_name": "Valid Accounts: Local Accounts",
    },
    "LocalUserNoPassword": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1078.003", "technique_name": "Valid Accounts: Local Accounts",
    },
    "UsersMissingMfaRegistration": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1078", "technique_name": "Valid Accounts",
    },
    "NoMfaCaPolicy": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1078", "technique_name": "Valid Accounts",
    },

    # ── Lateral Movement (TA0008) ────────────────────────────────────────────

    # ── Collection (TA0009) ──────────────────────────────────────────────────
    "UnrestrictedOAuthConsent": {
        "tactic": "Collection", "tactic_id": "TA0009",
        "technique_id": "T1528", "technique_name": "Steal Application Access Token",
    },
    "GuestAccessUnrestricted": {
        "tactic": "Collection", "tactic_id": "TA0009",
        "technique_id": "T1530", "technique_name": "Data from Cloud Storage",
    },
    "AnonymousLinksFound": {
        "tactic": "Collection", "tactic_id": "TA0009",
        "technique_id": "T1530", "technique_name": "Data from Cloud Storage",
    },

    # ── Exfiltration (TA0010) ────────────────────────────────────────────────
    "PublicBlobAccess": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique_id": "T1530", "technique_name": "Data from Cloud Storage",
    },
    "ExternalMailboxForwarding": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique_id": "T1114.003", "technique_name": "Email Collection: Email Forwarding Rule",
    },
    "ExternalInboxForwardRule": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique_id": "T1114.003", "technique_name": "Email Collection: Email Forwarding Rule",
    },
    "TenantExternalSharingAnyone": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique_id": "T1530", "technique_name": "Data from Cloud Storage",
    },
    "OneDriveExternalSharingUnrestricted": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique_id": "T1530", "technique_name": "Data from Cloud Storage",
    },
    "RemoteDomainAutoForwardEnabled": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique_id": "T1114.003", "technique_name": "Email Collection: Email Forwarding Rule",
    },
    "ExternalSharingNoDomainRestriction": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique_id": "T1530", "technique_name": "Data from Cloud Storage",
    },

    # ── Impact (TA0040) ──────────────────────────────────────────────────────
    "PurgeProtectionDisabled": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique_id": "T1485", "technique_name": "Data Destruction",
    },
    "SoftDeleteDisabled": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique_id": "T1485", "technique_name": "Data Destruction",
    },
    "ImmutabilityDisabled": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique_id": "T1485", "technique_name": "Data Destruction",
    },
    "NoBudgetAlerts": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique_id": "T1496", "technique_name": "Resource Hijacking",
    },
    "RecycleBinDisabled": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique_id": "T1485", "technique_name": "Data Destruction",
    },
    "RecentBackupFailure": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique_id": "T1490", "technique_name": "Inhibit System Recovery",
    },
    "VersioningDisabled": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique_id": "T1485", "technique_name": "Data Destruction",
    },
}
