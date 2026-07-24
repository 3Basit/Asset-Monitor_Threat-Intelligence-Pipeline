"""
mitre_attack.py — MITRE ATT&CK Contextual Mapping
===================================================
Maps vulnerability types (vuln_type) to MITRE ATT&CK techniques and tactics.

IMPORTANT — Methodology Note:
    This mapping is a *contextual heuristic* based on CWE-to-ATT&CK
    relationships and common attack patterns. It is NOT an official
    MITRE-certified CVE-to-ATT&CK mapping.

    The mapping represents the most likely initial attack technique for each
    vulnerability class in a web-facing context. A single vuln_type may map
    to different techniques depending on the specific exploit chain — this
    module captures the primary/most-common association.

    Source rationale:
        RCE / SQLi  → T1190  (Exploit Public-Facing Application) — direct
        auth_bypass → T1078  (Valid Accounts) — credential/session abuse
        traversal   → T1083  (File Discovery) — path enumeration
        ssrf        → T1090  (Proxy) — internal network pivoting
        xss         → T1059.007 (JavaScript) — client-side execution
"""

VULN_TYPE_TO_ATTACK = {
    "rce":            {"technique_id": "T1190",     "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "sqli":           {"technique_id": "T1190",     "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "auth_bypass":    {"technique_id": "T1078",     "technique_name": "Valid Accounts",                    "tactic": "Defense Evasion"},
    "path_traversal": {"technique_id": "T1083",     "technique_name": "File and Directory Discovery",      "tactic": "Discovery"},
    "ssrf":           {"technique_id": "T1090",     "technique_name": "Proxy",                             "tactic": "Command and Control"},
    "xss":            {"technique_id": "T1059.007", "technique_name": "JavaScript",                        "tactic": "Execution"},
    "other":          {"technique_id": "T1190",     "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "unknown":        {"technique_id": None,         "technique_name": None,                               "tactic": None},
}


def get_attack_mapping(vuln_type):
    """Return the ATT&CK technique dict for the given vuln_type.

    Falls back to the 'unknown' entry if vuln_type is not recognised.
    """
    return VULN_TYPE_TO_ATTACK.get(vuln_type, VULN_TYPE_TO_ATTACK["unknown"])
