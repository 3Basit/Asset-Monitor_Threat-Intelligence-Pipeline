# MITRE ATT&CK technique mapping keyed by vuln_type (as produced by matching.py)

VULN_TYPE_TO_ATTACK = {
    "rce":            {"technique_id": "T1190",    "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "sqli":           {"technique_id": "T1190",    "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "auth_bypass":    {"technique_id": "T1078",    "technique_name": "Valid Accounts",                    "tactic": "Defense Evasion"},
    "path_traversal": {"technique_id": "T1083",    "technique_name": "File and Directory Discovery",      "tactic": "Discovery"},
    "ssrf":           {"technique_id": "T1090",    "technique_name": "Proxy",                             "tactic": "Command and Control"},
    "xss":            {"technique_id": "T1059.007","technique_name": "JavaScript",                        "tactic": "Execution"},
    "other":          {"technique_id": "T1190",    "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "unknown":        {"technique_id": None,        "technique_name": None,                               "tactic": None},
}


def get_attack_mapping(vuln_type):
    """Return the ATT&CK technique dict for the given vuln_type.

    Falls back to the 'unknown' entry if vuln_type is not recognised.
    """
    return VULN_TYPE_TO_ATTACK.get(vuln_type, VULN_TYPE_TO_ATTACK["unknown"])
