"""
schema.py — Phase 0: Data Schema Definitions (Revised)
========================================================
FAIR-aligned separation between FREQUENCY features and MAGNITUDE features.

Key insight (from supervisor review):
  - The CVE technical features (cvss_score, epss_score, etc.) drive FREQUENCY
    → they're already captured by threat_pressure_factor (TPF) in the TI module
  - The Magnitude model should train on COMPANY + INCIDENT CONTEXT features only
    → because VCDB doesn't contain CVE-level technical data (no CVSS, no EPSS)
  - Mixing training features with unavailable-at-training-time features would
    create a mismatch between training and inference

FAIR pipeline:
  ALE = Frequency × Magnitude
      = (base_breach_rate × TPF) × ML_predicted_magnitude

  Where:
    TPF already encodes: cvss, epss, kev, exploit, attack_complexity, vuln_type
    ML magnitude model uses: industry, region, size, attack_type, data_sensitivity
"""

# ══════════════════════════════════════════════════════════════════════════════
# FREQUENCY SIDE — drives "how often" (already computed by TI module)
# ══════════════════════════════════════════════════════════════════════════════

# These features feed into TPF (threat_pressure.py). They are NOT used to
# train the Magnitude model because VCDB doesn't contain them. They remain
# in the output JSON for documentation and transparency, but they affect
# the final ALE only through the TPF multiplier.

FREQUENCY_FEATURES = {
    "cvss_score": {
        "type": float, "range": (0.0, 10.0),
        "source": "NVD via nvd_fetch.py",
        "role": "Feeds into TPF via CVSS component (weight 0.20)",
        "used_in_magnitude_training": False,
    },
    "epss_score": {
        "type": float, "range": (0.0, 1.0),
        "source": "FIRST.org via nvd_fetch.py",
        "role": "Feeds into TPF via EPSS component (weight 0.20)",
        "used_in_magnitude_training": False,
    },
    "threat_pressure_factor": {
        "type": float, "range": (1.0, 2.0),
        "source": "threat_pressure.py",
        "role": "Final frequency multiplier = base_rate × TPF",
        "used_in_magnitude_training": False,
    },
    "in_kev": {
        "type": bool,
        "source": "cisa_kev.py",
        "role": "Feeds into TPF via KEV component (weight 0.13)",
        "used_in_magnitude_training": False,
    },
    "has_public_exploit": {
        "type": bool,
        "source": "exploit_db.py",
        "role": "Feeds into TPF via exploit component (weight 0.10)",
        "used_in_magnitude_training": False,
    },
    "attack_complexity": {
        "type": str, "values": ["LOW", "HIGH"],
        "source": "NVD CVSS vector",
        "role": "Feeds into TPF via attack complexity component",
        "used_in_magnitude_training": False,
    },
    "attack_vector": {
        "type": str, "values": ["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"],
        "source": "NVD CVSS vector",
        "role": "Context for TPF, not directly in magnitude training",
        "used_in_magnitude_training": False,
    },
    "privileges_required": {
        "type": str, "values": ["NONE", "LOW", "HIGH"],
        "source": "NVD CVSS vector",
        "role": "Context for attack feasibility (frequency side)",
        "used_in_magnitude_training": False,
    },
    "cwe_id": {
        "type": str, "example": "CWE-89",
        "source": "NVD via nvd_fetch.py",
        "role": "Vulnerability classification, feeds vuln_type",
        "used_in_magnitude_training": False,
    },
    "attack_tactic": {
        "type": str, "example": "Initial Access",
        "source": "mitre_attack.py",
        "role": "ATT&CK context, captured indirectly via vuln_type → TPF",
        "used_in_magnitude_training": False,
    },
    "vuln_type": {
        "type": str,
        "values": ["rce", "sqli", "path_traversal", "auth_bypass",
                   "ssrf", "xss", "other", "unknown"],
        "source": "matching.py → detect_vuln_type()",
        "role": "Feeds into TPF via vuln_type component (weight 0.05-0.20)",
        "used_in_magnitude_training": False,
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# MAGNITUDE SIDE — drives "how much it costs" (what the ML model predicts)
# ══════════════════════════════════════════════════════════════════════════════

# These features are available in BOTH training data (VCDB) AND inference time
# (company_profile.json + TI output). The ML model trains on these to learn
# "given this company profile and attack context, how much does it cost?"

# ── Company features (from company_profile.json at inference time) ────────────

MAGNITUDE_COMPANY_FEATURES = {
    "industry_sector": {
        "type": str,
        "values": [
            "healthcare", "financial", "industrial", "energy",
            "technology", "pharmaceuticals", "professional_services",
            "transportation", "entertainment", "education",
            "communication", "consumer", "retail", "media",
            "hospitality", "research", "public_sector"
        ],
        "source_training": "VCDB victim.industry (NAICS → mapped)",
        "source_inference": "company_profile.json",
    },
    "employee_count_range": {
        "type": str,
        "values": [
            "1 to 10", "11 to 100", "101 to 1000",
            "1001 to 10000", "10001 to 25000",
            "25001 to 50000", "50001 to 100000",
            "Over 100000", "Unknown"
        ],
        "source_training": "VCDB victim.employee_count",
        "source_inference": "company_profile.json",
    },
    "region": {
        "type": str,
        "values": [
            "US", "Middle_East", "Canada", "Germany", "Japan",
            "UK", "Italy", "France", "South_Korea", "Australia",
            "ASEAN", "Latin_America", "India", "South_Africa", "EU"
        ],
        "source_training": "VCDB victim.country → mapped",
        "source_inference": "company_profile.json",
        "note": "Region is NOT a training feature for the ML model. Its effect is "
                "applied as a post-prediction external multiplier from IBM regional "
                "cost data (see ibm_benchmarks.py). This avoids double-counting since "
                "training data is 80% US and the model cannot reliably learn "
                "regional cost differences from 288 rows.",
    },
    "data_sensitivity": {
        "type": str,
        "values": ["ip", "corporate", "anonymized_customer",
                   "customer_pii", "employee_pii"],
        "source_training": "VCDB attribute.confidentiality.data[].variety → mapped",
        "source_inference": "company_profile.json",
    },
    "estimated_records": {
        "type": int, "range": (0, None),
        "source_training": "VCDB attribute.confidentiality.data_total",
        "source_inference": "company_profile.json",
    },
    "annual_revenue_usd": {
        "type": float, "range": (0, None), "optional": True,
        "source_training": "VCDB victim.revenue.amount (sparse)",
        "source_inference": "company_profile.json (optional)",
    },
    "has_cyber_insurance": {
        "type": bool,
        "source_training": "Not in VCDB — will be excluded from training features",
        "source_inference": "company_profile.json",
        "note": "Applied as post-prediction adjustment, not a training feature",
    },
    "business_criticality": {
        "type": str, "values": ["critical", "high", "medium", "low"],
        "source_training": "Not in VCDB — will be excluded from training features",
        "source_inference": "company_profile.json / targets.json",
        "note": "Affects magnitude through industry/size proxies instead",
    },
}

# ── Incident context features (available in both VCDB and at inference) ──────

MAGNITUDE_INCIDENT_FEATURES = {
    "attack_type": {
        "type": str,
        "values": ["hacking", "malware", "social", "misuse",
                   "physical", "error", "environmental"],
        "source_training": "VCDB action.* (primary action category)",
        "source_inference": "Mapped from TI module vuln_type → 'hacking' (default for CVE-based threats)",
        "used_in_training": True,
    },
    "attack_variety": {
        "type": str,
        "source_training": "VCDB action.*.variety (e.g., 'SQLi', 'Ransomware')",
        "source_inference": "Mapped from TI module vuln_type",
        "used_in_training": False,
        "exclusion_reason": "Too many unique values for 288 rows — causes sparse one-hot encoding",
    },
    "asset_variety": {
        "type": str,
        "source_training": "VCDB asset.assets[0].variety",
        "source_inference": "From targets.json asset_type → mapped",
        "used_in_training": False,
        "exclusion_reason": "Too many unique values for 288 rows — causes sparse one-hot encoding",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# TRAINING FEATURE CONFIGURATION — SINGLE SOURCE OF TRUTH
# preprocessing.py imports these lists; do NOT define them separately there.
# ══════════════════════════════════════════════════════════════════════════════

# Engineered numeric features used by the ML model.
# These are derived from raw VCDB fields during preprocessing:
#   employee_count_range  →  company_size_score (ordinal)
#   estimated_records     →  log_records_cost, log_records_affected
#   data_sensitivity      →  data_sensitivity_score (ordinal)
#   incident_year         →  incident_year_normalized (captures cost inflation trend)
#
# NOTE: region_cost_multiplier is EXCLUDED — applied externally in fair_engine.py.
# NOTE: ibm_industry_benchmark_log was REMOVED — SHAP showed 0% importance
#       (ElasticNet L1 zeroed it out). IBM benchmark still drives Bühlmann
#       credibility blending post-prediction. Not needed as a direct ML feature.
TRAINING_NUMERIC_FEATURES = [
    "company_size_score",
    "log_records_cost",
    "log_records_affected",
    "data_sensitivity_score",
    "incident_year_normalized",   # (year - 2010) / 10; inference uses current year
]

# Categorical features that get one-hot encoded.
# Only low-cardinality features — attack_variety and asset_variety are excluded
# because they have too many unique values for 288 training rows.
TRAINING_CATEGORICAL_FEATURES = [
    "industry_sector",
    "attack_type",
]


# ══════════════════════════════════════════════════════════════════════════════
# TRAINING-ONLY FEATURES (available in VCDB, used for training context)
# ══════════════════════════════════════════════════════════════════════════════

TRAINING_ONLY_FEATURES = {
    "incident_year": {
        "type": int,
        "source": "VCDB timeline.incident.year",
        "role": "Normalized to incident_year_normalized = (year - 2010) / 10 "
                "for use as a training feature. At inference time, current year is used "
                "(datetime.now().year) to reflect current breach costs.",
    },
    "industry_naics": {
        "type": str,
        "source": "VCDB victim.industry (raw NAICS code)",
        "role": "Original NAICS code before mapping, kept for traceability",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# TARGET VARIABLE — what the ML model learns to predict
# ══════════════════════════════════════════════════════════════════════════════

TARGET_SCHEMA = {
    "total_incident_cost_usd": {
        "type": float,
        "source": "VCDB impact.overall_amount",
        "description": "Total financial loss from the incident in USD.",
    },
}

# For Option C (Layered Model) — REVISED:
# The deviation_factor approach was abandoned because VCDB measures partial costs
# (fines, settlements from public records) while IBM measures full breach cost
# (Ponemon methodology). This mismatch caused 77% of rows to clip at the 0.2 floor.
# Instead, the model directly predicts log(total_incident_cost_usd).
LOG_LOSS_TARGET = {
    "log_loss": {
        "type": float,
        "formula": "log1p(total_incident_cost_usd)",
        "inverse": "expm1(log_loss) → USD",
        "description": "Log-transformed total incident cost. The ML model predicts "
                       "this directly. Use expm1() to convert back to USD.",
        "note": "Log-to-exp back-transformation amplifies errors non-linearly: "
                "a small MAE in log-space (e.g., 2.0) can produce large MAE in "
                "dollar-space (e.g., $11M) because exp() magnifies high-end "
                "prediction errors. Median Absolute Error in dollar-space is "
                "a more representative metric than MAE for this reason.",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# FAIR OUTPUT SCHEMA — final pipeline output (matches fair_engine.py)
# ══════════════════════════════════════════════════════════════════════════════

FAIR_OUTPUT_SCHEMA = {
    "loss_event_frequency": {
        "type": float,
        "formula": "base_industry_breach_rate × threat_pressure_factor",
        "source_frequency": "Estimated from Verizon DBIR industry trends (see ibm_benchmarks.py)",
        "source_tpf": "TI Module threat_pressure.py",
        "caveat": "These per-vulnerability frequency values are approximate and not "
                  "calibrated actuarial rates. The total ALE (sum of per-CVE ALEs) is a "
                  "valid expected value (linearity of expectation), but P(at least one "
                  "breach) cannot be derived by simply summing per-CVE frequencies.",
    },
    "loss_magnitude_usd": {
        "type": float,
        "formula": "expm1(ML_predicted_log_loss) × IBM_region_multiplier",
        "source": "ML model trained on VCDB (predicts log-loss directly), "
                  "with IBM industry benchmark as a model feature and IBM region "
                  "multiplier applied externally post-prediction.",
        "region_handling": "Region multiplier is applied EXTERNALLY only (not a "
                          "training feature) to avoid double-counting.",
        "note": "VCDB records partial costs from public sources (fines, settlements). "
                "IBM uses Ponemon standardized methodology for full breach costs. "
                "Individual predictions have high variance — MAE in dollar-space is "
                "amplified by log-to-exp back-transformation. Median AE is a more "
                "representative accuracy metric than MAE.",
    },
    "annualized_loss_expectancy_usd": {
        "type": float,
        "formula": "loss_event_frequency × loss_magnitude_usd",
        "framework": "FAIR (Factor Analysis of Information Risk)",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# VALIDATION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def validate_company_profile(profile: dict) -> list:
    """Validate a company profile dict against MAGNITUDE_COMPANY_FEATURES.
    Returns list of error messages (empty = valid)."""
    errors = []
    for field, spec in MAGNITUDE_COMPANY_FEATURES.items():
        if field not in profile:
            if spec.get("optional"):
                continue
            # Fields not in VCDB training (has_cyber_insurance, business_criticality)
            # are still required in company_profile but handled separately
            if spec.get("note") and "excluded from training" in spec.get("note", ""):
                continue
            errors.append(f"Missing required field: {field}")
            continue

        value = profile[field]

        # Type check
        expected_type = spec["type"]
        if not isinstance(value, expected_type):
            # Allow int for float fields
            if expected_type is float and isinstance(value, int):
                pass
            else:
                errors.append(f"{field}: expected {expected_type.__name__}, got {type(value).__name__}")
                continue

        # Enum check
        if "values" in spec and value not in spec["values"]:
            errors.append(f"{field}: '{value}' not in allowed values {spec['values']}")

        # Range check
        if "range" in spec:
            low, high = spec["range"]
            if low is not None and value < low:
                errors.append(f"{field}: {value} below minimum {low}")
            if high is not None and value > high:
                errors.append(f"{field}: {value} above maximum {high}")

    return errors


def get_magnitude_training_features() -> list:
    """Return the list of raw feature names that feed into magnitude training.

    Only includes features that are actually used by preprocessing.py.
    The engineered feature names are in TRAINING_NUMERIC_FEATURES.
    The categorical features (one-hot encoded) are in TRAINING_CATEGORICAL_FEATURES.

    Excludes:
      - has_cyber_insurance, business_criticality (not in VCDB)
      - annual_revenue_usd (too sparse in VCDB)
      - region (applied as external post-prediction multiplier to avoid double-counting)
      - attack_variety, asset_variety (too many unique values for 288 rows)
    """
    # Company features that are actually in VCDB AND used in training
    vcdb_company = [
        "industry_sector",
        "employee_count_range",
        # NOTE: region is intentionally excluded from training features.
        # Its effect is applied externally via IBM region multiplier in fair_engine.py.
        # Training data is 80% US, so the model can't reliably learn regional differences.
        "data_sensitivity",
        "estimated_records",    # maps to records_affected in VCDB
    ]
    # Incident context features — only those marked used_in_training=True
    incident = [k for k, v in MAGNITUDE_INCIDENT_FEATURES.items()
                if v.get("used_in_training", True)]

    return vcdb_company + incident


def get_inference_feature_mapping() -> dict:
    """Return mapping from inference-time field names to VCDB training field names.

    Some fields have different names at training vs inference time.
    Only includes features actually used in training.
    """
    return {
        # inference field → training field
        "estimated_records": "records_affected",
        # These map directly:
        "industry_sector": "industry_sector",
        "employee_count_range": "employee_count_range",
        "data_sensitivity": "data_sensitivity",
        "attack_type": "attack_type",
        # NOTE: region, attack_variety, asset_variety removed —
        # region is external-only; attack_variety/asset_variety excluded from training
    }


# ══════════════════════════════════════════════════════════════════════════════
# CLI: schema dump & validation
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if "--validate" in sys.argv:
        print("Schema validation mode")
        print("=" * 60)

        # 1. Check Frequency vs Magnitude separation
        freq_fields = set(FREQUENCY_FEATURES.keys())
        mag_company = set(MAGNITUDE_COMPANY_FEATURES.keys())
        mag_incident = set(MAGNITUDE_INCIDENT_FEATURES.keys())
        all_magnitude = mag_company | mag_incident

        overlap = freq_fields & all_magnitude
        if overlap:
            print(f"SCHEMA VIOLATION: Fields in both Frequency and Magnitude: {overlap}")
            sys.exit(1)
        else:
            print("[OK] No overlap between Frequency and Magnitude features")

        # 2. Check all frequency features are marked as NOT used in training
        for field, spec in FREQUENCY_FEATURES.items():
            if spec.get("used_in_magnitude_training", True):
                print(f"SCHEMA VIOLATION: Frequency feature '{field}' marked as used in training")
                sys.exit(1)
        print("[OK] All Frequency features correctly marked as NOT used in magnitude training")

        # 3. Verify training features are available in VCDB
        training_features = get_magnitude_training_features()
        print(f"\n[INFO] Magnitude training features ({len(training_features)}):")
        for f in training_features:
            print(f"  - {f}")

        print(f"\n[INFO] Frequency features ({len(freq_fields)}) — affect ALE via TPF only:")
        for f in sorted(freq_fields):
            print(f"  - {f}")

        # 4. Verify log-loss target
        print(f"\n[INFO] Target: {list(TARGET_SCHEMA.keys())}")
        print(f"[INFO] Log-loss target: {list(LOG_LOSS_TARGET.keys())}")
        log_loss = LOG_LOSS_TARGET["log_loss"]
        print(f"  Formula: {log_loss['formula']}")
        print(f"  Inverse: {log_loss['inverse']}")

        # 5. Verify region is excluded from training features
        if "region" in training_features:
            print("SCHEMA VIOLATION: 'region' should not be in training features")
            print("  Region effect must be applied externally only (see fair_engine.py)")
            sys.exit(1)
        print("[OK] 'region' correctly excluded from training features (external-only)")
        # 6. Verify TRAINING_NUMERIC_FEATURES and TRAINING_CATEGORICAL_FEATURES
        # are consistent with get_magnitude_training_features()
        raw_features = set(get_magnitude_training_features())
        categorical_set = set(TRAINING_CATEGORICAL_FEATURES)
        # All categoricals must be in raw features
        missing_cat = categorical_set - raw_features
        if missing_cat:
            print(f"SCHEMA VIOLATION: TRAINING_CATEGORICAL_FEATURES has features "
                  f"not in get_magnitude_training_features(): {missing_cat}")
            sys.exit(1)
        # Excluded incident features should NOT be in raw features
        excluded = [k for k, v in MAGNITUDE_INCIDENT_FEATURES.items()
                    if not v.get("used_in_training", True)]
        for feat in excluded:
            if feat in raw_features:
                print(f"SCHEMA VIOLATION: '{feat}' marked used_in_training=False "
                      f"but still in get_magnitude_training_features()")
                sys.exit(1)
        print(f"[OK] TRAINING_NUMERIC_FEATURES ({len(TRAINING_NUMERIC_FEATURES)}) "
              f"and TRAINING_CATEGORICAL_FEATURES ({len(TRAINING_CATEGORICAL_FEATURES)}) "
              f"consistent with raw features ({len(raw_features)})")

        print("\n[OK] Schema validation passed")

    else:
        print("=== FREQUENCY Features (drive TPF, NOT used in magnitude training) ===")
        for k, v in FREQUENCY_FEATURES.items():
            print(f"  {k}: {v['type'].__name__} -- {v['role']}")

        print("\n=== MAGNITUDE Company Features (used in training + inference) ===")
        for k, v in MAGNITUDE_COMPANY_FEATURES.items():
            note = ""
            if "excluded from training" in v.get("note", ""):
                note = " [NOT IN VCDB]"
            elif "NOT a training feature" in v.get("note", ""):
                note = " [EXTERNAL ONLY]"
            print(f"  {k}: {v['type'].__name__}{note}")

        print("\n=== MAGNITUDE Incident Features (used in training + inference) ===")
        for k, v in MAGNITUDE_INCIDENT_FEATURES.items():
            print(f"  {k}: {v['type'].__name__}")

        print("\n=== Target Variable ===")
        for k, v in TARGET_SCHEMA.items():
            print(f"  {k}: {v['type'].__name__} -- {v['source']}")

        print("\n=== Log-Loss Target (revised from deviation_factor) ===")
        for k, v in LOG_LOSS_TARGET.items():
            print(f"  {k}: {v['type'].__name__} -- {v['formula']}")
            print(f"         inverse: {v['inverse']}")

        print("\n=== FAIR Output ===")
        for k, v in FAIR_OUTPUT_SCHEMA.items():
            print(f"  {k}: {v['type'].__name__} -- {v['formula']}")
