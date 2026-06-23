"""
company_profile.py — Company Risk Profile Loader & Validator
=============================================================
Loads and validates company_profile.json.
Same philosophy as targets.json — simple JSON file, user fills it in.
"""

import json
import os
from prediction_model.schema import validate_company_profile, MAGNITUDE_COMPANY_FEATURES


def load_company_profile(filepath: str = "company_profile.json") -> dict:
    """Load and validate a company profile from JSON file.

    Args:
        filepath: Path to company_profile.json

    Returns:
        Validated company profile dict

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If validation fails
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"Company profile not found: {filepath}\n"
            f"Create a company_profile.json with these fields:\n"
            f"  {list(MAGNITUDE_COMPANY_FEATURES.keys())}"
        )

    with open(filepath, "r", encoding="utf-8") as f:
        profile = json.load(f)

    errors = validate_company_profile(profile)
    if errors:
        raise ValueError(
            f"Company profile validation failed:\n" +
            "\n".join(f"  [ERROR] {e}" for e in errors)
        )

    return profile


def get_company_features(profile: dict) -> dict:
    """Extract only the features needed for prediction from a company profile.

    Returns a clean dict with only the schema-defined company features.
    """
    features = {}
    for field in MAGNITUDE_COMPANY_FEATURES:
        if field in profile:
            features[field] = profile[field]
    return features


if __name__ == "__main__":
    import sys

    filepath = sys.argv[1] if len(sys.argv) > 1 else "company_profile.json"
    try:
        profile = load_company_profile(filepath)
        print(f"[OK] Company profile loaded: {profile.get('company_name', 'Unknown')}")
        print(f"   Industry: {profile.get('industry_sector')}")
        print(f"   Region: {profile.get('region')}")
        print(f"   Employees: {profile.get('employee_count_range')}")
        print(f"   Records at risk: {profile.get('estimated_records'):,}")
        print(f"   Data sensitivity: {profile.get('data_sensitivity')}")
        print(f"   Cyber insurance: {profile.get('has_cyber_insurance')}")
    except (FileNotFoundError, ValueError) as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
