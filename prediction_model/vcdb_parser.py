"""
vcdb_parser.py — Phase 1: VERIS Community Database Parser
==========================================================
Parses VCDB JSON incident files into a structured pandas DataFrame
for ML model training.

Source: https://github.com/vz-risk/VCDB
Each JSON file = one real-world security incident with VERIS schema.

Usage:
    python -m prediction_model.vcdb_parser --stats
    python -m prediction_model.vcdb_parser --preview 5
"""

import json
import os
import sys
from datetime import datetime

# ─── NAICS Code → Simplified Industry Category ────────────────────────────────
# Maps 2-digit NAICS sector codes to our industry categories
# (must align with IBM_INDUSTRY_COST keys in ibm_benchmarks.py)

NAICS_TO_INDUSTRY = {
    "11": "consumer",               # Agriculture → Consumer
    "21": "energy",                 # Mining → Energy
    "22": "energy",                 # Utilities → Energy
    "23": "industrial",             # Construction → Industrial
    "31": "industrial",             # Manufacturing
    "32": "industrial",             # Manufacturing
    "33": "industrial",             # Manufacturing
    "42": "retail",                 # Wholesale Trade → Retail
    "44": "retail",                 # Retail Trade
    "45": "retail",                 # Retail Trade
    "48": "transportation",         # Transportation
    "49": "transportation",         # Warehousing → Transportation
    "51": "technology",             # Information / Tech
    "52": "financial",              # Finance and Insurance
    "53": "professional_services",  # Real Estate
    "54": "professional_services",  # Professional/Technical
    "55": "financial",              # Management of Companies → Financial
    "56": "professional_services",  # Administrative
    "61": "education",              # Educational Services
    "62": "healthcare",             # Health Care
    "71": "entertainment",          # Arts/Entertainment
    "72": "hospitality",            # Accommodation/Food
    "81": "consumer",               # Other Services
    "92": "public_sector",          # Public Administration
}

# ─── Country → Region mapping ─────────────────────────────────────────────────
# Maps ISO country codes to our region categories
# (must align with IBM_REGION_COST keys in ibm_benchmarks.py)

COUNTRY_TO_REGION = {
    "US": "US",
    "CA": "Canada",
    "GB": "UK", "UK": "UK",
    "DE": "Germany",
    "FR": "France",
    "IT": "Italy",
    "JP": "Japan",
    "KR": "South_Korea",
    "AU": "Australia",
    "IN": "India",
    "ZA": "South_Africa",
    "BR": "Latin_America", "MX": "Latin_America", "AR": "Latin_America",
    "CO": "Latin_America", "CL": "Latin_America", "PE": "Latin_America",
    "SA": "Middle_East", "AE": "Middle_East", "QA": "Middle_East",
    "KW": "Middle_East", "BH": "Middle_East", "OM": "Middle_East",
    "IL": "Middle_East", "EG": "Middle_East", "JO": "Middle_East",
    "SG": "ASEAN", "MY": "ASEAN", "TH": "ASEAN", "ID": "ASEAN",
    "PH": "ASEAN", "VN": "ASEAN",
    # EU countries not explicitly listed above
    "NL": "EU", "BE": "EU", "ES": "EU", "PT": "EU", "AT": "EU",
    "SE": "EU", "NO": "EU", "DK": "EU", "FI": "EU", "IE": "EU",
    "PL": "EU", "CZ": "EU", "RO": "EU", "HU": "EU", "GR": "EU",
    "BG": "EU", "HR": "EU", "SK": "EU", "SI": "EU", "LT": "EU",
    "LV": "EU", "EE": "EU", "LU": "EU", "MT": "EU", "CY": "EU",
}

# ─── Employee count → ordinal score ───────────────────────────────────────────

EMPLOYEE_COUNT_SCORE = {
    "1 to 10":          1,
    "11 to 100":        2,
    "101 to 1000":      3,
    "Small":            3,      # VERIS uses "Small" for <=1000
    "1001 to 10000":    4,
    "10001 to 25000":   5,
    "25001 to 50000":   6,
    "50001 to 100000":  7,
    "Over 100000":      8,
    "Large":            6,      # VERIS uses "Large" for >1000
    "Unknown":          4,      # median as default
}

# ─── VERIS data variety → data sensitivity mapping ────────────────────────────

DATA_VARIETY_TO_SENSITIVITY = {
    "Credentials":          "customer_pii",
    "Personal":             "customer_pii",
    "Medical":              "customer_pii",
    "Payment":              "customer_pii",
    "Bank":                 "customer_pii",
    "Internal":             "corporate",
    "Classified":           "corporate",
    "System":               "corporate",
    "Secrets":              "ip",
    "Source code":           "ip",
    "Digital certificate":   "corporate",
    "Virtual currency":      "corporate",
    "Copyrighted":           "ip",
    "Unknown":              "unknown",
}


def _safe_get(d: dict, *keys, default=None):
    """Safely traverse nested dict keys."""
    current = d
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current


def _get_primary_action(incident: dict) -> tuple:
    """Extract the primary action category, variety, and vector from an incident.

    VERIS incidents can have multiple action categories (hacking, malware, etc.).
    We pick the "most severe" one based on a priority order.

    Returns: (action_type, action_variety, action_vector)
    """
    action = incident.get("action", {})
    # Priority order: hacking > malware > social > misuse > error > physical > environmental
    priority = ["hacking", "malware", "social", "misuse", "error", "physical", "environmental"]

    for action_type in priority:
        if action_type in action and action[action_type]:
            action_data = action[action_type]
            variety_list = action_data.get("variety", [])
            vector_list = action_data.get("vector", [])
            variety = variety_list[0] if variety_list else "Unknown"
            vector = vector_list[0] if vector_list else "Unknown"
            return action_type, variety, vector

    return "unknown", "Unknown", "Unknown"


def _map_industry(naics_code: str) -> str:
    """Map NAICS code to simplified industry category."""
    if not naics_code or naics_code == "Unknown":
        return "unknown"
    # Try 2-digit prefix
    prefix = str(naics_code)[:2]
    return NAICS_TO_INDUSTRY.get(prefix, "unknown")


def _map_region(country_list) -> str:
    """Map country code(s) to region. Uses first country if list."""
    if not country_list:
        return "unknown"
    if isinstance(country_list, list):
        country = country_list[0] if country_list else "unknown"
    else:
        country = str(country_list)
    return COUNTRY_TO_REGION.get(country, "unknown")


def _get_primary_data_variety(incident: dict) -> tuple:
    """Extract primary data variety and total records from confidentiality attribute.

    Returns: (data_variety, records_affected)
    """
    conf = _safe_get(incident, "attribute", "confidentiality", default={})

    # Records affected
    records = conf.get("data_total")
    if records is None:
        # Try summing individual data entries
        data_entries = conf.get("data", [])
        if data_entries:
            amounts = [d.get("amount", 0) for d in data_entries if isinstance(d.get("amount"), (int, float))]
            records = sum(amounts) if amounts else None

    # Data variety
    data_entries = conf.get("data", [])
    if data_entries:
        # Pick the first variety
        variety = data_entries[0].get("variety", "Unknown") if data_entries else "Unknown"
    else:
        variety = "Unknown"

    sensitivity = DATA_VARIETY_TO_SENSITIVITY.get(variety, "unknown")

    return sensitivity, records


def _get_asset_variety(incident: dict) -> str:
    """Extract primary asset variety from incident."""
    assets = _safe_get(incident, "asset", "assets", default=[])
    if assets and isinstance(assets, list) and len(assets) > 0:
        return assets[0].get("variety", "Unknown")
    return "Unknown"


def parse_single_incident(filepath: str) -> dict | None:
    """Parse a single VCDB JSON incident file.

    Returns a flat dict with extracted features, or None if the incident
    should be skipped (missing critical data).
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            incident = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    # ── Extract loss data (target variable) ──
    impact = incident.get("impact", {})
    total_loss = impact.get("overall_amount")

    # Try to sum individual losses if overall not available
    if total_loss is None:
        loss_entries = impact.get("loss", [])
        if loss_entries:
            amounts = [
                entry.get("amount", 0)
                for entry in loss_entries
                if isinstance(entry.get("amount"), (int, float)) and entry.get("amount", 0) > 0
            ]
            total_loss = sum(amounts) if amounts else None

    # ── Extract victim info ──
    victim = incident.get("victim", {})
    industry_raw = victim.get("industry", "Unknown")
    industry = _map_industry(industry_raw)
    employee_count = victim.get("employee_count", "Unknown")
    country_list = victim.get("country", [])
    region = _map_region(country_list)

    # ── Extract action info ──
    action_type, action_variety, action_vector = _get_primary_action(incident)

    # ── Extract data info ──
    data_sensitivity, records_affected = _get_primary_data_variety(incident)

    # ── Extract asset info ──
    asset_variety = _get_asset_variety(incident)

    # ── Extract timeline ──
    timeline = incident.get("timeline", {})
    incident_time = timeline.get("incident", {})
    incident_year = incident_time.get("year")

    # ── Build result ──
    return {
        "incident_id": incident.get("incident_id", os.path.basename(filepath)),
        "industry_sector": industry,
        "industry_naics": str(industry_raw),
        "employee_count_range": employee_count,
        "company_size_score": EMPLOYEE_COUNT_SCORE.get(employee_count, 4),
        "region": region,
        "attack_type": action_type,
        "attack_variety": action_variety,
        "attack_vector": action_vector,
        "asset_variety": asset_variety,
        "data_sensitivity": data_sensitivity,
        "records_affected": records_affected,
        "incident_year": incident_year,
        "total_incident_cost_usd": total_loss,
        "has_loss_data": total_loss is not None and total_loss > 0,
    }


def parse_vcdb(vcdb_dir: str = "data/vcdb/data/json/validated") -> list:
    """Parse all VCDB JSON files from the validated directory.

    Args:
        vcdb_dir: Path to VCDB's data/json/validated/ directory

    Returns:
        List of parsed incident dicts
    """
    if not os.path.exists(vcdb_dir):
        # Try alternate paths
        alt_paths = [
            os.path.join("data", "vcdb", "data", "json", "validated"),
            os.path.join("..", "VCDB", "data", "json", "validated"),
        ]
        for alt in alt_paths:
            if os.path.exists(alt):
                vcdb_dir = alt
                break
        else:
            raise FileNotFoundError(
                f"VCDB data directory not found: {vcdb_dir}\n"
                f"Clone it first: git clone https://github.com/vz-risk/VCDB.git data/vcdb"
            )

    incidents = []
    skipped = 0
    errors = 0

    json_files = [
        f for f in os.listdir(vcdb_dir)
        if f.endswith(".json")
    ]

    print(f"Found {len(json_files)} JSON files in {vcdb_dir}")

    for filename in json_files:
        filepath = os.path.join(vcdb_dir, filename)
        result = parse_single_incident(filepath)
        if result is None:
            errors += 1
        else:
            incidents.append(result)

    print(f"Parsed: {len(incidents)} incidents")
    print(f"Parse errors: {errors}")

    return incidents


def get_training_data(vcdb_dir: str = "data/vcdb/data/json/validated"):
    """Parse VCDB and return only incidents with loss data, as a pandas DataFrame.

    This is the main entry point for Phase 2 (preprocessing).
    """
    import pandas as pd

    incidents = parse_vcdb(vcdb_dir)

    # Separate: with loss data vs without
    with_loss = [i for i in incidents if i["has_loss_data"]]
    without_loss = [i for i in incidents if not i["has_loss_data"]]

    print(f"\n[INFO] Dataset Summary:")
    print(f"   Total incidents: {len(incidents)}")
    print(f"   With loss data:  {len(with_loss)} ({len(with_loss)/len(incidents)*100:.1f}%)")
    print(f"   Without loss:    {len(without_loss)}")

    df = pd.DataFrame(with_loss)

    # Drop helper column
    df = df.drop(columns=["has_loss_data"])

    # Basic type cleanup
    df["total_incident_cost_usd"] = df["total_incident_cost_usd"].astype(float)
    df["records_affected"] = pd.to_numeric(df["records_affected"], errors="coerce")
    df["incident_year"] = pd.to_numeric(df["incident_year"], errors="coerce")

    return df


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import pandas as pd

    vcdb_dir = "data/vcdb/data/json/validated"

    if "--stats" in sys.argv:
        print("=" * 70)
        print("VCDB Data Collection — Statistics Report")
        print("=" * 70)

        incidents = parse_vcdb(vcdb_dir)

        with_loss = [i for i in incidents if i["has_loss_data"]]
        without_loss = [i for i in incidents if not i["has_loss_data"]]

        print(f"\n[INFO] Total incidents parsed:      {len(incidents)}")
        print(f"[INFO] Incidents WITH loss data:    {len(with_loss)}")
        print(f"[INFO] Incidents WITHOUT loss data: {len(without_loss)}")

        if with_loss:
            df = pd.DataFrame(with_loss)
            print(f"\n[INFO] Loss data statistics:")
            print(f"   Min loss:    ${df['total_incident_cost_usd'].min():,.0f}")
            print(f"   Max loss:    ${df['total_incident_cost_usd'].max():,.0f}")
            print(f"   Mean loss:   ${df['total_incident_cost_usd'].mean():,.0f}")
            print(f"   Median loss: ${df['total_incident_cost_usd'].median():,.0f}")

            print(f"\n[INFO] Industries represented:")
            for ind, count in df["industry_sector"].value_counts().items():
                print(f"   {ind:<25s} {count}")

            print(f"\n[INFO] Attack types:")
            for at, count in df["attack_type"].value_counts().items():
                print(f"   {at:<25s} {count}")

            print(f"\n[INFO] Regions:")
            for reg, count in df["region"].value_counts().items():
                print(f"   {reg:<25s} {count}")

    elif "--preview" in sys.argv:
        n = 5
        try:
            idx = sys.argv.index("--preview")
            if idx + 1 < len(sys.argv):
                n = int(sys.argv[idx + 1])
        except (ValueError, IndexError):
            pass

        df = get_training_data(vcdb_dir)

        print(f"\n[INFO] First {n} rows of training data:")
        print("=" * 70)
        pd.set_option("display.max_columns", None)
        pd.set_option("display.width", None)
        pd.set_option("display.max_colwidth", 30)
        print(df.head(n).to_string(index=False))

        print(f"\n[INFO] Dataset shape: {df.shape}")
        print(f"[INFO] Columns: {list(df.columns)}")

    else:
        print("Usage:")
        print("  python -m prediction_model.vcdb_parser --stats")
        print("  python -m prediction_model.vcdb_parser --preview [N]")
