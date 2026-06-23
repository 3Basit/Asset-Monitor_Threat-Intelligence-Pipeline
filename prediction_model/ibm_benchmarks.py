"""
ibm_benchmarks.py — Phase 1: IBM Cost of a Data Breach Report 2025 Lookup Tables
=================================================================================
Source: IBM Security & Ponemon Institute, "Cost of a Data Breach Report 2025"
        https://www.ibm.com/reports/data-breach

All dollar amounts are from the published report. These are static benchmarks
that need manual annual updates when a new report is released.

Pattern: Same as CWE_NAMES in nvd_fetch.py — hardcoded lookup dict.
"""

# ─── Industry → Average breach cost (USD) ─────────────────────────────────────
# Source: IBM Cost of a Data Breach 2025, Figure "Average cost of a data breach by industry"

IBM_INDUSTRY_COST = {
    "healthcare":             7_420_000,
    "financial":              5_560_000,
    "industrial":             5_000_000,
    "energy":                 4_830_000,
    "technology":             4_790_000,
    "pharmaceuticals":        4_610_000,
    "professional_services":  4_550_000,
    "transportation":         4_420_000,
    "entertainment":          4_090_000,
    "education":              3_980_000,
    "communication":          3_900_000,
    "consumer":               3_820_000,
    "retail":                 3_480_000,
    "media":                  3_390_000,
    "hospitality":            3_260_000,
    "research":               3_250_000,
    "public_sector":          2_670_000,
    # Fallback
    "global_average":         4_440_000,
}


# ─── Data type → Cost per record (USD) ────────────────────────────────────────
# Source: IBM Cost of a Data Breach 2025, "Per-record cost by type of data compromised"

IBM_PER_RECORD_COST = {
    "ip":                     178,
    "corporate":              171,
    "anonymized_customer":    162,
    "customer_pii":           158,
    "employee_pii":           154,
    # Fallback
    "unknown":                160,   # approximate global average per record
}


# ─── Region → Average breach cost (USD) ───────────────────────────────────────
# Source: IBM Cost of a Data Breach 2025, "Average cost by country/region"

IBM_REGION_COST = {
    "US":             9_360_000,
    "Middle_East":    8_750_000,
    "Germany":        4_850_000,
    "Canada":         4_660_000,
    "Japan":          4_570_000,
    "UK":             4_400_000,
    "Italy":          4_180_000,
    "France":         4_150_000,
    "South_Korea":    3_520_000,
    "Australia":      3_400_000,
    "ASEAN":          3_180_000,
    "Latin_America":  2_760_000,
    "India":          2_350_000,
    "South_Africa":   2_150_000,
    # Aggregate
    "EU":             4_180_000,   # approximate EU average (Italy as proxy)
    "global_average": 4_440_000,
}


# ─── Attack vector → Average cost (USD) ───────────────────────────────────────
# Source: IBM Cost of a Data Breach 2025, "Average cost by initial attack vector"

IBM_ATTACK_VECTOR_COST = {
    "malicious_insider":          4_990_000,
    "business_email_compromise":  4_890_000,
    "phishing":                   4_800_000,
    "social_engineering":         4_770_000,
    "stolen_credentials":         4_660_000,
    "zero_day":                   4_580_000,
    "known_vulnerability":        4_560_000,
    "accidental_data_loss":       4_280_000,
    "cloud_misconfiguration":     4_190_000,
    "system_error":               3_880_000,
    # Fallback
    "unknown":                    4_440_000,
}


# ─── Base industry breach probability (annual) ────────────────────────────────
# [!] IMPORTANT: These are ESTIMATED / DERIVED values, NOT direct quotes.
# They are informed by Verizon DBIR 2024/2025 breach frequency trends per
# industry sector, normalized to approximate annual probability for a
# mid-sized organization. They should be treated as order-of-magnitude
# estimates, not precise actuarial rates.
#
# Methodology: DBIR reports the relative share of breaches per industry.
# We combine that with Cyentia IRIS estimates of overall breach frequency
# to derive per-industry annual probability estimates.
#
# Source basis: Verizon DBIR 2024/2025 industry trends + Cyentia IRIS 20/20

BASE_BREACH_RATE = {
    "healthcare":             0.35,
    "financial":              0.30,
    "technology":             0.28,
    "public_sector":          0.27,
    "education":              0.25,
    "retail":                 0.22,
    "professional_services":  0.20,
    "energy":                 0.20,
    "industrial":             0.18,
    "pharmaceuticals":        0.18,
    "communication":          0.18,
    "hospitality":            0.17,
    "transportation":         0.16,
    "entertainment":          0.15,
    "consumer":               0.15,
    "research":               0.15,
    "media":                  0.14,
    # Fallback
    "global_average":         0.22,
}


# ─── Cost amplification / reduction factors ────────────────────────────────────
# Source: IBM Cost of a Data Breach 2025, "Cost factors"

COST_AMPLIFIERS = {
    "compliance_failures":        1_680_000,    # +$1.68M
    "breach_lifecycle_over_200d": 1_280_000,    # +$1.28M
    "supply_chain_breach":          920_000,    # +$0.92M
}

COST_REDUCERS = {
    "security_ai_automation":    -2_220_000,    # -$2.22M savings
    "incident_response_plan":    -1_490_000,    # -$1.49M
    "employee_training":         -1_180_000,    # -$1.18M
    "cyber_insurance":             -750_000,    # estimated from report trends
}


# ─── Helper functions ─────────────────────────────────────────────────────────

def get_industry_cost(industry: str) -> int:
    """Get IBM benchmark cost for an industry. Falls back to global average."""
    return IBM_INDUSTRY_COST.get(industry, IBM_INDUSTRY_COST["global_average"])


def get_region_cost(region: str) -> int:
    """Get IBM benchmark cost for a region. Falls back to global average."""
    return IBM_REGION_COST.get(region, IBM_REGION_COST["global_average"])


def get_per_record_cost(data_sensitivity: str) -> int:
    """Get per-record cost by data type. Falls back to unknown."""
    return IBM_PER_RECORD_COST.get(data_sensitivity, IBM_PER_RECORD_COST["unknown"])


def get_breach_rate(industry: str) -> float:
    """Get estimated annual breach rate for an industry. Falls back to global average."""
    return BASE_BREACH_RATE.get(industry, BASE_BREACH_RATE["global_average"])


def get_region_multiplier(region: str) -> float:
    """
    Get a multiplier based on region cost vs global average.
    US = 9.36M / 4.44M ~ 2.11 (breaches cost 2x the global average in US)
    India = 2.35M / 4.44M ~ 0.53 (breaches cost half in India)
    """
    region_cost = get_region_cost(region)
    global_avg = IBM_REGION_COST["global_average"]
    return round(region_cost / global_avg, 4)


# ─── CLI: dump tables ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("IBM Cost of a Data Breach Report 2025 — Lookup Tables")
    print("=" * 70)

    print("\n[*] Industry → Average Breach Cost (USD)")
    print("-" * 45)
    for k, v in sorted(IBM_INDUSTRY_COST.items(), key=lambda x: -x[1]):
        print(f"  {k:<25s} ${v:>12,}")

    print(f"\n[*] Data Sensitivity → Per-Record Cost (USD)")
    print("-" * 45)
    for k, v in sorted(IBM_PER_RECORD_COST.items(), key=lambda x: -x[1]):
        print(f"  {k:<25s} ${v:>6,}")

    print(f"\n[*] Region → Average Breach Cost (USD)")
    print("-" * 45)
    for k, v in sorted(IBM_REGION_COST.items(), key=lambda x: -x[1]):
        mult = get_region_multiplier(k)
        print(f"  {k:<25s} ${v:>12,}  (×{mult:.2f})")

    print(f"\n[*] Attack Vector → Average Cost (USD)")
    print("-" * 45)
    for k, v in sorted(IBM_ATTACK_VECTOR_COST.items(), key=lambda x: -x[1]):
        print(f"  {k:<30s} ${v:>12,}")

    print(f"\n[*] Base Breach Rate (Annual, ESTIMATED)")
    print("-" * 45)
    for k, v in sorted(BASE_BREACH_RATE.items(), key=lambda x: -x[1]):
        print(f"  {k:<25s} {v:.0%}")
