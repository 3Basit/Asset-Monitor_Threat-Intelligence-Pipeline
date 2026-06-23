"""
fair_engine.py — Phase 4: FAIR Integration Engine
====================================================
Combines TI module output (frequency) with ML predictions (magnitude)
to calculate Annualized Loss Expectancy (ALE).

FAIR Formula:
  ALE = Loss Event Frequency × Loss Magnitude
      = (base_breach_rate × TPF) × ML_predicted_loss

Pipeline:
  1. Load threat_intelligence_output.json (TI module)
  2. Load company_profile.json (user input)
  3. Load trained ML model
  4. For each vulnerability:
     a. Frequency = base_breach_rate[industry] × TPF
     b. Magnitude = exp(ML.predict(features)) - 1
     c. Apply adjustments: region, insurance, bounds
     d. ALE = Frequency × Magnitude
"""

import json
import os
import warnings
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd

from prediction_model.ibm_benchmarks import (
    BASE_BREACH_RATE,
    COST_REDUCERS,
    IBM_INDUSTRY_COST,
    get_breach_rate,
    get_industry_cost,
    get_per_record_cost,
    get_region_multiplier,
)
from prediction_model.vcdb_parser import EMPLOYEE_COUNT_SCORE

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ─── Bounds ───────────────────────────────────────────────────────────────────
MIN_MAGNITUDE_USD = 10_000        # $10K minimum predicted loss
MAX_MAGNITUDE_USD = 50_000_000    # $50M maximum predicted loss
CREDIBILITY_K = 20                # Bühlmann constant: ~20 samples = 50% trust in model


def credibility_weight(n_industry_samples: int, k: int = CREDIBILITY_K) -> float:
    """Bühlmann credibility factor.

    Z = N / (N + K)
    More VCDB samples for this industry → trust the ML model more.
    Fewer samples → fall back toward the IBM industry benchmark.

    Reference: Bühlmann, H. (1967). Experience Rating and Credibility. ASTIN Bulletin.
    """
    return n_industry_samples / (n_industry_samples + k)


# ─── Mapping helpers (TI output → model features) ────────────────────────────

# Map TI module vuln_type to VCDB-style attack_type/variety
VULN_TYPE_TO_ATTACK = {
    "rce":            ("hacking", "Use of backdoor or C2"),
    "sqli":           ("hacking", "SQLi"),
    "path_traversal": ("hacking", "Path traversal"),
    "auth_bypass":    ("hacking", "Use of stolen creds"),
    "ssrf":           ("hacking", "Abuse of functionality"),
    "xss":            ("hacking", "XSS"),
    "other":          ("hacking", "Unknown"),
    "unknown":        ("hacking", "Unknown"),
}

# Map TI module asset_type to VCDB-style asset_variety
ASSET_TYPE_TO_VARIETY = {
    "web_application": "S - Web application",
    "database":        "S - Database",
    "server":          "S - Other",
    "network":         "N - Router",
    "endpoint":        "U - Desktop",
    "other":           "S - Other",
}


def classify_risk_tier(ale: float) -> str:
    """Classify ALE into risk tiers."""
    if ale > 2_000_000:
        return "CRITICAL"
    elif ale > 500_000:
        return "HIGH"
    elif ale > 100_000:
        return "MEDIUM"
    else:
        return "LOW"


def _build_feature_vector(vuln: dict, company: dict, feature_names: list) -> pd.DataFrame:
    """Build a feature vector for the ML model from vulnerability + company data.

    Maps inference-time field names to the same feature names used during training.
    """
    # Determine attack mapping from vuln_type
    vuln_type = vuln.get("vuln_type", "unknown")
    attack_type, attack_variety = VULN_TYPE_TO_ATTACK.get(
        vuln_type, ("hacking", "Unknown")
    )

    # Determine asset variety
    asset_type = vuln.get("asset_type", company.get("asset_type", "web_application"))
    asset_variety = ASSET_TYPE_TO_VARIETY.get(asset_type, "S - Web application")

    # Build raw features dict
    # NOTE: region_cost_multiplier is NOT included here — it is applied
    # as a post-prediction external adjustment only, to avoid double-counting.
    # NOTE: ibm_industry_benchmark_log is NOT included — SHAP showed 0% importance;
    # IBM benchmark is used only via Bühlmann credibility blending post-prediction.
    inference_year = datetime.now().year
    raw = {
        "company_size_score": EMPLOYEE_COUNT_SCORE.get(
            company.get("employee_count_range", "Unknown"), 4
        ),
        "log_records_cost": np.log1p(
            company.get("estimated_records", 0)
            * get_per_record_cost(company.get("data_sensitivity", "unknown"))
        ),
        "log_records_affected": np.log1p(
            company.get("estimated_records", 0)
        ),
        "data_sensitivity_score": {
            "ip": 5, "corporate": 4, "customer_pii": 3,
            "anonymized_customer": 2, "employee_pii": 2, "unknown": 1,
        }.get(company.get("data_sensitivity", "unknown"), 1),
        "incident_year_normalized": (inference_year - 2010) / 10.0,
    }

    # Build one-hot features (initialize all to 0)
    feature_dict = {}
    company_industry = company.get("industry_sector", "")
    industry_in_training = any(
        fname == f"industry_sector_{company_industry}"
        for fname in feature_names
    )
    if not industry_in_training and company_industry:
        # Industry exists in IBM benchmarks but had no VCDB training samples.
        # Model will use the reference category (dropped by drop_first=True).
        # The ibm_industry_benchmark_log feature still carries the industry
        # cost signal, so predictions remain meaningful via that channel.
        print(
            f"  [NOTE] '{company_industry}' has no VCDB training samples — "
            f"model uses reference category; IBM benchmark drives the estimate."
        )

    for fname in feature_names:
        if fname in raw:
            feature_dict[fname] = raw[fname]
        elif fname.startswith("industry_sector_"):
            industry = fname.replace("industry_sector_", "")
            feature_dict[fname] = 1.0 if company_industry == industry else 0.0
        elif fname.startswith("attack_type_"):
            at = fname.replace("attack_type_", "")
            feature_dict[fname] = 1.0 if attack_type == at else 0.0
        else:
            feature_dict[fname] = 0.0

    return pd.DataFrame([feature_dict])[feature_names]


def _compute_confidence_tier(z: float, n_samples: int) -> str:
    """Classify prediction confidence based on Bühlmann credibility weight Z.

    Z = N / (N + K), K=20. Thresholds map to meaningful ML vs benchmark balance:
      high   z >= 0.6  →  30+ samples, ML-dominant (model learned the industry well)
      medium z >= 0.4  →  13-29 samples, balanced blend
      low    z <  0.4  →  <13 samples, IBM benchmark dominant
    """
    if z >= 0.6:
        return "high"
    elif z >= 0.4:
        return "medium"
    else:
        return "low"


def calculate_fair(ti_output: list, company_profile: dict,
                   model, feature_names: list,
                   metadata: dict = None,
                   conformal_model=None,
                   industry_models: dict = None) -> dict:
    """Calculate FAIR-based ALE for each vulnerability.

    Args:
        ti_output: List of vulnerability dicts from threat_intelligence_output.json
        company_profile: Company profile dict from company_profile.json
        model: Trained ML model (predicts log_loss)
        feature_names: List of feature names the model expects
        metadata: Model metadata dict (for industry_sample_counts, conformal info)
        conformal_model: MapieRegressor for prediction intervals (optional)

    Returns:
        Complete FAIR analysis dict ready for JSON output
    """
    industry = company_profile.get("industry_sector", "global_average")
    region = company_profile.get("region", "global_average")
    has_insurance = company_profile.get("has_cyber_insurance", False)

    # Base breach rate for this industry
    base_rate = get_breach_rate(industry)
    region_mult = get_region_multiplier(region)
    ibm_benchmark = get_industry_cost(industry)

    # Credibility weighting
    industry_counts = (metadata or {}).get("industry_sample_counts", {})
    n_samples = industry_counts.get(industry, 0)
    z = credibility_weight(n_samples)

    results = []

    for vuln in ti_output:
        # ═══ FREQUENCY SIDE ═══
        tpf = vuln.get("threat_pressure_factor", 1.5)
        loss_event_frequency = base_rate * tpf

        # ═══ MAGNITUDE SIDE ═══
        # Build features and predict (use industry model if available)
        features = _build_feature_vector(vuln, company_profile, feature_names)
        if industry_models:
            from prediction_model.industry_models import predict_with_industry_model
            log_prediction, model_used = predict_with_industry_model(
                features, industry, model, feature_names, industry_models
            )
        else:
            log_prediction = float(model.predict(features)[0])
            model_used = "global_model"

        # Convert from log scale to dollars
        ml_magnitude = float(np.expm1(log_prediction))

        # Apply region adjustment EXTERNALLY (not a training feature)
        ml_magnitude *= region_mult

        # ═══ CREDIBILITY BLENDING (Bühlmann) ═══
        # Blend ML prediction with IBM benchmark based on data availability
        blended_magnitude = z * ml_magnitude + (1 - z) * ibm_benchmark

        # Insurance adjustment (post-prediction, not a training feature)
        if has_insurance:
            insurance_offset = abs(COST_REDUCERS.get("cyber_insurance", -750_000))
            blended_magnitude = max(0, blended_magnitude - insurance_offset)

        # Sanity bounds
        predicted_magnitude = max(MIN_MAGNITUDE_USD, min(blended_magnitude, MAX_MAGNITUDE_USD))

        # ═══ PREDICTION INTERVALS (Conformal) ═══
        interval_80 = None
        if conformal_model is not None:
            try:
                _, y_interval = conformal_model.predict(features, alpha=0.2)
                log_lo = float(y_interval[0, 0, 0])
                log_hi = float(y_interval[0, 1, 0])
                # Apply same post-processing: expm1 → region → credibility → bounds
                raw_lo = float(np.expm1(log_lo)) * region_mult
                raw_hi = float(np.expm1(log_hi)) * region_mult
                ci_lo = z * raw_lo + (1 - z) * ibm_benchmark
                ci_hi = z * raw_hi + (1 - z) * ibm_benchmark
                ci_lo = max(MIN_MAGNITUDE_USD, ci_lo)
                ci_hi = min(MAX_MAGNITUDE_USD, ci_hi)
                interval_80 = {
                    "lower_usd": round(ci_lo, 2),
                    "upper_usd": round(ci_hi, 2),
                    "method": (metadata or {}).get("conformal_method", "Conformal Prediction (Jackknife+)"),
                }
            except Exception:
                pass  # silently skip if conformal prediction fails

        # ═══ ALE ═══
        ale = loss_event_frequency * predicted_magnitude

        result_entry = {
            "cve_id": vuln.get("cve_id", "UNKNOWN"),
            "severity": vuln.get("severity", vuln.get("alert_level", "UNKNOWN")),
            "vuln_type": vuln.get("vuln_type", "unknown"),
            "threat_pressure_factor": round(tpf, 4),
            "loss_event_frequency": round(loss_event_frequency, 4),
            "predicted_loss_magnitude_usd": round(predicted_magnitude, 2),
            "annualized_loss_expectancy_usd": round(ale, 2),
            "risk_tier": classify_risk_tier(ale),
            "confidence_tier": _compute_confidence_tier(z, n_samples),
            "fair_breakdown": {
                "base_industry_breach_rate": base_rate,
                "tpf_multiplier": round(tpf, 4),
                "frequency_calculation": f"{base_rate} x {tpf:.4f} = {loss_event_frequency:.4f}",
                "magnitude_source": f"{model_used} (log-loss) + region + credibility blending",
                "ml_raw_magnitude_usd": round(ml_magnitude, 2),
                "ibm_benchmark_usd": ibm_benchmark,
                "credibility_factor_z": round(z, 4),
                "credibility_note": (
                    f"{industry}: {n_samples} training samples, "
                    f"Z={z:.2f} (K={CREDIBILITY_K}). "
                    f"{'ML-dominant' if z > 0.6 else 'Benchmark-dominant' if z < 0.4 else 'Balanced blend'}."
                ),
                "region_multiplier": region_mult,
                "insurance_applied": has_insurance,
                "ale_calculation": f"{loss_event_frequency:.4f} x ${predicted_magnitude:,.0f} = ${ale:,.0f}",
            },
        }

        if interval_80:
            result_entry["prediction_interval_80"] = interval_80

        results.append(result_entry)

    # Sort by ALE descending
    results.sort(key=lambda x: x["annualized_loss_expectancy_usd"], reverse=True)

    total_ale = sum(r["annualized_loss_expectancy_usd"] for r in results)

    # Risk vs benchmark (compare average per-vulnerability magnitude, not total ALE)
    avg_magnitude = (
        sum(r["predicted_loss_magnitude_usd"] for r in results) / len(results)
        if results else 0
    )
    if avg_magnitude > ibm_benchmark:
        risk_vs_benchmark = "above_average"
    elif avg_magnitude > ibm_benchmark * 0.5:
        risk_vs_benchmark = "near_average"
    else:
        risk_vs_benchmark = "below_average"

    return {
        "analysis_metadata": {
            "analysis_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "framework": "FAIR (Factor Analysis of Information Risk)",
            "model_version": "1.0",
            "ti_source": "threat_intelligence_output.json",
            "company_profile_source": "company_profile.json",
            "methodology_note": (
                "Frequency: estimated from Verizon DBIR industry trends x TPF. "
                "These per-vulnerability frequency values are approximate and not "
                "calibrated actuarial rates. The total ALE (sum of per-CVE ALEs) is a valid "
                "expected value (linearity of expectation applies regardless of event correlation), "
                "but the probability of at least one breach cannot be derived by simple addition "
                "of per-CVE frequencies. "
                "Magnitude: ML model trained on VCDB real incidents (predicts log-loss), "
                "with IBM benchmark as a feature and IBM region multiplier applied externally. "
                "Region adjustment is applied post-prediction only (not a training feature) to "
                "avoid double-counting. VCDB records partial costs from public sources; IBM uses "
                "Ponemon standardized methodology. Individual predictions may have high variance "
                "(MAE in dollar-space is amplified by log-to-exp back-transformation). "
                "Results are order-of-magnitude estimates, not precise actuarial values."
            ),
        },
        "company": {
            "name": company_profile.get("company_name", "Unknown"),
            "industry": industry,
            "region": region,
            "estimated_records": company_profile.get("estimated_records", 0),
            "has_cyber_insurance": has_insurance,
        },
        "risk_summary": {
            "total_annualized_loss_expectancy_usd": round(total_ale, 2),
            "total_vulnerabilities_analyzed": len(results),
            "critical_risk_count": sum(1 for r in results if r["risk_tier"] == "CRITICAL"),
            "high_risk_count": sum(1 for r in results if r["risk_tier"] == "HIGH"),
            "medium_risk_count": sum(1 for r in results if r["risk_tier"] == "MEDIUM"),
            "low_risk_count": sum(1 for r in results if r["risk_tier"] == "LOW"),
            "industry_benchmark_avg_breach_cost_usd": ibm_benchmark,
            "risk_vs_benchmark": risk_vs_benchmark,
        },
        "vulnerability_risk_analysis": results,
    }


def run_prediction(ti_output_file: str = None,
                   company_profile_file: str = None,
                   output_file: str = None,
                   model_dir: str = None):
    """Run the complete FAIR prediction pipeline.

    This is the main entry point, called from main.py.
    """
    import config as _cfg
    if ti_output_file is None:
        ti_output_file = _cfg.TI_OUTPUT_FILE
    if company_profile_file is None:
        company_profile_file = _cfg.COMPANY_PROFILE_FILE
    if output_file is None:
        output_file = _cfg.PREDICTION_OUTPUT_FILE
    if model_dir is None:
        model_dir = _cfg.MODEL_DIR

    print(f"\n{'='*60}")
    print(f"FAIR Prediction Engine")
    print(f"{'='*60}")

    # Load TI output
    if not os.path.exists(ti_output_file):
        raise FileNotFoundError(f"TI output not found: {ti_output_file}")
    with open(ti_output_file, "r", encoding="utf-8") as f:
        ti_output = json.load(f)

    # Handle both array and dict formats
    if isinstance(ti_output, dict):
        vulnerabilities = ti_output.get("vulnerabilities", [ti_output])
    elif isinstance(ti_output, list):
        vulnerabilities = ti_output
    else:
        raise ValueError(f"Unexpected TI output format: {type(ti_output)}")

    print(f"  TI output loaded: {len(vulnerabilities)} vulnerabilities")

    # Load and validate company profile
    if not os.path.exists(company_profile_file):
        raise FileNotFoundError(f"Company profile not found: {company_profile_file}")
    with open(company_profile_file, "r", encoding="utf-8") as f:
        company_profile = json.load(f)

    from prediction_model.schema import validate_company_profile
    validation_errors = validate_company_profile(company_profile)
    if validation_errors:
        raise ValueError(
            "company_profile.json validation failed:\n" +
            "\n".join(f"  - {e}" for e in validation_errors)
        )
    print(f"  Company: {company_profile.get('company_name', 'Unknown')} ({company_profile.get('industry_sector')})")

    # Load ML model
    model_path = os.path.join(model_dir, "magnitude_model.joblib")
    meta_path = os.path.join(model_dir, "model_metadata.json")

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}. Run model_training first.")

    model = joblib.load(model_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)
    feature_names = metadata["feature_names"]
    print(f"  Model loaded: {metadata['model_type']} ({metadata['n_features']} features)")

    # Load conformal model if available
    conformal_path = os.path.join(model_dir, "magnitude_model_conformal.joblib")
    conformal_model = None
    if os.path.exists(conformal_path):
        try:
            conformal_model = joblib.load(conformal_path)
            print(f"  Conformal model loaded (80% prediction intervals enabled)")
        except Exception:
            print(f"  [WARN] Could not load conformal model, intervals disabled")

    # Load industry sub-models if available
    industry_models = {}
    try:
        from prediction_model.industry_models import load_industry_models
        industry_models = load_industry_models(model_dir)
        if industry_models:
            print(f"  Industry models loaded: {sorted(industry_models.keys())}")
    except Exception:
        pass  # industry models are optional

    # Run FAIR calculation
    result = calculate_fair(
        vulnerabilities, company_profile, model, feature_names,
        metadata=metadata, conformal_model=conformal_model,
        industry_models=industry_models,
    )

    # Save output
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"  Output saved: {output_file}")

    # Summary
    summary = result["risk_summary"]
    print(f"\n  === Risk Summary ===")
    print(f"  Total ALE: ${summary['total_annualized_loss_expectancy_usd']:,.2f}")
    print(f"  Industry benchmark: ${summary['industry_benchmark_avg_breach_cost_usd']:,}")
    print(f"  Risk vs benchmark: {summary['risk_vs_benchmark']}")
    print(f"  CRITICAL: {summary['critical_risk_count']}, HIGH: {summary['high_risk_count']}, "
          f"MEDIUM: {summary['medium_risk_count']}, LOW: {summary['low_risk_count']}")

    return result


# ─── Worked Example ───────────────────────────────────────────────────────────

def run_worked_example(model_dir: str = None):
    """Generate a worked example showing the full FAIR calculation step by step."""
    import config as _cfg
    if model_dir is None:
        model_dir = _cfg.MODEL_DIR

    print(f"\n{'='*60}")
    print(f"FAIR Worked Example")
    print(f"{'='*60}")

    # Load model
    model_path = os.path.join(model_dir, "magnitude_model.joblib")
    meta_path = os.path.join(model_dir, "model_metadata.json")
    model = joblib.load(model_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)
    feature_names = metadata["feature_names"]

    # Example vulnerability (from TI module)
    example_vuln = {
        "cve_id": "CVE-2024-XXXXX",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "epss_score": 0.94,
        "vuln_type": "sqli",
        "cwe_id": "CWE-89",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "threat_pressure_factor": 1.85,
        "has_public_exploit": True,
        "in_kev": True,
        "attack_tactic": "Initial Access",
    }

    # Example company
    example_company = {
        "company_name": "Example Healthcare Corp",
        "industry_sector": "healthcare",
        "employee_count_range": "1001 to 10000",
        "estimated_records": 50000,
        "data_sensitivity": "customer_pii",
        "region": "US",
        "annual_revenue_usd": 50000000,
        "has_cyber_insurance": False,
        "business_criticality": "high",
    }

    print(f"\n  === Input: Vulnerability ===")
    print(f"  CVE: {example_vuln['cve_id']}")
    print(f"  Severity: {example_vuln['severity']} (CVSS {example_vuln['cvss_score']})")
    print(f"  Type: {example_vuln['vuln_type']} ({example_vuln['cwe_id']})")
    print(f"  TPF: {example_vuln['threat_pressure_factor']}")
    print(f"  EPSS: {example_vuln['epss_score']}")

    print(f"\n  === Input: Company ===")
    print(f"  Name: {example_company['company_name']}")
    print(f"  Industry: {example_company['industry_sector']}")
    print(f"  Region: {example_company['region']}")
    print(f"  Records: {example_company['estimated_records']:,}")
    print(f"  Insurance: {example_company['has_cyber_insurance']}")

    # Step 1: Frequency
    base_rate = get_breach_rate(example_company["industry_sector"])
    tpf = example_vuln["threat_pressure_factor"]
    frequency = base_rate * tpf

    print(f"\n  === Step 1: Loss Event Frequency ===")
    print(f"  Base breach rate (healthcare): {base_rate}")
    print(f"  TPF (from TI module): {tpf}")
    print(f"  Frequency = {base_rate} x {tpf} = {frequency:.4f}")
    print(f"  Interpretation: {frequency:.1%} annual probability of this attack succeeding")

    # Step 2: Magnitude (with credibility blending)
    features = _build_feature_vector(example_vuln, example_company, feature_names)
    log_pred = model.predict(features)[0]
    raw_magnitude = float(np.expm1(log_pred))
    region_mult = get_region_multiplier(example_company["region"])
    ml_magnitude = raw_magnitude * region_mult

    ibm_bench = get_industry_cost(example_company["industry_sector"])
    industry_counts = metadata.get("industry_sample_counts", {})
    n_samples = industry_counts.get(example_company["industry_sector"], 0)
    z = credibility_weight(n_samples)

    blended_magnitude = z * ml_magnitude + (1 - z) * ibm_bench
    final_magnitude = max(MIN_MAGNITUDE_USD, min(blended_magnitude, MAX_MAGNITUDE_USD))

    print(f"\n  === Step 2: Loss Magnitude ===")
    print(f"  ML model prediction (log): {log_pred:.2f}")
    print(f"  ML prediction (USD): ${raw_magnitude:,.0f}")
    print(f"  Region multiplier (US): x{region_mult:.2f}")
    print(f"  After region adjustment: ${ml_magnitude:,.0f}")
    print(f"\n  === Step 2b: Bühlmann Credibility Blending ===")
    print(f"  Industry: {example_company['industry_sector']}")
    print(f"  VCDB training samples: {n_samples}")
    print(f"  Credibility factor Z = {n_samples}/({n_samples}+{CREDIBILITY_K}) = {z:.2f}")
    print(f"  Blended = {z:.2f} x ${ml_magnitude:,.0f} + {1-z:.2f} x ${ibm_bench:,}")
    print(f"  Blended magnitude: ${blended_magnitude:,.0f}")
    print(f"  After sanity bounds [{MIN_MAGNITUDE_USD:,} - {MAX_MAGNITUDE_USD:,}]: ${final_magnitude:,.0f}")

    # Step 2c: Conformal prediction interval
    conformal_path = os.path.join(model_dir, "magnitude_model_conformal.joblib")
    if os.path.exists(conformal_path):
        try:
            conformal_model = joblib.load(conformal_path)
            _, y_interval = conformal_model.predict(features, alpha=0.2)
            log_lo = float(y_interval[0, 0, 0])
            log_hi = float(y_interval[0, 1, 0])
            raw_lo = float(np.expm1(log_lo)) * region_mult
            raw_hi = float(np.expm1(log_hi)) * region_mult
            ci_lo = z * raw_lo + (1 - z) * ibm_bench
            ci_hi = z * raw_hi + (1 - z) * ibm_bench
            ci_lo = max(MIN_MAGNITUDE_USD, ci_lo)
            ci_hi = min(MAX_MAGNITUDE_USD, ci_hi)
            print(f"\n  === Step 2c: 80% Prediction Interval (Conformal) ===")
            print(f"  Log-space interval: [{log_lo:.2f}, {log_hi:.2f}]")
            print(f"  USD interval: [${ci_lo:,.0f}, ${ci_hi:,.0f}]")
            conformal_label = metadata.get("conformal_method", "Conformal Prediction") if metadata else "Conformal Prediction"
            print(f"  Method: {conformal_label}")
        except Exception as e:
            print(f"\n  [Conformal interval not available: {e}]")

    # Step 3: ALE
    ale = frequency * final_magnitude
    tier = classify_risk_tier(ale)

    print(f"\n  === Step 3: Annualized Loss Expectancy ===")
    print(f"  ALE = {frequency:.4f} x ${final_magnitude:,.0f}")
    print(f"  ALE = ${ale:,.2f}")
    print(f"  Risk Tier: {tier}")

    # Context
    print(f"\n  === Context ===")
    print(f"  IBM industry benchmark: ${ibm_bench:,}")
    print(f"  ALE as % of benchmark: {ale/ibm_bench*100:.1f}%")
    if ale > ibm_bench:
        print(f"  Risk is ABOVE industry average")
    else:
        print(f"  Risk is BELOW industry average")

    return {
        "frequency": frequency,
        "magnitude": final_magnitude,
        "ale": ale,
        "tier": tier,
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if "--example" in sys.argv:
        run_worked_example()
    elif "--run" in sys.argv:
        run_prediction()
    else:
        print("Usage:")
        print("  python -m prediction_model.fair_engine --example")
        print("  python -m prediction_model.fair_engine --run")
