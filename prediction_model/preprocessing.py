"""
preprocessing.py — Phase 2: Data Preprocessing & Feature Engineering (Revised)
================================================================================
Cleans VCDB data, engineers features, and performs mandatory leakage checks.

Option C (Layered Model) — Revised approach:
  - Target = log(total_incident_cost_usd) — log-transformed actual loss
  - Previous deviation_factor approach failed because VCDB measures partial costs
    (fines, settlements from public records) while IBM measures full breach cost
    (Ponemon methodology). This mismatch caused 77% of rows to clip at floor.
  - Now the ML model predicts log(loss) directly from incident + company features.
  - At inference: IBM benchmark provides context as a feature, ML predicts actual loss.
  - The FAIR engine then applies: ALE = frequency × ML_predicted_magnitude

Key principle: Only use features available in BOTH training (VCDB) AND inference
(company_profile.json + TI output). See schema.py for the full separation.
"""

import warnings
import numpy as np
import pandas as pd

from prediction_model.ibm_benchmarks import (
    IBM_PER_RECORD_COST,
    get_region_multiplier,
    get_per_record_cost,
)
from prediction_model.schema import (
    TRAINING_NUMERIC_FEATURES,
    TRAINING_CATEGORICAL_FEATURES,
    get_magnitude_training_features,
)
from prediction_model.vcdb_parser import EMPLOYEE_COUNT_SCORE


# ─── Constants ────────────────────────────────────────────────────────────────

# Outlier thresholds
MAX_LOSS_USD = 10_000_000_000      # $10B — above this is clearly erroneous
MIN_LOSS_USD = 100                  # $100 — below this is likely incomplete data

# Year filter: only use relatively recent incidents for training
MIN_INCIDENT_YEAR = 2010


def load_and_clean(vcdb_dir: str = "data/vcdb/data/json/validated") -> pd.DataFrame:
    """Phase 2 Step 1: Load VCDB data and perform basic cleaning.

    Returns cleaned DataFrame with loss data only.
    """
    from prediction_model.vcdb_parser import get_training_data

    df = get_training_data(vcdb_dir)
    initial_rows = len(df)
    print(f"\n{'='*60}")
    print(f"Phase 2: Preprocessing")
    print(f"{'='*60}")
    print(f"\n[1/5] Loading & cleaning...")
    print(f"  Raw rows with loss data: {initial_rows}")

    # ── Remove duplicates by incident_id ──
    dupes = df.duplicated(subset=["incident_id"], keep="first").sum()
    df = df.drop_duplicates(subset=["incident_id"], keep="first")
    print(f"  Duplicates removed: {dupes}")

    # ── Remove outliers ──
    outliers_high = (df["total_incident_cost_usd"] > MAX_LOSS_USD).sum()
    outliers_low = (df["total_incident_cost_usd"] < MIN_LOSS_USD).sum()
    df = df[
        (df["total_incident_cost_usd"] >= MIN_LOSS_USD) &
        (df["total_incident_cost_usd"] <= MAX_LOSS_USD)
    ]
    print(f"  Outliers removed (> ${MAX_LOSS_USD:,}): {outliers_high}")
    print(f"  Outliers removed (< ${MIN_LOSS_USD:,}): {outliers_low}")

    # ── Filter by year ──
    if "incident_year" in df.columns:
        old = (df["incident_year"] < MIN_INCIDENT_YEAR).sum()
        old += df["incident_year"].isna().sum()
        df = df[df["incident_year"] >= MIN_INCIDENT_YEAR]
        print(f"  Old incidents removed (before {MIN_INCIDENT_YEAR}): {old}")

    # ── Remove rows with unknown industry ──
    unknown_industry = (df["industry_sector"] == "unknown").sum()
    df = df[df["industry_sector"] != "unknown"]
    print(f"  Unknown industry removed: {unknown_industry}")

    print(f"  Rows after cleaning: {len(df)}")
    return df.reset_index(drop=True)


def compute_log_loss_target(df: pd.DataFrame) -> pd.DataFrame:
    """Phase 2 Step 2: Compute the log-transformed loss target.

    Using log(loss) instead of deviation_factor because:
    - VCDB records partial costs (fines, settlements from public sources)
    - IBM measures full breach cost (Ponemon standardized methodology)
    - Direct division creates floor effect (77% clipped in previous attempt)
    - Log-transform handles the heavy right-skew of financial loss data
    """
    print(f"\n[2/5] Computing log-loss target...")

    df["log_loss"] = np.log1p(df["total_incident_cost_usd"])

    print(f"  Raw loss stats:")
    print(f"    Min:    ${df['total_incident_cost_usd'].min():>15,.0f}")
    print(f"    Max:    ${df['total_incident_cost_usd'].max():>15,.0f}")
    print(f"    Mean:   ${df['total_incident_cost_usd'].mean():>15,.0f}")
    print(f"    Median: ${df['total_incident_cost_usd'].median():>15,.0f}")
    print(f"  Log-loss stats:")
    print(f"    Min:    {df['log_loss'].min():.2f}")
    print(f"    Max:    {df['log_loss'].max():.2f}")
    print(f"    Mean:   {df['log_loss'].mean():.2f}")
    print(f"    Median: {df['log_loss'].median():.2f}")
    print(f"    Std:    {df['log_loss'].std():.2f}")

    return df


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Phase 2 Step 3: Feature engineering.

    Creates derived features from raw VCDB data that are also computable
    at inference time from company_profile.json.
    """
    print(f"\n[3/5] Feature engineering...")

    # ── Company size score (ordinal) ──
    if "company_size_score" not in df.columns:
        df["company_size_score"] = df["employee_count_range"].map(EMPLOYEE_COUNT_SCORE).fillna(4)
    df["company_size_score"] = df["company_size_score"].astype(int)

    # ── Region cost multiplier ──
    df["region_cost_multiplier"] = df["region"].apply(get_region_multiplier)

    # ── Records affected (log-transformed) ──
    df["records_affected"] = pd.to_numeric(df["records_affected"], errors="coerce")
    df["log_records_affected"] = np.log1p(df["records_affected"].fillna(0))

    # ── Per-record cost estimate (log-transformed) ──
    df["per_record_cost"] = df["data_sensitivity"].apply(
        lambda x: IBM_PER_RECORD_COST.get(x, IBM_PER_RECORD_COST.get("unknown", 160))
    )
    df["records_cost_estimate"] = df["records_affected"].fillna(0) * df["per_record_cost"]
    df["log_records_cost"] = np.log1p(df["records_cost_estimate"])

    # ── Data sensitivity score (ordinal) ──
    sensitivity_scores = {
        "ip": 5,
        "corporate": 4,
        "customer_pii": 3,
        "anonymized_customer": 2,
        "employee_pii": 2,
        "unknown": 1,
    }
    df["data_sensitivity_score"] = df["data_sensitivity"].map(sensitivity_scores).fillna(1).astype(int)

    # ── Incident year (normalized) ──
    # Captures breach cost inflation trend (~10% per year per IBM reports).
    # Normalized: (year - 2010) / 10 → range ~0.0 to ~1.4 for VCDB data.
    # At inference time, current calendar year is used (see fair_engine.py).
    df["incident_year_normalized"] = (
        df["incident_year"].fillna(2017).clip(lower=2010) - 2010
    ) / 10.0

    # ── Fill missing categoricals ──
    categorical_cols = ["attack_type", "attack_variety", "attack_vector",
                        "asset_variety", "data_sensitivity", "industry_sector",
                        "region", "employee_count_range"]
    for col in categorical_cols:
        if col in df.columns:
            df[col] = df[col].fillna("unknown").astype(str)

    # NOTE: region_cost_multiplier is intentionally NOT included here.
    # It is applied as an external post-prediction adjustment in fair_engine.py.
    # Including it here AND multiplying externally would double-count the region effect.
    # NOTE: ibm_industry_benchmark_log is NOT included — SHAP showed 0% importance
    # (ElasticNet L1 zeroed it out). IBM benchmark is still used post-prediction
    # via Bühlmann credibility blending in fair_engine.py.
    engineered = [
        "company_size_score",
        "log_records_cost", "log_records_affected",
        "data_sensitivity_score", "incident_year_normalized",
    ]
    print(f"  Engineered features: {engineered}")
    print(f"  Columns now: {len(df.columns)}")

    # Safety net: catch silent drift between these hardcoded names and schema.py.
    # If you rename a feature in schema.py, this assert will fail immediately with
    # a clear message instead of a confusing KeyError later in training.
    assert set(engineered) == set(TRAINING_NUMERIC_FEATURES), (
        f"engineer_features() output {engineered} doesn't match "
        f"schema.py TRAINING_NUMERIC_FEATURES {list(TRAINING_NUMERIC_FEATURES)}. "
        f"Update both together."
    )

    return df


def check_leakage(df: pd.DataFrame, target_col: str = "log_loss") -> pd.DataFrame:
    """Phase 2 Step 4: Mandatory leakage check.

    Any feature with correlation > 0.9 with the target is flagged and removed.
    """
    print(f"\n[4/5] Leakage check (target: {target_col})...")

    # Only check numeric columns
    numeric_df = df.select_dtypes(include=[np.number])

    if target_col not in numeric_df.columns:
        print(f"  WARNING: Target '{target_col}' not in numeric columns, skipping check")
        return df

    correlations = numeric_df.corr()[target_col].abs().sort_values(ascending=False)

    print(f"\n  Correlation with {target_col}:")
    print(f"  {'Feature':<35s} {'Corr':>8s}  {'Status':>10s}")
    print(f"  {'-'*55}")

    leakage_features = []
    # Features that are DERIVED from the target — expected to correlate
    expected_high_corr = {"total_incident_cost_usd", "records_cost_estimate",
                          "deviation_factor_raw", "deviation_factor", "per_record_cost"}

    for feature, corr in correlations.items():
        if feature == target_col:
            continue

        status = ""
        if corr > 0.9:
            if feature in expected_high_corr:
                status = "Expected"
            else:
                status = "LEAKAGE!"
                leakage_features.append(feature)
        elif corr > 0.7:
            status = "Watch"
        elif corr > 0.3:
            status = ""

        # Show top correlations + any flagged ones
        if corr > 0.2 or status:
            print(f"  {feature:<35s} {corr:>8.4f}  {status:>10s}")

    if leakage_features:
        print(f"\n  LEAKAGE DETECTED in {len(leakage_features)} feature(s): {leakage_features}")
        for feat in leakage_features:
            print(f"    REMOVING '{feat}'")
            df = df.drop(columns=[feat])
    else:
        print(f"\n  No leakage detected (all training-eligible features < 0.9)")

    return df


def prepare_training_data(df: pd.DataFrame):
    """Phase 2 Step 5: Prepare final training DataFrame.

    Selects only the features the model will actually use, encodes categoricals,
    and returns (X, y, feature_names, full_df).
    """
    print(f"\n[5/5] Preparing training data...")

    target_col = "log_loss"

    # ── Select features for training ──
    # Imported from schema.py — SINGLE SOURCE OF TRUTH.
    # Do NOT redefine these lists here; update schema.py instead.
    numeric_features = list(TRAINING_NUMERIC_FEATURES)
    categorical_features = list(TRAINING_CATEGORICAL_FEATURES)

    # ── Build feature matrix ──
    # One-hot encode categoricals
    df_encoded = pd.get_dummies(df, columns=categorical_features, drop_first=True)

    # Get all one-hot columns
    onehot_cols = [c for c in df_encoded.columns
                   if any(c.startswith(f"{cat}_") for cat in categorical_features)]

    all_features = numeric_features + onehot_cols

    # Deduplicate feature names (safety check)
    seen = set()
    unique_features = []
    for f in all_features:
        if f in df_encoded.columns and f not in seen:
            unique_features.append(f)
            seen.add(f)
    all_features = unique_features

    X = df_encoded[all_features].astype(float)
    y = df_encoded[target_col].astype(float)

    # Fill any remaining NaN in features with 0
    nan_counts = X.isna().sum()
    nan_features = nan_counts[nan_counts > 0]
    if len(nan_features) > 0:
        print(f"  NaN fill (with 0): {dict(nan_features)}")
    X = X.fillna(0)

    # Verify no duplicate columns
    if X.columns.duplicated().any():
        dupes = X.columns[X.columns.duplicated()].tolist()
        print(f"  WARNING: Removing duplicate columns: {dupes}")
        X = X.loc[:, ~X.columns.duplicated()]
        all_features = list(X.columns)

    print(f"  Final feature count: {len(all_features)}")
    print(f"  Numeric features: {len(numeric_features)}")
    print(f"  One-hot features: {len(onehot_cols)}")
    print(f"  Training samples: {len(X)}")
    print(f"  Target (log_loss) stats:")
    print(f"    Mean:   {y.mean():.2f}  (= ${np.expm1(y.mean()):,.0f})")
    print(f"    Median: {y.median():.2f}  (= ${np.expm1(y.median()):,.0f})")
    print(f"    Std:    {y.std():.2f}")

    return X, y, all_features, df_encoded


def run_preprocessing(vcdb_dir: str = None):
    """Run the full preprocessing pipeline. Returns (X, y, feature_names, full_df)."""
    if vcdb_dir is None:
        import config as _cfg
        vcdb_dir = _cfg.VCDB_DIR

    # Step 1: Load and clean
    df = load_and_clean(vcdb_dir)

    # Step 2: Compute log-loss target
    df = compute_log_loss_target(df)

    # Step 3: Feature engineering
    df = engineer_features(df)

    # Step 4: Leakage check
    df = check_leakage(df, target_col="log_loss")

    # Step 5: Prepare training data
    X, y, feature_names, full_df = prepare_training_data(df)

    print(f"\n{'='*60}")
    print(f"Preprocessing complete!")
    print(f"  Dataset shape: X={X.shape}, y={y.shape}")
    print(f"  Features: {len(feature_names)}")
    print(f"{'='*60}")

    return X, y, feature_names, full_df


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    vcdb_dir = "data/vcdb/data/json/validated"

    if "--check-leakage" in sys.argv:
        X, y, features, df = run_preprocessing(vcdb_dir)
        print(f"\nFinal columns in preprocessed data:")
        for i, f in enumerate(features):
            print(f"  [{i+1:2d}] {f}")

    elif "--shape" in sys.argv:
        X, y, features, df = run_preprocessing(vcdb_dir)
        print(f"\nDataset shape: {X.shape}")
        print(f"Features ({len(features)}):")
        for f in features:
            print(f"  {f}")

    else:
        print("Usage:")
        print("  python -m prediction_model.preprocessing --check-leakage")
        print("  python -m prediction_model.preprocessing --shape")
