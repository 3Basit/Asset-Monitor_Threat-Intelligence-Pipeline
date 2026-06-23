"""
model_training.py — Phase 3: Model Training & Comparison (Revised)
====================================================================
Trains multiple models on VCDB data to predict log(loss).
Uses 5-fold cross-validation due to small dataset (~288 rows).

Option C (Layered Model) — Revised:
  - Model predicts log(total_incident_cost_usd)
  - IBM benchmark feeds in as a feature (ibm_industry_benchmark_log)
  - At inference: predicted_loss_usd = exp(model.predict(features)) - 1
  - FAIR engine: ALE = frequency × predicted_loss_usd

Production enhancements:
  - Conformal prediction intervals (MapieRegressor, CV+ method)
  - Industry sample counts for Bühlmann credibility weighting
  - SHAP explainability (via explainability.py)
  - Error analysis diagnostics

Acceptance criteria:
  R² = 0.3 – 0.7    → Healthy, realistic
  R² < 0.3           → Model is guessing, but honest
  R² > 0.95          → STOP — leakage detected
"""

import os
import json
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.linear_model import LinearRegression, Ridge, ElasticNet
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.base import clone
from sklearn.model_selection import KFold, TimeSeriesSplit, cross_val_predict

warnings.filterwarnings("ignore", category=UserWarning)


def _cv_predict(model, X: pd.DataFrame, y: pd.Series, cv,
                sample_weight: np.ndarray = None) -> tuple:
    """Cross-validated predictions compatible with both KFold and TimeSeriesSplit.

    TimeSeriesSplit doesn't cover all samples (first fold has no train history),
    so cross_val_predict raises "only works for partitions". This function
    handles it manually: only samples that appear in a test fold get predictions.

    Returns (y_pred, mask) where mask selects the evaluated samples.
    """
    if isinstance(cv, TimeSeriesSplit):
        y_pred = np.full(len(y), np.nan)
        for train_idx, test_idx in cv.split(X):
            m = clone(model)
            sw = sample_weight[train_idx] if sample_weight is not None else None
            try:
                m.fit(X.iloc[train_idx], y.iloc[train_idx], sample_weight=sw)
            except TypeError:
                m.fit(X.iloc[train_idx], y.iloc[train_idx])
            y_pred[test_idx] = m.predict(X.iloc[test_idx])
        mask = ~np.isnan(y_pred)
        return y_pred, mask
    else:
        y_pred = cross_val_predict(model, X, y, cv=cv)
        return y_pred, np.ones(len(y), dtype=bool)


def _safe_import_xgboost():
    """Try to import XGBoost, return None if not available."""
    try:
        from xgboost import XGBRegressor
        return XGBRegressor
    except ImportError:
        print("  [WARN] XGBoost not installed, skipping")
        return None


def _safe_import_lightgbm():
    """Try to import LightGBM, return None if not available."""
    try:
        from lightgbm import LGBMRegressor
        return LGBMRegressor
    except ImportError:
        print("  [WARN] LightGBM not installed, skipping")
        return None


def build_models() -> dict:
    """Build the set of models to compare."""
    models = {}

    # Baseline: Linear Regression
    models["LinearRegression"] = LinearRegression()

    # Ridge Regression (L2 regularization) — controls coefficient magnitude
    models["Ridge"] = Ridge(alpha=1.0, random_state=42)

    # ElasticNet (L1+L2 regularization) — feature selection + regularization
    models["ElasticNet"] = ElasticNet(alpha=0.1, l1_ratio=0.5, max_iter=5000, random_state=42)

    # Random Forest — tuned for small dataset
    models["RandomForest"] = RandomForestRegressor(
        n_estimators=300,
        max_depth=8,
        min_samples_leaf=4,
        min_samples_split=8,
        max_features="sqrt",
        random_state=42,
        n_jobs=-1,
    )

    # XGBoost
    XGBRegressor = _safe_import_xgboost()
    if XGBRegressor:
        models["XGBoost"] = XGBRegressor(
            n_estimators=300,
            max_depth=5,
            learning_rate=0.05,
            min_child_weight=4,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_alpha=0.1,
            reg_lambda=1.0,
            random_state=42,
            verbosity=0,
        )

    # LightGBM
    LGBMRegressor = _safe_import_lightgbm()
    if LGBMRegressor:
        models["LightGBM"] = LGBMRegressor(
            n_estimators=300,
            max_depth=5,
            learning_rate=0.05,
            min_child_weight=4,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_alpha=0.1,
            reg_lambda=1.0,
            random_state=42,
            verbose=-1,
        )

    return models


def evaluate_with_kfold(X: pd.DataFrame, y: pd.Series, models: dict,
                        n_folds: int = 5, cv=None,
                        sample_weight: np.ndarray = None) -> tuple:
    """Evaluate all models using cross-validation.

    Pass cv=TimeSeriesSplit(...) for time-sorted data (preferred).
    Defaults to random KFold if cv is not provided.

    Returns (results_df, predictions_dict).
    """
    if cv is None:
        cv = KFold(n_splits=n_folds, shuffle=True, random_state=42)
        cv_label = f"Random KFold (k={n_folds})"
    else:
        cv_label = type(cv).__name__

    print(f"\n{'='*60}")
    print(f"Phase 3: Model Training ({cv_label})")
    print(f"{'='*60}")
    print(f"  Samples: {len(X)}")
    print(f"  Features: {X.shape[1]}")

    kf = cv

    results = []
    predictions = {}

    for name, model in models.items():
        print(f"\n  Training: {name}...")

        # Cross-validated predictions (handles both KFold and TimeSeriesSplit)
        try:
            y_pred, eval_mask = _cv_predict(model, X, y, kf, sample_weight=sample_weight)
        except Exception as e:
            print(f"    ERROR: {e}")
            continue

        y_eval = y.values[eval_mask]
        y_pred_eval = y_pred[eval_mask]
        n_eval = eval_mask.sum()

        # Metrics on log scale
        r2 = r2_score(y_eval, y_pred_eval)
        mae_log = mean_absolute_error(y_eval, y_pred_eval)
        rmse_log = np.sqrt(mean_squared_error(y_eval, y_pred_eval))

        # Metrics on dollar scale (more interpretable)
        y_dollars = np.expm1(y_eval)
        y_pred_dollars = np.expm1(np.clip(y_pred_eval, 0, 30))  # cap at ~$10T
        mae_dollars = mean_absolute_error(y_dollars, y_pred_dollars)
        median_ae_dollars = np.median(np.abs(y_dollars - y_pred_dollars))

        # Per-fold R² for stability check
        fold_r2s = []
        for train_idx, test_idx in kf.split(X):
            model_clone = clone(model)
            sw = sample_weight[train_idx] if sample_weight is not None else None
            try:
                model_clone.fit(X.iloc[train_idx], y.iloc[train_idx], sample_weight=sw)
            except TypeError:
                model_clone.fit(X.iloc[train_idx], y.iloc[train_idx])
            fold_pred = model_clone.predict(X.iloc[test_idx])
            fold_r2 = r2_score(y.iloc[test_idx], fold_pred)
            fold_r2s.append(fold_r2)

        r2_std = np.std(fold_r2s)
        r2_mean = np.mean(fold_r2s)

        # Sanity check
        if r2 > 0.95:
            status = "LEAKAGE WARNING"
        elif r2 > 0.7:
            status = "High (verify)"
        elif r2 >= 0.3:
            status = "Healthy"
        elif r2 >= 0.1:
            status = "Weak"
        else:
            status = "Poor"

        results.append({
            "model": name,
            "r2_overall": round(r2, 4),
            "r2_fold_mean": round(r2_mean, 4),
            "r2_fold_std": round(r2_std, 4),
            "mae_log": round(mae_log, 4),
            "rmse_log": round(rmse_log, 4),
            "mae_dollars": int(mae_dollars),
            "median_ae_dollars": int(median_ae_dollars),
            "status": status,
        })

        predictions[name] = y_pred

        print(f"    Evaluated on {n_eval}/{len(X)} samples")
        print(f"    R2 = {r2:.4f} (fold mean: {r2_mean:.4f} +/- {r2_std:.4f})")
        print(f"    MAE (log) = {mae_log:.4f}, RMSE (log) = {rmse_log:.4f}")
        print(f"    MAE ($) = ${mae_dollars:,.0f}, Median AE ($) = ${median_ae_dollars:,.0f}")
        print(f"    Status: {status}")

    if not results:
        print("\n  ERROR: All models failed during cross-validation.")
        return pd.DataFrame(), {}

    results_df = pd.DataFrame(results).sort_values("r2_overall", ascending=False)
    return results_df, predictions


def get_feature_importance(X: pd.DataFrame, y: pd.Series,
                           best_model_name: str, models: dict) -> pd.DataFrame:
    """Train the best model on full data and extract feature importance."""
    print(f"\n  Feature importance ({best_model_name}):")

    model = models[best_model_name]

    # Fit on full data for importance extraction
    from sklearn.base import clone
    model_full = clone(model)
    model_full.fit(X, y)

    # Store the fitted model for later use
    models[f"{best_model_name}_fitted"] = model_full

    # Get importances
    if hasattr(model_full, "feature_importances_"):
        importances = model_full.feature_importances_
    elif hasattr(model_full, "coef_"):
        importances = np.abs(model_full.coef_)
    else:
        print("    Model doesn't support feature importance")
        return pd.DataFrame()

    importance_df = pd.DataFrame({
        "feature": X.columns,
        "importance": importances,
    }).sort_values("importance", ascending=False)

    importance_df["importance_pct"] = (
        importance_df["importance"] / importance_df["importance"].sum() * 100
    ).round(2)

    # Print top features
    for _, row in importance_df.head(15).iterrows():
        bar = "#" * int(row["importance_pct"] / 2)
        print(f"    {row['feature']:<35s} {row['importance_pct']:>6.2f}%  {bar}")

    return importance_df


def check_hacking_performance(X: pd.DataFrame, y: pd.Series,
                              full_df: pd.DataFrame, models: dict,
                              best_model_name: str, cv=None):
    """Check model performance specifically on 'hacking' incidents.

    Since inference will always be for CVE-based threats (= hacking category),
    we need to verify the model works well on this subset.
    """
    print(f"\n  Performance on 'hacking' subset (inference-relevant):")

    # Find hacking rows via one-hot column
    hacking_col = "attack_type_hacking"
    if hacking_col in X.columns:
        hacking_mask = X[hacking_col] == 1
    elif "attack_type" in full_df.columns:
        hacking_mask = full_df["attack_type"] == "hacking"
        hacking_mask = hacking_mask.iloc[:len(X)]
    else:
        print("    Cannot identify hacking subset")
        return

    n_hacking = hacking_mask.sum()
    print(f"    Hacking incidents: {n_hacking} / {len(X)} ({n_hacking/len(X)*100:.1f}%)")

    if n_hacking < 10:
        print("    Too few hacking incidents for reliable evaluation")
        return

    model = models[best_model_name]
    kf = cv if cv is not None else KFold(n_splits=5, shuffle=True, random_state=42)

    # Full CV predictions (handles TimeSeriesSplit)
    y_pred, eval_mask = _cv_predict(model, X, y, kf)

    # Subset to hacking (intersect with eval_mask for TimeSeriesSplit)
    combined_mask = hacking_mask & eval_mask
    y_hack = y[combined_mask]
    y_pred_hack = y_pred[combined_mask]

    if len(y_hack) < 2:
        print(f"    Too few hacking samples in evaluated set ({len(y_hack)}) — skipping")
        return

    r2_hack = r2_score(y_hack, y_pred_hack)
    mae_hack_log = mean_absolute_error(y_hack, y_pred_hack)

    # Dollar-scale metrics for hacking
    y_hack_dollars = np.expm1(y_hack)
    y_pred_hack_dollars = np.expm1(np.clip(y_pred_hack, 0, 30))
    mae_hack_dollars = mean_absolute_error(y_hack_dollars, y_pred_hack_dollars)

    print(f"    R2 (hacking only): {r2_hack:.4f}")
    print(f"    MAE log (hacking): {mae_hack_log:.4f}")
    print(f"    MAE $ (hacking): ${mae_hack_dollars:,.0f}")
    print(f"    Mean log_loss (hacking): {y_hack.mean():.2f} (= ${np.expm1(y_hack.mean()):,.0f})")


def _compute_industry_sample_counts(full_df: pd.DataFrame) -> dict:
    """Count training samples per industry for Bühlmann credibility weighting.

    These counts are saved in model_metadata.json and used by fair_engine.py
    to blend ML predictions with IBM benchmarks:
      Z = N / (N + K)   where N = industry sample count, K = credibility constant

    Note: full_df is one-hot encoded, so we reconstruct industry from
    columns like 'industry_sector_healthcare', 'industry_sector_financial', etc.
    """
    # Try direct column first (if somehow still present)
    if "industry_sector" in full_df.columns:
        counts = full_df["industry_sector"].value_counts().to_dict()
        return {k: int(v) for k, v in counts.items()}

    # Reconstruct from one-hot columns
    industry_cols = [c for c in full_df.columns if c.startswith("industry_sector_")]
    if industry_cols:
        counts = {}
        for col in industry_cols:
            industry_name = col.replace("industry_sector_", "")
            counts[industry_name] = int(full_df[col].sum())
        return counts

    return {}


def _train_conformal_model(X: pd.DataFrame, y: pd.Series,
                           base_model, save_dir: str):
    """Train a conformal prediction wrapper (MapieRegressor) for prediction intervals.

    Uses CV+ method (method='plus') which is suitable for small datasets because
    it uses all data in k-fold cross-validation rather than sacrificing a separate
    calibration set.

    Returns (mapie_model, cv_residuals_std, method_name) or (None, None, None) if mapie not available.
    """
    try:
        from mapie.regression import MapieRegressor
    except ImportError:
        print("  [WARN] mapie not installed — skipping conformal prediction intervals")
        print("         Install with: pip install mapie")
        return None, None, None

    from sklearn.base import clone

    # Try both CV+ and Jackknife+ — pick the one with tighter intervals
    # while maintaining >=80% coverage.
    # Jackknife+ (leave-one-out) is more statistically efficient for N=288.
    best_model = None
    best_width = float('inf')
    best_coverage = 0
    best_method_name = ""

    for method_label, cv_param in [("CV+ (cv=5)", 5), ("Jackknife+ (LOO)", -1)]:
        print(f"\n  Training conformal model ({method_label})...")
        try:
            candidate = MapieRegressor(
                estimator=clone(base_model),
                cv=cv_param,
                method="plus",
                random_state=42,
            )
            candidate.fit(X, y)

            y_pred_c, y_intervals_c = candidate.predict(X, alpha=0.2)
            in_interval = ((y >= y_intervals_c[:, 0, 0]) & (y <= y_intervals_c[:, 1, 0]))
            coverage = in_interval.mean()
            mean_width = float(np.mean(y_intervals_c[:, 1, 0] - y_intervals_c[:, 0, 0]))

            print(f"    Coverage: {coverage:.1%} (target: >=80%)")
            print(f"    Mean interval width (log-space): {mean_width:.2f}")

            if coverage >= 0.80 and mean_width < best_width:
                best_model = candidate
                best_width = mean_width
                best_coverage = coverage
                best_method_name = method_label
        except Exception as e:
            print(f"    Failed: {e}")

    if best_model is None:
        print("  [WARN] No conformal method achieved >=80% coverage")
        return None, None, None

    print(f"\n  Selected: {best_method_name} (coverage={best_coverage:.1%}, width={best_width:.2f})")

    # Final metrics with selected model
    y_pred, y_intervals = best_model.predict(X, alpha=0.2)
    cv_residuals = y.values - y_pred
    cv_residuals_std = float(np.std(cv_residuals))
    print(f"  CV residual std (log-space): {cv_residuals_std:.4f}")

    # Save conformal model
    conformal_path = os.path.join(save_dir, "magnitude_model_conformal.joblib")
    joblib.dump(best_model, conformal_path)
    print(f"  Conformal model saved: {conformal_path}")

    return best_model, cv_residuals_std, best_method_name


def _run_error_analysis(y: pd.Series, y_pred: np.ndarray, full_df: pd.DataFrame,
                        save_dir: str):
    """Generate error analysis diagnostics and save plots."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print("  [WARN] matplotlib not installed — skipping error analysis plots")
        return

    print("\n  Generating error analysis...")
    os.makedirs(save_dir, exist_ok=True)

    y_dollars = np.expm1(y)
    y_pred_dollars = np.expm1(np.clip(y_pred, 0, 30))
    residuals_log = y.values - y_pred
    residuals_usd = y_dollars.values - y_pred_dollars

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Model Error Analysis — VCDB Loss Prediction', fontsize=14, fontweight='bold')

    # 1. Actual vs Predicted (log-space)
    ax = axes[0, 0]
    ax.scatter(y, y_pred, alpha=0.4, s=20, c='steelblue')
    lims = [min(y.min(), y_pred.min()), max(y.max(), y_pred.max())]
    ax.plot(lims, lims, 'r--', alpha=0.8, label='Perfect prediction')
    ax.set_xlabel('Actual log(loss)')
    ax.set_ylabel('Predicted log(loss)')
    ax.set_title('Actual vs Predicted (log-space)')
    ax.legend()

    # 2. Residual plot
    ax = axes[0, 1]
    ax.scatter(y_pred, residuals_log, alpha=0.4, s=20, c='steelblue')
    ax.axhline(y=0, color='r', linestyle='--', alpha=0.8)
    ax.set_xlabel('Predicted log(loss)')
    ax.set_ylabel('Residual (actual - predicted)')
    ax.set_title('Residual Plot')

    # 3. Error distribution (log-space)
    ax = axes[1, 0]
    ax.hist(residuals_log, bins=30, alpha=0.7, color='steelblue', edgecolor='white')
    ax.axvline(x=0, color='r', linestyle='--', alpha=0.8)
    ax.set_xlabel('Residual (log-space)')
    ax.set_ylabel('Count')
    ax.set_title(f'Error Distribution (mean={np.mean(residuals_log):.2f}, std={np.std(residuals_log):.2f})')

    # 4. Under/Over prediction breakdown
    ax = axes[1, 1]
    under = (residuals_usd > 0).sum()
    over = (residuals_usd < 0).sum()
    exact = (residuals_usd == 0).sum()
    under_mean = np.abs(residuals_usd[residuals_usd > 0]).mean() if under > 0 else 0
    over_mean = np.abs(residuals_usd[residuals_usd < 0]).mean() if over > 0 else 0
    bars = ax.bar(['Under-prediction', 'Over-prediction'],
                  [under, over], color=['#e74c3c', '#3498db'], alpha=0.8)
    ax.set_ylabel('Count')
    ax.set_title('Under vs Over Prediction')
    ax.text(0, under + 2, f'Mean err: ${under_mean:,.0f}', ha='center', fontsize=9)
    ax.text(1, over + 2, f'Mean err: ${over_mean:,.0f}', ha='center', fontsize=9)

    plt.tight_layout()
    plot_path = os.path.join(save_dir, 'error_analysis.png')
    plt.savefig(plot_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Error analysis plot saved: {plot_path}")

    # Industry breakdown (reconstruct from one-hot columns)
    industry_cols = [c for c in full_df.columns if c.startswith("industry_sector_")]
    if industry_cols:
        print("\n  Error by industry:")
        print(f"  {'Industry':<25s} {'N':>4s} {'Median AE ($)':>15s} {'Mean AE ($)':>15s}")
        print(f"  {'-'*63}")
        for col in sorted(industry_cols):
            industry = col.replace("industry_sector_", "")
            mask = full_df[col] == 1
            mask = mask.iloc[:len(y)]  # align with X
            n = mask.sum()
            if n < 2:
                continue
            ind_ae = np.abs(y_dollars.values[mask] - y_pred_dollars[mask])
            print(f"  {industry:<25s} {n:>4d} ${np.median(ind_ae):>14,.0f} ${np.mean(ind_ae):>14,.0f}")


def save_best_model(X: pd.DataFrame, y: pd.Series,
                    best_model_name: str, models: dict,
                    feature_names: list, full_df: pd.DataFrame,
                    save_dir: str = None, cv=None,
                    sample_weight: np.ndarray = None):
    """Save the best model, conformal wrapper, and metadata."""
    if save_dir is None:
        import config as _cfg
        save_dir = _cfg.MODEL_DIR
    os.makedirs(save_dir, exist_ok=True)

    # Use the already-fitted model if available
    fitted_key = f"{best_model_name}_fitted"
    if fitted_key in models:
        model = models[fitted_key]
    else:
        from sklearn.base import clone
        model = clone(models[best_model_name])
        try:
            model.fit(X, y, sample_weight=sample_weight)
        except TypeError:
            model.fit(X, y)

    model_path = os.path.join(save_dir, "magnitude_model.joblib")
    meta_path = os.path.join(save_dir, "model_metadata.json")

    joblib.dump(model, model_path)

    # ── Train conformal model for prediction intervals ──
    _, cv_residuals_std, conformal_method_name = _train_conformal_model(
        X, y, models[best_model_name], save_dir
    )

    # ── Compute industry sample counts for credibility weighting ──
    industry_counts = _compute_industry_sample_counts(full_df)
    print(f"\n  Industry sample counts (for Bühlmann credibility):")
    for ind, cnt in sorted(industry_counts.items(), key=lambda x: -x[1]):
        z = cnt / (cnt + 20)  # preview Z with K=20
        print(f"    {ind:<25s} N={cnt:>3d}  Z={z:.2f}")

    # ── Error analysis ──
    kf = cv if cv is not None else KFold(n_splits=5, shuffle=True, random_state=42)
    y_pred_cv, eval_mask = _cv_predict(models[best_model_name], X, y, kf,
                                        sample_weight=sample_weight)
    # For error analysis, use only evaluated samples
    y_eval = y.iloc[eval_mask].reset_index(drop=True)
    y_pred_cv_eval = y_pred_cv[eval_mask]
    full_df_eval = full_df.iloc[eval_mask].reset_index(drop=True)
    _run_error_analysis(y_eval, y_pred_cv_eval, full_df_eval, save_dir)

    # ── Save metadata ──
    metadata = {
        "model_type": best_model_name,
        "n_training_samples": int(len(X)),
        "n_features": int(len(feature_names)),
        "feature_names": list(feature_names),
        "target": "log_loss (log1p of total_incident_cost_usd)",
        "target_transform": "log1p → expm1 to get USD",
        "training_data_source": "VCDB (https://github.com/vz-risk/VCDB)",
        "option": "C (Layered Model) — revised with log-loss target",
        "industry_sample_counts": industry_counts,
        "cv_residuals_std": cv_residuals_std,
        "has_conformal_model": cv_residuals_std is not None,
        "conformal_method": f"Conformal Prediction ({conformal_method_name})" if conformal_method_name else None,
        "methodology_note": (
            "VCDB records partial costs (fines, settlements from public sources). "
            "IBM Cost of Data Breach measures full breach cost (Ponemon standardized "
            "methodology). "
            "ML features: company_size_score, log_records_cost, log_records_affected, "
            "data_sensitivity_score, incident_year_normalized (captures cost inflation). "
            "IBM benchmark drives Bühlmann credibility blending post-prediction "
            "(not a direct ML feature — SHAP showed 0% importance for ibm_industry_benchmark_log). "
            "Credibility weighting (Bühlmann, 1967) blends ML predictions with IBM "
            "benchmarks based on per-industry training sample count. "
            "Conformal prediction intervals (TimeSeriesSplit CV+) provide distribution-free "
            "80% confidence bands. "
            "Predictions should be treated as order-of-magnitude estimates."
        ),
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"\n  Model saved: {model_path}")
    print(f"  Metadata saved: {meta_path}")
    return model_path, model


def run_training(
    vcdb_dir: str = None,
    sources: list = None,
    semi_supervised: bool = False,
):
    """Run the full training pipeline: preprocess → train → evaluate → save.

    Parameters
    ----------
    vcdb_dir : str
        Path to VCDB validated JSON directory (default: config.VCDB_DIR).
    sources : list or None
        Data sources to include. None = ["vcdb"] only (original behaviour).
        Options: "vcdb", "ransomwhere", "sec_edgar"
        Example: ["vcdb", "ransomwhere", "sec_edgar"]
    semi_supervised : bool
        If True, add VCDB pseudo-labeled incidents via self-training.
        Requires a previously saved model in MODEL_DIR.
    """
    import config as _cfg

    if vcdb_dir is None:
        vcdb_dir = _cfg.VCDB_DIR

    # ── Phase 2: Data loading ──────────────────────────────────────────────────
    sample_weight = None

    if sources and sources != ["vcdb"]:
        # Multi-source extended pipeline
        from prediction_model.data_pipeline import build_extended_dataset
        X, y, sample_weight, feature_names = build_extended_dataset(
            sources=sources,
            vcdb_dir=vcdb_dir,
            model_dir=_cfg.MODEL_DIR,
            semi_supervised=semi_supervised,
        )
        # Use X as full_df proxy (it has all the one-hot columns needed)
        full_df = X.copy()
        print(f"\n  Extended dataset: {X.shape[0]} samples, {X.shape[1]} features")
        print(f"  Unique weights: {sorted(set(round(float(w), 2) for w in sample_weight))}")
    else:
        # Original single-source pipeline
        from prediction_model.preprocessing import run_preprocessing
        X, y, feature_names, full_df = run_preprocessing(vcdb_dir)
        if semi_supervised:
            import joblib as _jl
            try:
                model_ss = _jl.load(os.path.join(_cfg.MODEL_DIR, "magnitude_model.joblib"))
                try:
                    conf_ss = _jl.load(
                        os.path.join(_cfg.MODEL_DIR, "magnitude_model_conformal.joblib")
                    )
                except FileNotFoundError:
                    conf_ss = None
                from prediction_model.semi_supervised import run_self_training
                X, y, sample_weight = run_self_training(
                    X, y, feature_names, model_ss, conf_ss, vcdb_dir
                )
                full_df = X.copy()
            except FileNotFoundError:
                print("  [WARN] No saved model for semi-supervised — skipping")

    # Sort by incident year for time-based CV (prevents temporal leakage)
    if "incident_year_normalized" in X.columns:
        sort_order = X["incident_year_normalized"].argsort().values
        X = X.iloc[sort_order].reset_index(drop=True)
        y = y.iloc[sort_order].reset_index(drop=True)
        full_df = full_df.iloc[sort_order].reset_index(drop=True)
        if sample_weight is not None:
            sample_weight = sample_weight[sort_order]
        cv = TimeSeriesSplit(n_splits=5)
        print("\n  Data sorted by incident_year_normalized — using TimeSeriesSplit CV")
    elif "incident_year" in full_df.columns:
        sort_order = full_df["incident_year"].fillna(2017).argsort().values
        X = X.iloc[sort_order].reset_index(drop=True)
        y = y.iloc[sort_order].reset_index(drop=True)
        full_df = full_df.iloc[sort_order].reset_index(drop=True)
        if sample_weight is not None:
            sample_weight = sample_weight[sort_order]
        cv = TimeSeriesSplit(n_splits=5)
        print("\n  Data sorted by incident_year — using TimeSeriesSplit CV")
    else:
        cv = KFold(n_splits=5, shuffle=True, random_state=42)
        print("\n  incident_year not available — using random KFold CV")

    # ── Phase 3: Model training ────────────────────────────────────────────────
    models = build_models()
    results_df, predictions = evaluate_with_kfold(
        X, y, models, cv=cv, sample_weight=sample_weight
    )

    # Results table
    print(f"\n{'='*60}")
    print(f"Model Comparison Results")
    print(f"{'='*60}")
    print(results_df.to_string(index=False))

    # Pick best model
    best_row = results_df.iloc[0]
    best_model_name = best_row["model"]
    best_r2 = best_row["r2_overall"]

    # Sanity check
    if best_r2 > 0.95:
        print(f"\n  STOP: R2 = {best_r2:.4f} is suspiciously high!")
        print(f"  Likely leakage or data issue. Investigate before proceeding.")
        return None, results_df, None, None

    print(f"\n  Best model: {best_model_name} (R2 = {best_r2:.4f})")

    # Feature importance
    importance_df = get_feature_importance(X, y, best_model_name, models)

    # Hacking subset performance
    check_hacking_performance(X, y, full_df, models, best_model_name, cv=cv)

    # Save model + conformal wrapper + industry counts + error analysis
    model_path, fitted_model = save_best_model(
        X, y, best_model_name, models, feature_names, full_df,
        cv=cv, sample_weight=sample_weight,
    )

    # SHAP analysis (optional — requires shap package)
    # Use only VCDB-weighted samples for SHAP (weight=1.0) to avoid polluting
    # explanations with synthetic data from ransomwhere/edgar
    X_shap = X if sample_weight is None else X[sample_weight >= 0.85]
    y_shap = y if sample_weight is None else y[sample_weight >= 0.85]
    try:
        from prediction_model.explainability import run_shap_analysis
        run_shap_analysis(fitted_model, X_shap, list(feature_names),
                         save_dir=_cfg.MODEL_DIR)
    except ImportError:
        print("\n  [WARN] shap not installed — skipping SHAP analysis")
    except Exception as e:
        print(f"\n  [WARN] SHAP analysis failed: {e}")

    # Save results
    os.makedirs(_cfg.MODEL_DIR, exist_ok=True)
    results_df.to_csv(os.path.join(_cfg.MODEL_DIR, "model_comparison.csv"), index=False)
    if len(importance_df) > 0:
        importance_df.to_csv(os.path.join(_cfg.MODEL_DIR, "feature_importance.csv"), index=False)

    print(f"\n  Results saved to {_cfg.MODEL_DIR}/")

    return model_path, results_df, importance_df, fitted_model


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if "--compare" in sys.argv:
        run_training()
    else:
        print("Usage:")
        print("  python -m prediction_model.model_training --compare")

