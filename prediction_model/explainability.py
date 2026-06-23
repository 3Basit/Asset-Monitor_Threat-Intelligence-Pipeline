"""
explainability.py — SHAP-Based Model Explainability
====================================================================
Generates SHAP explanations for the trained magnitude model.

Auto-detects the appropriate explainer:
  - LinearExplainer for linear models (ElasticNet, Ridge, etc.)
  - TreeExplainer for tree-based models (RandomForest, XGBoost, etc.)

Because the training set is small (~288 rows), computing SHAP values
for ALL rows is fast and gives the most faithful global picture.

Outputs (saved to `save_dir`):
  - shap_bar_global.png      — top 15 features by mean |SHAP value|
  - shap_beeswarm.png        — beeswarm plot (top 15)
  - shap_waterfall_top.png   — waterfall for the highest-loss instance
  - shap_importance.csv      — full feature SHAP importances
"""

import json
import os
import warnings

import matplotlib
matplotlib.use("Agg")  # no GUI backend — safe for servers and CI

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np               # noqa: E402
import pandas as pd              # noqa: E402
import joblib                    # noqa: E402

warnings.filterwarnings("ignore", category=UserWarning)

# ─── Guarded SHAP import ─────────────────────────────────────────────────────

try:
    import shap
except ImportError:
    shap = None
    _SHAP_MISSING_MSG = (
        "The 'shap' package is required for explainability analysis.\n"
        "Install it with:  pip install shap\n"
        "Then re-run this module."
    )


# ─── Public API ───────────────────────────────────────────────────────────────

def run_shap_analysis(
    model,
    X: pd.DataFrame,
    feature_names: list,
    save_dir: str = "prediction_model/saved_model",
) -> pd.DataFrame:
    """Run full SHAP analysis on a fitted tree-based model.

    Parameters
    ----------
    model : fitted sklearn estimator
        Must support ``shap.TreeExplainer`` (RandomForest, XGBoost, etc.).
    X : pd.DataFrame
        Training feature matrix (all rows — 288 is small enough).
    feature_names : list[str]
        Ordered feature names matching ``X.columns``.
    save_dir : str
        Directory to write plots and CSV into (created if absent).

    Returns
    -------
    pd.DataFrame
        Feature importance table sorted by mean |SHAP value|.
    """
    if shap is None:
        raise ImportError(_SHAP_MISSING_MSG)

    os.makedirs(save_dir, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"SHAP Explainability Analysis")
    print(f"{'='*60}")
    print(f"  Model type : {type(model).__name__}")
    print(f"  Samples    : {X.shape[0]}")
    print(f"  Features   : {X.shape[1]}")

    # ── 1. Compute SHAP values ────────────────────────────────────────────
    # Auto-detect explainer: LinearExplainer for linear models, TreeExplainer for trees
    model_name = type(model).__name__
    linear_models = ("LinearRegression", "Ridge", "Lasso", "ElasticNet", "BayesianRidge")
    if model_name in linear_models:
        print(f"\n  Computing SHAP values (LinearExplainer)...")
        masker = shap.maskers.Independent(X, max_samples=X.shape[0])
        explainer = shap.LinearExplainer(model, masker)
    else:
        print(f"\n  Computing SHAP values (TreeExplainer)...")
        explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)

    # Handle scalar or array expected_value
    base_val = float(explainer.expected_value) if np.ndim(explainer.expected_value) == 0 else float(explainer.expected_value[0])

    # Build a shap.Explanation object (required by the modern plots API)
    explanation = shap.Explanation(
        values=shap_values,
        base_values=np.full(shap_values.shape[0], base_val),
        data=X.values,
        feature_names=list(feature_names),
    )

    print(f"  SHAP values shape: {shap_values.shape}")
    print(f"  Base value (E[f(x)]): {base_val:.4f}")

    # ── 2. Global importance table ────────────────────────────────────────
    mean_abs_shap = np.abs(shap_values).mean(axis=0)
    importance_df = pd.DataFrame({
        "feature": feature_names,
        "mean_abs_shap": mean_abs_shap,
    }).sort_values("mean_abs_shap", ascending=False).reset_index(drop=True)

    importance_df["importance_pct"] = (
        importance_df["mean_abs_shap"] / importance_df["mean_abs_shap"].sum() * 100
    ).round(2)

    csv_path = os.path.join(save_dir, "shap_importance.csv")
    importance_df.to_csv(csv_path, index=False)
    print(f"\n  Saved: {csv_path}")

    # ── 3a. Bar plot — top 15 features ────────────────────────────────────
    print(f"  Generating bar plot (top 15)...")
    fig, ax = plt.subplots(figsize=(10, 7))
    plt.sca(ax)
    shap.plots.bar(explanation, max_display=15, show=False)
    plt.title("Global Feature Importance — mean |SHAP value|", fontsize=13)
    plt.tight_layout()
    bar_path = os.path.join(save_dir, "shap_bar_global.png")
    plt.savefig(bar_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {bar_path}")

    # ── 3b. Beeswarm plot — top 15 features ──────────────────────────────
    print(f"  Generating beeswarm plot (top 15)...")
    fig, ax = plt.subplots(figsize=(10, 7))
    plt.sca(ax)
    shap.plots.beeswarm(explanation, max_display=15, show=False)
    plt.title("SHAP Beeswarm — feature impact distribution", fontsize=13)
    plt.tight_layout()
    beeswarm_path = os.path.join(save_dir, "shap_beeswarm.png")
    plt.savefig(beeswarm_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {beeswarm_path}")

    # ── 3c. Waterfall plot — highest-loss instance ────────────────────────
    print(f"  Generating waterfall plot (highest-loss instance)...")
    # The highest predicted value corresponds to the instance with the
    # largest base_value + sum(shap_values), i.e. the highest-loss row.
    predicted = shap_values.sum(axis=1) + base_val
    top_idx = int(np.argmax(predicted))
    print(f"    Instance index: {top_idx}")
    print(f"    Predicted log_loss: {float(predicted[top_idx]):.4f} "
          f"(~${float(np.expm1(predicted[top_idx])):,.0f})")

    fig, ax = plt.subplots(figsize=(10, 7))
    plt.sca(ax)
    shap.plots.waterfall(explanation[top_idx], max_display=15, show=False)
    plt.title(f"SHAP Waterfall — highest-loss instance (idx={top_idx})",
              fontsize=13)
    plt.tight_layout()
    waterfall_path = os.path.join(save_dir, "shap_waterfall_top.png")
    plt.savefig(waterfall_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {waterfall_path}")

    # ── 4. Print summary table ────────────────────────────────────────────
    print(f"\n  {'Feature':<35s} {'mean|SHAP|':>12s} {'%':>8s}")
    print(f"  {'-'*55}")
    for _, row in importance_df.head(15).iterrows():
        bar = "#" * int(float(row["importance_pct"]) / 2)
        print(f"  {row['feature']:<35s} {float(row['mean_abs_shap']):>12.4f} "
              f"{float(row['importance_pct']):>7.2f}%  {bar}")

    print(f"\n{'='*60}")
    print(f"SHAP analysis complete — {len(importance_df)} features analysed")
    print(f"{'='*60}")

    return importance_df


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _cli_main():
    """CLI entry point: load saved model + data, run SHAP analysis."""

    if shap is None:
        print(f"\n  ERROR: {_SHAP_MISSING_MSG}")
        return

    # ── Load model ────────────────────────────────────────────────────────
    import config as _cfg
    model_path = os.path.join(_cfg.MODEL_DIR, "magnitude_model.joblib")
    meta_path = os.path.join(_cfg.MODEL_DIR, "model_metadata.json")

    if not os.path.exists(model_path):
        print(f"\n  ERROR: Saved model not found at '{model_path}'.")
        print(f"  Run training first:  python -m prediction_model.model_training --compare")
        return

    print(f"\n{'='*60}")
    print(f"Loading model & data")
    print(f"{'='*60}")

    model = joblib.load(model_path)
    print(f"  Model loaded: {model_path}")

    # ── Load feature names from metadata ──────────────────────────────────
    with open(meta_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)
    feature_names = metadata["feature_names"]
    print(f"  Features from metadata: {len(feature_names)}")

    # ── Run preprocessing to get X ────────────────────────────────────────
    from prediction_model.preprocessing import run_preprocessing

    X, y, _, _ = run_preprocessing()

    # Align X columns to saved feature names (in case preprocessing order
    # drifts — the model was trained on exactly these columns).
    missing = set(feature_names) - set(X.columns)
    if missing:
        print(f"  WARNING: Features in metadata but not in X: {missing}")
        for col in missing:
            X[col] = 0.0
    X = X[feature_names]

    print(f"  Training data loaded: X={X.shape}")

    # ── Run analysis ──────────────────────────────────────────────────────
    save_dir = _cfg.MODEL_DIR
    importance_df = run_shap_analysis(model, X, feature_names, save_dir)

    # Quick sanity cross-reference with built-in importances
    if hasattr(model, "feature_importances_"):
        builtin = pd.Series(model.feature_importances_, index=feature_names)
        top_builtin = builtin.sort_values(ascending=False).head(5).index.tolist()
        top_shap = importance_df.head(5)["feature"].tolist()
        overlap = len(set(top_builtin) & set(top_shap))
        print(f"\n  Sanity check: {overlap}/5 top features overlap between "
              f"SHAP and built-in importance")


if __name__ == "__main__":
    _cli_main()
