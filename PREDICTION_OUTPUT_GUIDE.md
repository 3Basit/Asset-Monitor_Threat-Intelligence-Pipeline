# Prediction Output — Documentation for Downstream Consumers

**From:** Prediction Model (Module 3 — FAIR Engine)
**File:** `prediction_output.json` (path configurable via `CRD_PREDICTION_OUTPUT_FILE`)
**Format:** JSON Object — single analysis per pipeline run
**Updated:** Every pipeline run when `company_profile.json` and trained model are present
**Configuration:** All paths and settings managed in `config.py` — override via `CRD_*` environment variables

---

## How This File Is Generated

```
threat_intelligence_output.json   (from TI Module — Steps 1-4)
    |
    v
company_profile.json              (user-provided company data)
    |
    v
ML Model                          (ElasticNet trained on VCDB)
    |                              predicts log(loss) per vulnerability
    v
IBM Benchmarks                    (industry cost + region multiplier)
    |
    v
FAIR Engine                       (Frequency × Magnitude = ALE)
    |
    v
prediction_output.json
```

---

## Your Integration Point

```
ALE = Loss Event Frequency × Loss Magnitude

Where:
  Frequency = base_industry_breach_rate × threat_pressure_factor
  Magnitude = Z × (expm1(ML_log_pred) × region_mult) + (1-Z) × IBM_benchmark
  Z = Bühlmann credibility factor = N / (N + K), K=20
```

`annualized_loss_expectancy_usd` is the final dollar figure per vulnerability.

---

## Full Field Reference

### Analysis Metadata

| Field | Type | Example | Description |
|---|---|---|---|
| `analysis_date` | string | `"2026-06-20T13:04:19Z"` | UTC timestamp of analysis. |
| `framework` | string | `"FAIR (...)"` | Risk framework used. Always FAIR. |
| `model_version` | string | `"1.0"` | Prediction model version. |
| `ti_source` | string | `"threat_intelligence_output.json"` | Source of vulnerability data. |
| `company_profile_source` | string | `"company_profile.json"` | Source of company data. |
| `methodology_note` | string | (long text) | Full methodology description with all caveats. **Read this.** |

> The `methodology_note` contains all limitations and caveats inline — any consumer reading just the JSON file gets full context without needing external documentation.

---

### Company Summary

| Field | Type | Example | Description |
|---|---|---|---|
| `name` | string | `"Example Corp"` | Company name from `company_profile.json`. |
| `industry` | string | `"healthcare"` | Industry sector. See allowed values below. |
| `region` | string | `"US"` | Geographic region. See allowed values below. |
| `estimated_records` | int | `50000` | Estimated number of data records at risk. |
| `has_cyber_insurance` | bool | `false` | Whether company has cyber insurance. |

**`industry` values:**

| Value | IBM 2025 Avg Breach Cost |
|---|---|
| `healthcare` | $7,420,000 |
| `financial` | $5,560,000 |
| `industrial` | $5,000,000 |
| `energy` | $4,830,000 |
| `technology` | $4,790,000 |
| `pharmaceuticals` | $4,610,000 |
| `professional_services` | $4,550,000 |
| `transportation` | $4,420,000 |
| `entertainment` | $4,090,000 |
| `education` | $3,980,000 |
| `communication` | $3,900,000 |
| `consumer` | $3,820,000 |
| `retail` | $3,480,000 |
| `media` | $3,390,000 |
| `hospitality` | $3,260,000 |
| `research` | $3,250,000 |
| `public_sector` | $2,670,000 |

**`region` values and multipliers:**

| Value | Multiplier | Meaning |
|---|---|---|
| `US` | ×2.11 | Above global average |
| `Middle_East` | ×1.97 | Above global average |
| `Germany` | ×1.09 | Near global average |
| `Canada` | ×1.05 | Near global average |
| `Japan` | ×1.03 | Near global average |
| `UK` | ×0.99 | Near global average |
| `Italy` | ×0.94 | Below global average |
| `EU` | ×0.94 | Below global average |
| `France` | ×0.93 | Below global average |
| `South_Korea` | ×0.79 | Below global average |
| `Australia` | ×0.77 | Below global average |
| `ASEAN` | ×0.72 | Below global average |
| `Latin_America` | ×0.62 | Below global average |
| `India` | ×0.53 | Below global average |
| `South_Africa` | ×0.48 | Below global average |

> The region multiplier is applied **externally** after the ML prediction. It is NOT a training feature (training data is 80% US, so the model cannot reliably learn regional differences from 288 rows). IBM's regional cost data (Ponemon Institute surveys) is more reliable for this adjustment.

---

### Risk Summary

| Field | Type | Example | Description |
|---|---|---|---|
| `total_annualized_loss_expectancy_usd` | float | `895056.66` | Sum of ALE across all analyzed vulnerabilities. |
| `total_vulnerabilities_analyzed` | int | `1` | Number of vulnerabilities from TI output. |
| `critical_risk_count` | int | `0` | Vulnerabilities with ALE > $2M. |
| `high_risk_count` | int | `1` | Vulnerabilities with ALE $500K–$2M. |
| `medium_risk_count` | int | `0` | Vulnerabilities with ALE $100K–$500K. |
| `low_risk_count` | int | `0` | Vulnerabilities with ALE < $100K. |
| `industry_benchmark_avg_breach_cost_usd` | int | `7420000` | IBM 2025 average breach cost for this industry. |
| `risk_vs_benchmark` | string | `"below_average"` | How total ALE compares to the industry benchmark. |

**`risk_vs_benchmark` values:**

| Value | Meaning |
|---|---|
| `above_average` | Total ALE > industry benchmark |
| `near_average` | Total ALE between 50%–100% of benchmark |
| `below_average` | Total ALE < 50% of benchmark |

**Risk tier thresholds:**

| ALE | Tier |
|---|---|
| > $2,000,000 | `CRITICAL` |
| > $500,000 | `HIGH` |
| > $100,000 | `MEDIUM` |
| ≤ $100,000 | `LOW` |

---

### Vulnerability Risk Analysis (Per-CVE)

| Field | Type | Example | Description |
|---|---|---|---|
| `cve_id` | string | `"CVE-2017-7269"` | CVE identifier (from TI module). |
| `severity` | string | `"CRITICAL"` | Severity level (from TI module). |
| `vuln_type` | string | `"rce"` | Vulnerability type (from TI module). |
| `threat_pressure_factor` | float | `1.76` | TPF from TI module. Range: 1.0-2.0. |
| `loss_event_frequency` | float | `0.616` | Annual probability of this attack succeeding. |
| `predicted_loss_magnitude_usd` | float | `1453014.06` | Predicted single-event loss in USD (credibility-blended). |
| `annualized_loss_expectancy_usd` | float | `895056.66` | **The key output.** ALE = frequency x magnitude. |
| `risk_tier` | string | `"HIGH"` | Risk classification based on ALE. |
| `credibility_factor_z` | float | `0.75` | Buhlmann credibility weight applied (0-1). Higher = more data, more trust in ML. |
| `credibility_note` | string | `"Z=0.75 (N=61)..."` | Human-readable explanation of credibility blending. |
| `prediction_interval_80` | object | see below | 80% conformal prediction interval for magnitude. |

---

### FAIR Breakdown (Per-CVE)

Each vulnerability includes a `fair_breakdown` object showing the full calculation:

| Field | Type | Example | Description |
|---|---|---|---|
| `base_industry_breach_rate` | float | `0.35` | Estimated annual breach probability for this industry. |
| `tpf_multiplier` | float | `1.76` | Threat Pressure Factor from TI module. |
| `frequency_calculation` | string | `"0.35 x 1.7600 = 0.6160"` | Human-readable frequency formula. |
| `magnitude_source` | string | `"ML model (log-loss) + region + credibility blending"` | How magnitude was computed. |
| `ml_raw_magnitude_usd` | float | `1453014.06` | ML prediction × region multiplier (before credibility). |
| `ibm_benchmark_usd` | int | `7420000` | IBM industry benchmark used for credibility blending. |
| `credibility_factor_z` | float | `0.7531` | Bühlmann Z factor. Higher = more trust in ML. |
| `credibility_note` | string | `"healthcare: 61..."` | Human-readable credibility explanation. |
| `region_multiplier` | float | `2.1081` | IBM regional cost multiplier applied post-prediction. |
| `insurance_applied` | bool | `false` | Whether cyber insurance offset was applied. |
| `ale_calculation` | string | `"0.6160 x $2,926,344..."` | Human-readable ALE formula. |

### Prediction Interval (Per-CVE, optional)

Present when a conformal model is available.

| Field | Type | Example | Description |
|---|---|---|---|
| `prediction_interval_80.lower_usd` | float | `1859875.04` | Lower bound of 80% confidence interval. |
| `prediction_interval_80.upper_usd` | float | `31792875.18` | Upper bound of 80% confidence interval. |
| `prediction_interval_80.method` | string | `"Conformal Prediction (Jackknife+)"` | Statistical method used. |

---

## Worked Example — CVE-2017-7269 for Healthcare Company (US)

```
INPUT:
  Vulnerability: CVE-2017-7269 (RCE, CVSS 9.8, TPF 1.76)
  Company: Healthcare, US, 50,000 records, no insurance

STEP 1 — FREQUENCY:
  base_breach_rate(healthcare)          = 0.35
  threat_pressure_factor (from TI)      = 1.76
  loss_event_frequency                  = 0.35 × 1.76 = 0.616

STEP 2a — ML MAGNITUDE:
  ML model prediction (log-space)       = 13.44
  expm1(13.44) = $689,253               (ML raw output)
  region_multiplier(US) = ×2.11         (applied externally)
  ml_magnitude                          = $689,253 × 2.11 = $1,453,014

STEP 2b — CREDIBILITY BLENDING (Bühlmann):
  VCDB training samples (healthcare)    = 61
  Credibility factor Z                  = 61 / (61 + 20) = 0.75
  IBM benchmark (healthcare)            = $7,420,000
  blended_magnitude                     = 0.75 × $1,453,014 + 0.25 × $7,420,000
                                        = $2,926,344

STEP 2c — PREDICTION INTERVAL (80% Conformal):
  Log-space interval                    = [9.77, 16.75]
  USD interval                          = [$1,859,875, $31,792,875]

STEP 3 — ALE:
  annualized_loss_expectancy            = 0.616 × $2,926,344
                                        = $1,802,628
  risk_tier                             = HIGH (> $500K)
  vs IBM benchmark ($7.42M)             = 24.3% → below_average
```

---

## Integration Example

```python
import json

with open("prediction_output.json") as f:
    prediction = json.load(f)

# Access risk summary
summary = prediction["risk_summary"]
total_ale = summary["total_annualized_loss_expectancy_usd"]
benchmark = summary["industry_benchmark_avg_breach_cost_usd"]

print(f"Total ALE: ${total_ale:,.2f}")
print(f"Industry benchmark: ${benchmark:,}")
print(f"Risk vs benchmark: {summary['risk_vs_benchmark']}")

# Access per-vulnerability analysis
for vuln in prediction["vulnerability_risk_analysis"]:
    print(f"\n{vuln['cve_id']} ({vuln['severity']})")
    print(f"  Frequency: {vuln['loss_event_frequency']:.4f}")
    print(f"  Magnitude: ${vuln['predicted_loss_magnitude_usd']:,.0f}")
    print(f"  ALE: ${vuln['annualized_loss_expectancy_usd']:,.0f}")
    print(f"  Risk Tier: {vuln['risk_tier']}")
    print(f"  Credibility Z: {vuln['fair_breakdown']['credibility_factor_z']:.2f}")
    print(f"  {vuln['fair_breakdown']['credibility_note']}")
    print(f"  Calculation: {vuln['fair_breakdown']['ale_calculation']}")

    # Prediction interval (if available)
    if 'prediction_interval_80' in vuln:
        pi = vuln['prediction_interval_80']
        print(f"  80% CI: [${pi['lower_usd']:,.0f}, ${pi['upper_usd']:,.0f}]")
```

---

## Data Sources

| Source | What It Provides | Type |
|---|---|---|
| TI Module (`threat_intelligence_output.json`) | CVE data + TPF | Per pipeline run |
| Company Profile (`company_profile.json`) | Industry, region, records, insurance | User-provided |
| VCDB (10,037 incidents, 288 with loss data) | ML model training data | One-time training |
| IBM Cost of Data Breach 2025 | Industry benchmarks + region multipliers | Annual update |
| Verizon DBIR | Base breach rate estimates per industry | Annual update |

---

## Accuracy & Limitations

### Model Performance

| Metric | Value | Meaning |
|---|---|---|
| R² | 0.204 | Explains ~20% of loss variance |
| **Median Absolute Error** | **$318,602** | **Typical prediction error** |
| MAE (dollar-space) | ~$11.1M | Inflated by log→exp amplification (see below) |
| MAE (log-space) | 2.03 | ~2 log-units average error |
| Training samples | 288 | VCDB incidents with loss data |
| Cross-validation | 5-fold | All data used for both training and testing |

> **Model selection note:** The same 5-fold CV results were used both to select ElasticNet as best model (from 6 candidates) and to report final R²=0.204. This means the reported R² is slightly optimistic. A nested CV (outer loop for selection, inner loop for evaluation) would give a more conservative estimate, but was not used here due to the small dataset (288 rows makes nested 5×5 splits too small for stable estimates). ElasticNet was selected over RandomForest (R²=0.14), Ridge (R²=0.15), and 3 other models.

### Why MAE (~$11.1M) ≠ Median AE ($323K)

The model predicts `log(loss)`. Converting back to dollars via `exp()` amplifies errors non-linearly:
- For a $200 incident: 2.0 log-units error → $1,280 dollar error
- For an $800M incident: 2.0 log-units error → $5.1B dollar error

One wrong prediction on a high-value incident dominates the dollar-space MAE. **Use Median AE ($319K) as the representative accuracy metric.**

### Key Caveats

1. **VCDB vs IBM methodology:** VCDB records partial costs from public sources (fines, settlements). IBM measures full breach cost (Ponemon standardized methodology). They measure different things.
2. **Frequency is approximate:** Per-vulnerability breach rates are estimated, not calibrated actuarial rates. The `total_ale` (sum of per-CVE ALE values) is a valid expected value — linearity of expectation means E[total loss] = Σ E[individual loss] regardless of correlation between events. However, the *probability of at least one breach occurring* across multiple CVEs cannot be computed by simple addition of per-CVE frequencies; that requires accounting for event correlation.
3. **Order-of-magnitude estimates:** Results distinguish "$100K-level" from "$1M-level" from "$10M-level" risk — not "$943,217 precisely."
4. **Region multiplier is external:** Applied post-prediction from IBM data, not learned by the model (training data is 80% US).
5. **Insurance adjustment is simplified:** Flat offset ($750K) subtracted from magnitude. Real insurance policies are more complex.

---

## Production Enhancements

### Bühlmann Credibility Weighting

When the model has few training samples for a specific industry, its predictions are unreliable. Credibility weighting (from actuarial science) addresses this:

```
Z = N / (N + K)    where K = 20 (credibility constant)

predicted_magnitude = Z × ML_prediction + (1-Z) × IBM_benchmark
```

| Industry | Training Samples (N) | Z | Interpretation |
|---|---|---|---|
| healthcare | 61 | 0.75 | ML-dominant |
| financial | 57 | 0.74 | ML-dominant |
| public_sector | 49 | 0.71 | ML-dominant |
| professional_services | 27 | 0.57 | Balanced blend |
| retail | 24 | 0.55 | Balanced blend |
| technology | 19 | 0.49 | Balanced blend |
| education | 13 | 0.39 | Benchmark-dominant |
| industrial | 11 | 0.35 | Benchmark-dominant |
| transportation | 8 | 0.29 | Benchmark-dominant |
| energy | 6 | 0.23 | Benchmark-dominant |
| hospitality | 4 | 0.17 | Benchmark-dominant |
| entertainment | 1 | 0.05 | Benchmark-dominant |
| consumer, pharmaceuticals, communication, media, research | 0 | 0.00 | IBM benchmark only |

> **Reference:** Bühlmann, H. (1967). Experience Rating and Credibility. ASTIN Bulletin.

### Conformal Prediction Intervals

With R²=0.20, point estimates alone are misleading. Conformal prediction (Jackknife+ method) provides **distribution-free 80% confidence intervals** — no normality assumptions.

- **Method:** MapieRegressor with Jackknife+ leave-one-out (mapie library)
- **Coverage:** 80.9% on training data (well-calibrated for the target 80% level)
- **Output:** `prediction_interval_80: {lower_usd, upper_usd, method}`
- **Post-processing:** Same pipeline as point prediction (expm1 → region × credibility → bounds)

### SHAP Explainability

LinearExplainer (for ElasticNet) computes per-feature attribution for every prediction. TreeExplainer is used automatically as fallback for tree-based models.

**Saved artifacts** (in `prediction_model/saved_model/`):
- `shap_bar_global.png` — top 15 features by mean |SHAP value|
- `shap_beeswarm.png` — feature impact distribution
- `shap_waterfall_top.png` — waterfall for highest-loss instance
- `shap_importance.csv` — full SHAP importance table

**Run standalone:** `python -m prediction_model.explainability`

---

## Notes

- The file is regenerated on every `python main.py` run (Step 5) if both `company_profile.json` and a trained model exist.
- If either prerequisite is missing, Step 5 is skipped gracefully with a message.
- The `methodology_note` field inside the JSON contains all caveats inline — consumers don't need this external document for basic understanding.
- To retrain the model: `python -m prediction_model.model_training --compare`
- To run a worked example: `python -m prediction_model.fair_engine --example`
- To generate SHAP analysis: `python -m prediction_model.explainability`
