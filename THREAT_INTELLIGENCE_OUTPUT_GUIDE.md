# Threat Intelligence Output — Documentation for Prediction Model Team

**From:** Threat Intelligence Module  
**File:** `threat_intelligence_output.json`  
**Format:** JSON Array — one object per (CVE × Asset) pair  
**Updated:** Every pipeline run (triggered by `python main.py`)

---

## How This File Is Generated

```
targets.json
    ↓
Asset Monitor       → discovers live web assets via HTTP + Nmap
    ↓
CISA KEV            → 1500+ confirmed-exploited vulnerabilities
    ↓
NVD + EPSS          → CVSS scores + exploitation probability
    ↓
Matching Engine     → links CVEs to assets (vendor + product + version)
    ↓
TPF Engine          → computes Threat Pressure Factor per CVE-Asset pair
    ↓
threat_intelligence_output.json
```

---

## Your Integration Point

The Prediction Model receives this file and uses:

```
Final Risk Probability = base_probability × threat_pressure_factor
```

Where `threat_pressure_factor` ranges from **1.0** (no threat) to **2.0** (maximum threat).

---

## Full Field Reference

### Asset Identification

| Field | Type | Example | Description |
|---|---|---|---|
| `asset_id` | string | `"ASSET-002"` | Unique asset identifier. Links back to our asset database. |
| `asset_name` | string | `"acuforum forums"` | Human-readable asset name (page title or URL). |
| `asset_type` | string | `"web_application"` | Always `web_application` in this module. |
| `asset_vendor` | string | `"Microsoft"` | Technology vendor detected on the asset. |
| `asset_product` | string | `"IIS"` | Specific product detected on the asset. |
| `business_criticality` | string | `"high"` | Business impact level: `critical` / `high` / `medium` / `low`. Defined in `targets.json`. |

---

### CVE Identification

| Field | Type | Example | Description |
|---|---|---|---|
| `cve_id` | string | `"CVE-2017-7269"` | Official MITRE CVE identifier. |
| `cve_vendor` | string | `"Microsoft"` | Vendor named in the CVE record. |
| `cve_product` | string | `"Internet Information Services (IIS)"` | Product named in the CVE record. |
| `description` | string | `"...buffer overflow..."` | Full CVE description from NVD. Useful as NLP feature if your model uses text. |
| `vuln_type` | string | `"rce"` | Vulnerability category. Detected from description keywords. |

**Vulnerability type values:**

| Value | Meaning | Risk Weight in TPF |
|---|---|---|
| `rce` | Remote Code Execution | +0.20 (highest) |
| `sqli` | SQL Injection | +0.15 |
| `auth_bypass` | Authentication Bypass | +0.15 |
| `path_traversal` | Path/Directory Traversal | +0.12 |
| `ssrf` | Server-Side Request Forgery | +0.12 |
| `xss` | Cross-Site Scripting | +0.08 |
| `other` | Other web vulnerability | +0.05 |
| `unknown` | Could not be determined | +0.00 |

---

### Risk Scores (Core Model Features)

| Field | Type | Example | Description |
|---|---|---|---|
| `cvss_score` | float | `9.8` | CVSS v3.1 base score from NVD. Range: 0.0–10.0. |
| `severity` | string | `"CRITICAL"` | CVSS severity label: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`. |
| `epss_score` | float | `0.94411` | EPSS probability of exploitation within 30 days. Range: 0.0–1.0. Value `0.944` = 94.4% chance. |
| `epss_percentile` | float | `0.99978` | Where this CVE ranks among all CVEs. Value `0.9998` = top 0.02% most dangerous. |
| `known_ransomware` | bool | `false` | `true` if CISA confirmed this CVE was used in ransomware campaigns. |

**CVSS score bands used in TPF:**

| Score | Band | TPF Weight |
|---|---|---|
| ≥ 9.0 | Critical | +0.20 |
| ≥ 7.0 | High | +0.13 |
| ≥ 4.0 | Medium | +0.07 |
| < 4.0 | Low | +0.00 |

**EPSS score bands used in TPF:**

| Score | Interpretation | TPF Weight |
|---|---|---|
| ≥ 0.7 | Very likely exploited | +0.20 |
| ≥ 0.4 | Likely exploited | +0.13 |
| ≥ 0.1 | Possible exploitation | +0.07 |
| < 0.1 | Unlikely exploitation | +0.00 |

---

### Temporal Features

| Field | Type | Example | Description |
|---|---|---|---|
| `published` | string (date) | `"2017-03-27"` | Date CVE was officially published by NVD. |
| `date_added` | string (date) | `"2021-11-03"` | Date CISA added this CVE to the Known Exploited Vulnerabilities list — confirms real-world exploitation. |
| `days_since_published` | int | `3328` | Age of the vulnerability in days. Old unpatched vulnerabilities = higher risk. |
| `days_since_kev_added` | int | `1646` | Days since CISA confirmed exploitation. Smaller = more recent active threat. |

**Recency bands used in TPF:**

| Days Since KEV Added | TPF Weight |
|---|---|
| ≤ 30 days | +0.10 (urgent) |
| ≤ 90 days | +0.06 |
| ≤ 365 days | +0.03 |
| > 365 days | +0.00 |

---

### Match Quality Fields

| Field | Type | Example | Description |
|---|---|---|---|
| `match_confidence` | string | `"high"` | Always `"high"` in this file — low confidence matches are excluded from output. A high match means vendor + product both matched between CVE and asset. |
| `scope` | string | `"web"` | Always `"web"` — this module covers web assets only. |
| `source` | string | `"CISA_KEV + NVD + EPSS"` | Data sources used to build this record. |
| `version_confirmed` | bool | `false` | `true` if the Nmap-detected version on the live server appears in the CVE description — confirms the specific vulnerable version is running. Adds +0.05 to TPF when true. |
| `detected_version` | string | `"8.5"` | The actual version string detected by Nmap on the live asset. Informational — used for version_confirmed check. |

---

### WAF Context

| Field | Type | Example | Description |
|---|---|---|---|
| `is_behind_waf` | bool | `false` | `true` if a Web Application Firewall was detected in front of this asset. |
| `waf_name` | string\|null | `null` | Name of detected WAF. Possible values: `"Cloudflare"`, `"Akamai"`, `"AWS CloudFront"`, `"Sucuri"`, `"Incapsula"`, `"F5 BIG-IP"`, `"ModSecurity"`, `"Fastly"`, or `null`. |

> **Note for Prediction Team:** WAF presence does not reduce TPF in our module — we leave this decision to your model. A WAF provides some mitigation but does not eliminate risk. You may choose to apply a discount factor when `is_behind_waf = true`.

---

### TPF Output (Primary Integration Fields)

| Field | Type | Example | Description |
|---|---|---|---|
| `threat_score` | float | `0.86` | Raw sum of all weighted components before adding base 1.0. Range: 0.0–1.0. |
| `threat_pressure_factor` | **float** | **`1.86`** | **The multiplier your model uses.** Range: 1.0–2.0. |
| `alert_level` | string | `"CRITICAL"` | Pre-computed severity label based on TPF. |

**Alert level thresholds:**

| TPF Value | Alert Level |
|---|---|
| ≥ 1.7 | `CRITICAL` |
| ≥ 1.5 | `HIGH` |
| ≥ 1.3 | `MEDIUM` |
| < 1.3 | `LOW` |

---

## TPF Formula (Full Breakdown)

```
threat_score = (CVSS component)
             + (EPSS component)
             + 0.13              ← KEV presence (always — all records are KEV)
             + 0.07              ← if known_ransomware = true
             + (vuln_type weight)
             + (business_criticality weight)
             + (recency weight)
             + 0.05              ← if version_confirmed = true

threat_score = min(threat_score, 1.0)   ← capped at 1.0
threat_pressure_factor = 1.0 + threat_score
```

**Business criticality weights:**

| Value | TPF Weight |
|---|---|
| `critical` | +0.20 |
| `high` | +0.13 |
| `medium` | +0.07 |
| `low` | +0.00 |

---

## Worked Example — CVE-2017-7269

```
CVSS 9.8  (≥9.0)              → +0.20
EPSS 0.944 (≥0.7)             → +0.20
KEV presence                  → +0.13
known_ransomware = false       → +0.00
vuln_type = rce               → +0.20
business_criticality = high   → +0.13
days_since_kev_added = 1646   → +0.00  (> 365 days)
version_confirmed = false      → +0.00
                            ─────────
threat_score (raw)            = 0.86
threat_score (capped at 1.0)  = 0.86
threat_pressure_factor        = 1.0 + 0.86 = 1.86
alert_level                   = CRITICAL (≥ 1.7)
```

---

## Integration Example

```python
# Prediction Model — minimal integration example

import json

with open("threat_intelligence_output.json") as f:
    ti_records = json.load(f)

for record in ti_records:
    asset_id   = record["asset_id"]
    cve_id     = record["cve_id"]
    tpf        = record["threat_pressure_factor"]   # 1.0 – 2.0
    is_waf     = record["is_behind_waf"]            # bool
    vc         = record["version_confirmed"]        # bool

    # Your model computes base probability from other signals
    base_probability = your_model.predict(record)

    # Apply TPF multiplier
    final_probability = base_probability * tpf

    print(f"{asset_id} | {cve_id} | base={base_probability:.3f} | "
          f"TPF={tpf} | final={final_probability:.3f}")
```

---

## Data Sources

| Source | What It Provides | Update Frequency |
|---|---|---|
| CISA KEV | Confirmed exploited vulnerabilities | Continuously updated |
| NVD | CVSS scores, severity, published date | Updated within 24–48h of CVE publication |
| EPSS | 30-day exploitation probability | Updated daily |
| Nmap | Live service version on asset | Per pipeline run |
| HTTP Fingerprinting | Vendor, product, WAF, technologies | Per pipeline run |

---

## Notes

- Every record in this file has `match_confidence = "high"` — low confidence matches are intentionally excluded.
- The file is regenerated on every `python main.py` run. Always use the latest version.
- If `detected_version` is present but `version_confirmed = false`, it means Nmap detected a version but it did not appear in the CVE description text (different version than the vulnerable one).
- All records in this file come from CISA KEV, meaning real-world exploitation has been confirmed by the US government — these are not theoretical vulnerabilities.
