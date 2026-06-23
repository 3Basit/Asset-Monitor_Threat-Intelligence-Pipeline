"""
config.py — Centralized Configuration
=======================================
Single source of truth for paths, API settings, and runtime options.
All modules import from here instead of hardcoding paths.

Override any setting via environment variables (uppercase, prefixed with CRD_).
Example: CRD_DB_PATH=custom.db  CRD_NVD_API_KEY=xxx  python main.py
"""

import os

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _env(key: str, default=None):
    return os.environ.get(f"CRD_{key}", default)


# ── Database ─────────────────────────────────────────────────────────────────
DB_PATH = _env("DB_PATH", os.path.join(_BASE_DIR, "threat_intelligence.db"))

# ── API Keys ─────────────────────────────────────────────────────────────────
NVD_API_KEY = _env("NVD_API_KEY", os.environ.get("NVD_API_KEY", ""))

# ── API Rate Limits ──────────────────────────────────────────────────────────
NVD_DELAY_WITH_KEY = float(_env("NVD_DELAY_WITH_KEY", "0.6"))
NVD_DELAY_WITHOUT_KEY = float(_env("NVD_DELAY_WITHOUT_KEY", "6.0"))
EXPLOITDB_MAX_RETRIES = int(_env("EXPLOITDB_MAX_RETRIES", "2"))
CISA_MAX_RETRIES = int(_env("CISA_MAX_RETRIES", "3"))

# ── Asset Monitor ────────────────────────────────────────────────────────────
TARGETS_FILE = _env("TARGETS_FILE", os.path.join(_BASE_DIR, "targets.json"))
SCAN_DELAY_SECONDS = int(_env("SCAN_DELAY_SECONDS", "2"))
USER_AGENT = _env(
    "USER_AGENT",
    "CyberRiskDollarizer/1.0 (authorized-security-research)"
)
NMAP_WEB_PORTS = _env("NMAP_WEB_PORTS", "80,443,8080,8443,8000,8888")

# ── Output Files ─────────────────────────────────────────────────────────────
TI_OUTPUT_FILE = _env("TI_OUTPUT_FILE", os.path.join(_BASE_DIR, "threat_intelligence_output.json"))
ALERTS_FILE = _env("ALERTS_FILE", os.path.join(_BASE_DIR, "alerts.json"))
PREDICTION_OUTPUT_FILE = _env("PREDICTION_OUTPUT_FILE", os.path.join(_BASE_DIR, "prediction_output.json"))
COMPANY_PROFILE_FILE = _env("COMPANY_PROFILE_FILE", os.path.join(_BASE_DIR, "company_profile.json"))

# ── Prediction Model ────────────────────────────────────────────────────────
MODEL_DIR = _env("MODEL_DIR", os.path.join(_BASE_DIR, "prediction_model", "saved_model"))
VCDB_DIR = _env("VCDB_DIR", os.path.join(_BASE_DIR, "data", "vcdb", "data", "json", "validated"))

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL = _env("LOG_LEVEL", "INFO")
LOG_FILE = _env("LOG_FILE", "")  # empty = console only
LOG_FORMAT = _env(
    "LOG_FORMAT",
    "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
