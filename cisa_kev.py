import requests
import json
import os
import time

import config
from logger import get_logger
from database import save_cisa_kev as db_save_cisa_kev

log = get_logger("cisa_kev")

KEV_URL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_ETAG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".kev_etag")


def _load_etag():
    try:
        with open(_ETAG_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def _save_etag(etag):
    with open(_ETAG_FILE, "w") as f:
        f.write(etag or "")


def fetch_cisa_kev(max_retries=3):
    """Fetch CISA KEV feed with ETag caching and exponential-backoff retry.

    ETag caching: if the feed hasn't changed since the last run, the server
    returns HTTP 304 and we skip the download entirely — saving bandwidth and
    time on every subsequent pipeline run.

    Returns:
        list[dict]  — CVE records to save (may be empty)
        None        — feed unchanged, DB already up to date, skip save
    Raises:
        Exception   — all retry attempts exhausted
    """
    saved_etag = _load_etag()
    headers    = {"If-None-Match": saved_etag} if saved_etag else {}

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(KEV_URL, headers=headers, timeout=30)

            # Feed unchanged — reuse what's already in the DB
            if response.status_code == 304:
                log.info("CISA KEV feed unchanged (ETag match) — skipping download")
                return None   # caller should skip save_cisa_kev

            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                log.warning("CISA KEV returned empty vulnerabilities list")
                return []

            # Persist ETag for next run
            new_etag = response.headers.get("ETag")
            if new_etag:
                _save_etag(new_etag)

            return [
                {
                    "cve_id":           vuln.get("cveID", ""),
                    "vendor":           vuln.get("vendorProject", ""),
                    "product":          vuln.get("product", ""),
                    "date_added":       vuln.get("dateAdded", ""),
                    "known_ransomware": vuln.get("knownRansomwareCampaignUse") == "Known",
                    "description":      vuln.get("shortDescription", "")
                }
                for vuln in vulnerabilities
            ]

        except Exception as e:
            if attempt < max_retries:
                wait = 2 ** attempt
                log.warning("CISA KEV attempt %d/%d (waiting %ds): %s",
                            attempt + 1, max_retries, wait, e)
                time.sleep(wait)
            else:
                log.error("CISA KEV — all %d attempts failed: %s", max_retries, e)
                raise


def save_cisa_kev(data):
    db_save_cisa_kev(data)
    print(f"Saved {len(data)} CVEs to DB")


if __name__ == "__main__":
    data = fetch_cisa_kev()
    if data is not None:
        save_cisa_kev(data)