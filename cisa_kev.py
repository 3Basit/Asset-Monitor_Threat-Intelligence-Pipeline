import requests
import json

import config
from logger import get_logger
from database import save_cisa_kev as db_save_cisa_kev

log = get_logger("cisa_kev")

def fetch_cisa_kev(max_retries=3):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                log.warning("CISA KEV returned empty vulnerabilities list")
                return []

            filtered = []
            for vuln in vulnerabilities:
                filtered.append({
                    "cve_id":           vuln.get("cveID", ""),
                    "vendor":           vuln.get("vendorProject", ""),
                    "product":          vuln.get("product", ""),
                    "date_added":       vuln.get("dateAdded", ""),
                    "known_ransomware": vuln.get("knownRansomwareCampaignUse") == "Known",
                    "description":      vuln.get("shortDescription", "")
                })
            return filtered
        except Exception as e:
            if attempt < max_retries:
                wait = 2 ** attempt
                log.warning("CISA KEV attempt %d/%d (waiting %ds): %s", attempt + 1, max_retries, wait, e)
                import time
                time.sleep(wait)
            else:
                log.error("CISA KEV — all %d attempts failed: %s", max_retries, e)
                raise

def save_cisa_kev(data):
    db_save_cisa_kev(data)
    print(f"Saved {len(data)} CVEs to DB")

if __name__ == "__main__":
    data = fetch_cisa_kev()
    save_cisa_kev(data)