import requests
import json
import time
import os
from database import get_cisa_kev, get_assets, save_enriched_cves as db_save_enriched_cves

NVD_API_KEY = os.getenv("NVD_API_KEY", "")


def is_relevant(vuln, assets):
    text = f"{vuln['vendor']} {vuln['product']} {vuln['description']}".lower()
    for asset in assets:
        for keyword in asset["keywords"]:
            if keyword.lower() in text:
                return True
    return False


def extract_cpe_ranges(cve_data):
    """
    Extract CPE version ranges from NVD API response.
    Returns a list of dicts with version boundary fields.
    Used by matching.py for precise version confirmation.
    """
    ranges = []
    try:
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable", False):
                        continue
                    ranges.append({
                        "criteria":                  cpe_match.get("criteria", ""),
                        "version_start_including":   cpe_match.get("versionStartIncluding"),
                        "version_start_excluding":   cpe_match.get("versionStartExcluding"),
                        "version_end_including":     cpe_match.get("versionEndIncluding"),
                        "version_end_excluding":     cpe_match.get("versionEndExcluding"),
                    })
    except Exception:
        pass
    return ranges


def fetch_nvd_details(cve_id):
    url     = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        data     = response.json()
        cve      = data["vulnerabilities"][0]["cve"]

        try:
            cvss_score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            severity   = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        except Exception:
            try:
                cvss_score = cve["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
                severity   = cve["metrics"]["cvssMetricV2"][0]["baseSeverity"]
            except Exception:
                cvss_score = None
                severity   = None

        cpe_ranges = extract_cpe_ranges(cve)

        return {
            "cvss_score": cvss_score,
            "severity":   severity,
            "published":  cve["published"][:10],
            "cpe_ranges": cpe_ranges,
        }
    except Exception:
        return {"cvss_score": None, "severity": None, "published": None, "cpe_ranges": []}


def fetch_epss(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200 or not response.text.strip():
            return {"epss_score": None, "epss_percentile": None}
        data = response.json()
        if not data.get("data"):
            return {"epss_score": None, "epss_percentile": None}
        return {
            "epss_score":      float(data["data"][0]["epss"]),
            "epss_percentile": float(data["data"][0]["percentile"])
        }
    except Exception:
        return {"epss_score": None, "epss_percentile": None}


def enrich_cves():
    cisa_data = get_cisa_kev()
    assets    = get_assets()

    if not cisa_data:
        print("[ERROR] cisa_kev table is empty. Run Step 1 first.")
        return

    if not assets:
        print("[ERROR] assets table is empty. Run Asset Monitor first.")
        return

    relevant = [v for v in cisa_data if is_relevant(v, assets)]
    print(f"Relevant CVEs: {len(relevant)} out of {len(cisa_data)}")

    enriched = []
    for i, vuln in enumerate(relevant):
        print(f"Fetching {i+1}/{len(relevant)} - {vuln['cve_id']}")
        nvd  = fetch_nvd_details(vuln["cve_id"])
        epss = fetch_epss(vuln["cve_id"])

        record = {**vuln, **epss,
                  "cvss_score": nvd["cvss_score"],
                  "severity":   nvd["severity"],
                  "published":  nvd["published"],
                  "cpe_ranges": nvd["cpe_ranges"]}

        cpe_count = len(nvd["cpe_ranges"])
        if cpe_count:
            print(f"  → {cpe_count} CPE version range(s) extracted")

        enriched.append(record)
        time.sleep(0.6)

    db_save_enriched_cves(enriched)
    print(f"Saved {len(enriched)} enriched CVEs to DB")


if __name__ == "__main__":
    enrich_cves()
