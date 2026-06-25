"""Tests for CVE-to-asset matching logic — version parsing, CPE ranges, confidence."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch
from matching import (
    parse_version,
    version_in_cpe_range,
    extract_cpe_version,
    compute_match_confidence,
    detect_vuln_type,
    check_version_confirmed,
)


class TestParseVersion(unittest.TestCase):

    def test_simple(self):
        self.assertEqual(parse_version("1.2.3"), (1, 2, 3))

    def test_two_parts(self):
        self.assertEqual(parse_version("10.0"), (10, 0))

    def test_single(self):
        self.assertEqual(parse_version("7"), (7,))

    def test_with_suffix(self):
        self.assertEqual(parse_version("1.2.3-beta"), (1, 2, 3))

    def test_none(self):
        self.assertIsNone(parse_version(None))

    def test_empty(self):
        self.assertIsNone(parse_version(""))

    def test_non_numeric(self):
        self.assertIsNone(parse_version("abc"))

    def test_max_four_parts(self):
        self.assertEqual(parse_version("1.2.3.4.5"), (1, 2, 3, 4))


class TestExtractCpeVersion(unittest.TestCase):

    def test_iis(self):
        cpe = "cpe:2.3:a:microsoft:internet_information_services:6.0:*:*:*:*:*:*:*"
        self.assertEqual(extract_cpe_version(cpe), "6.0")

    def test_wildcard(self):
        cpe = "cpe:2.3:a:microsoft:iis:*:*:*:*:*:*:*:*"
        self.assertIsNone(extract_cpe_version(cpe))

    def test_none(self):
        self.assertIsNone(extract_cpe_version(None))

    def test_short(self):
        self.assertIsNone(extract_cpe_version("cpe:2.3:a"))


class TestVersionInCpeRange(unittest.TestCase):

    def test_in_range_inclusive(self):
        cpe_range = {
            "version_start_including": "1.0",
            "version_end_including": "2.0",
        }
        self.assertTrue(version_in_cpe_range("1.5", cpe_range))

    def test_at_start_boundary(self):
        cpe_range = {
            "version_start_including": "1.0",
            "version_end_including": "2.0",
        }
        self.assertTrue(version_in_cpe_range("1.0", cpe_range))

    def test_at_end_boundary(self):
        cpe_range = {
            "version_start_including": "1.0",
            "version_end_including": "2.0",
        }
        self.assertTrue(version_in_cpe_range("2.0", cpe_range))

    def test_below_range(self):
        cpe_range = {
            "version_start_including": "2.0",
            "version_end_including": "3.0",
        }
        self.assertFalse(version_in_cpe_range("1.9", cpe_range))

    def test_above_range(self):
        cpe_range = {
            "version_start_including": "1.0",
            "version_end_excluding": "2.0",
        }
        self.assertFalse(version_in_cpe_range("2.0", cpe_range))

    def test_excluding_start(self):
        cpe_range = {
            "version_start_excluding": "1.0",
            "version_end_including": "2.0",
        }
        self.assertFalse(version_in_cpe_range("1.0", cpe_range))
        self.assertTrue(version_in_cpe_range("1.1", cpe_range))

    def test_exact_match(self):
        cpe_range = {
            "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        }
        self.assertTrue(version_in_cpe_range("2.4.49", cpe_range))
        self.assertFalse(version_in_cpe_range("2.4.50", cpe_range))

    def test_wildcard_no_boundaries(self):
        cpe_range = {
            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        }
        self.assertFalse(version_in_cpe_range("2.4.49", cpe_range))

    def test_none_version(self):
        cpe_range = {"version_start_including": "1.0", "version_end_including": "2.0"}
        self.assertFalse(version_in_cpe_range(None, cpe_range))

    def test_only_end_boundary(self):
        cpe_range = {"version_end_excluding": "10.0"}
        self.assertTrue(version_in_cpe_range("9.0", cpe_range))
        self.assertFalse(version_in_cpe_range("10.0", cpe_range))


class TestComputeMatchConfidence(unittest.TestCase):

    def test_high_confidence(self):
        cve = {"vendor": "Microsoft", "product": "IIS"}
        asset = {"vendor": "Microsoft", "keywords": ["IIS", "web"]}
        self.assertEqual(compute_match_confidence(cve, asset), "high")

    def test_low_no_vendor_match(self):
        cve = {"vendor": "Apache", "product": "httpd"}
        asset = {"vendor": "Microsoft", "keywords": ["httpd"]}
        self.assertEqual(compute_match_confidence(cve, asset), "low")

    def test_none_vendor(self):
        cve = {"vendor": None, "product": "something"}
        asset = {"vendor": None, "keywords": ["something"]}
        self.assertEqual(compute_match_confidence(cve, asset), "low")

    def test_short_keywords_ignored(self):
        cve = {"vendor": "test", "product": "is a thing"}
        asset = {"vendor": "test", "keywords": ["is", "a"]}
        self.assertEqual(compute_match_confidence(cve, asset), "low")


class TestDetectVulnType(unittest.TestCase):

    def test_rce(self):
        self.assertEqual(detect_vuln_type("allows remote code execution"), "rce")

    def test_sqli(self):
        self.assertEqual(detect_vuln_type("SQL injection vulnerability"), "sqli")

    def test_xss(self):
        self.assertEqual(detect_vuln_type("Cross-site scripting (XSS)"), "xss")

    def test_path_traversal(self):
        self.assertEqual(detect_vuln_type("path traversal via ../"), "path_traversal")

    def test_unknown(self):
        self.assertEqual(detect_vuln_type("buffer overflow issue"), "other")

    def test_none(self):
        self.assertEqual(detect_vuln_type(None), "unknown")

    def test_empty(self):
        self.assertEqual(detect_vuln_type(""), "unknown")


# ── New: _criteria_matches_product behavior ───────────────────────────────────

class TestCriteriaMatchesProduct(unittest.TestCase):
    """Unit tests for the CPE vendor/product field filter.

    _criteria_matches_product is an inner function — we test it indirectly
    via check_version_confirmed by mocking get_asset_services.

    Key invariant: only CPE ranges whose vendor [3] or product [4] field
    matches the asset keyword should be used for version confirmation.
    """

    def _svc(self, product, version):
        return [{"product": product, "service_name": product, "version": version}]

    def _cve(self, cpe_ranges, description="test vuln"):
        return {
            "cve_id": "CVE-TEST-0001",
            "vendor": "nginx",
            "product": "nginx",
            "date_added": None,
            "description": description,
            "cpe_ranges": cpe_ranges,
        }

    @patch("matching.get_asset_services")
    def test_matching_vendor_product_confirms(self, mock_svc):
        """nginx CPE with nginx in vendor+product fields confirms nginx 1.18.0."""
        mock_svc.return_value = self._svc("nginx", "1.18.0")
        cve = self._cve([{
            "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
            "version_start_including": "0.6.18",
            "version_end_excluding": "1.20.1",
            "version_start_excluding": None,
            "version_end_including": None,
        }])
        confirmed, version, method, _ = check_version_confirmed(cve, "ASSET-001")
        self.assertTrue(confirmed)
        self.assertEqual(method, "cpe_range")
        self.assertEqual(version, "1.18.0")

    @patch("matching.get_asset_services")
    def test_unrelated_vendor_not_confirmed(self, mock_svc):
        """CPE from unrelated vendor (f5) must not confirm nginx asset."""
        mock_svc.return_value = self._svc("nginx", "1.18.0")
        cve = self._cve([{
            "criteria": "cpe:2.3:a:f5:big_ip_local_traffic_manager:*:*:*:*:*:*:*:*",
            "version_start_including": None,
            "version_end_including": "14.0",
            "version_start_excluding": None,
            "version_end_excluding": None,
        }])
        confirmed, _, method, _ = check_version_confirmed(cve, "ASSET-001")
        self.assertFalse(confirmed)

    @patch("matching.get_asset_services")
    def test_os_cpe_is_skipped(self, mock_svc):
        """CPE with :o: type (OS-level) must be filtered out entirely."""
        mock_svc.return_value = self._svc("nginx", "1.18.0")
        cve = self._cve([{
            "criteria": "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*",
            "version_start_including": "0.1",
            "version_end_including": "99.0",
            "version_start_excluding": None,
            "version_end_excluding": None,
        }])
        confirmed, _, _, _ = check_version_confirmed(cve, "ASSET-001")
        self.assertFalse(confirmed, "OS CPE must never confirm a software product")

    @patch("matching.get_asset_services")
    def test_version_not_in_range_definitive_no(self, mock_svc):
        """When product CPE ranges exist but version is NOT in range → definitive no."""
        mock_svc.return_value = self._svc("nginx", "1.20.1")
        # 1.20.1 is NOT in >=0.6.18 <1.20.1 (end is exclusive)
        cve = self._cve([{
            "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
            "version_start_including": "0.6.18",
            "version_end_excluding": "1.20.1",
            "version_start_excluding": None,
            "version_end_including": None,
        }])
        confirmed, _, method, _ = check_version_confirmed(cve, "ASSET-001")
        self.assertFalse(confirmed)
        self.assertEqual(method, "none")

    @patch("matching.get_asset_services")
    def test_no_version_detected_returns_none(self, mock_svc):
        """Service with no version field → cannot confirm."""
        mock_svc.return_value = [{"product": "nginx", "service_name": "nginx", "version": None}]
        cve = self._cve([{
            "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
            "version_start_including": "0.1",
            "version_end_including": "2.0",
            "version_start_excluding": None,
            "version_end_excluding": None,
        }])
        confirmed, version, _, _ = check_version_confirmed(cve, "ASSET-001")
        self.assertFalse(confirmed)
        self.assertIsNone(version)


# ── Regression tests: exact false positives found in production ───────────────

class TestCPEFalsePositiveRegression(unittest.TestCase):
    """Regression tests for the 14 false positives caught in production.

    These CVEs were returned by NVD keyword search for 'nginx' because they
    mention nginx in their description, but their CPE ranges belong to
    completely unrelated products with incompatible version numbering.

    nginx 1.20.1 (a real version) numerically satisfied ranges like <=8.3
    because (1,20,1) < (8,3) is True in Python tuple comparison — but these
    ranges were for zzcms, pascom, sundray etc., not nginx.

    If ANY of these tests fail, the false positive bug has been re-introduced.
    """

    def _svc(self, version):
        return [{"product": "nginx", "service_name": "nginx", "version": version}]

    @patch("matching.get_asset_services")
    def test_zzcms_cpe_does_not_match_nginx_1_20_1(self, mock_svc):
        """CVE-2018-1000653: zzcms <=8.3 must NOT match nginx 1.20.1."""
        mock_svc.return_value = self._svc("1.20.1")
        cve = {
            "cve_id": "CVE-2018-1000653",
            "vendor": "nginx", "product": "nginx",
            "date_added": None,
            "description": "zzcms SQL injection",
            "cpe_ranges": [{
                "criteria": "cpe:2.3:a:zzcms:zzcms:*:*:*:*:*:*:*:*",
                "version_start_including": None, "version_start_excluding": None,
                "version_end_including": "8.3", "version_end_excluding": None,
            }],
        }
        confirmed, _, method, _ = check_version_confirmed(cve, "ASSET-001")
        self.assertFalse(confirmed, "zzcms <=8.3 must NOT confirm nginx 1.20.1")
        self.assertEqual(method, "none")

    @patch("matching.get_asset_services")
    def test_pascom_cpe_does_not_match_nginx_1_18_0(self, mock_svc):
        """CVE-2021-45967: pascom cloud_phone_system <=7.19 must NOT match nginx 1.18.0."""
        mock_svc.return_value = self._svc("1.18.0")
        cve = {
            "cve_id": "CVE-2021-45967",
            "vendor": "nginx", "product": "nginx",
            "date_added": None,
            "description": "pascom phone system path traversal",
            "cpe_ranges": [{
                "criteria": "cpe:2.3:a:pascom:cloud_phone_system:*:*:*:*:*:*:*:*",
                "version_start_including": None, "version_start_excluding": None,
                "version_end_including": "7.19", "version_end_excluding": None,
            }],
        }
        confirmed, _, _, _ = check_version_confirmed(cve, "ASSET-001")
        self.assertFalse(confirmed, "pascom <=7.19 must NOT confirm nginx 1.18.0")

    @patch("matching.get_asset_services")
    def test_sundray_cpe_does_not_match_nginx(self, mock_svc):
        """CVE-2019-9161: sundray_wan_controller <=3.7.4.2 must NOT match nginx."""
        mock_svc.return_value = self._svc("1.20.1")
        cve = {
            "cve_id": "CVE-2019-9161",
            "vendor": "nginx", "product": "nginx",
            "date_added": None,
            "description": "Sundray WAN controller command injection",
            "cpe_ranges": [{
                "criteria": "cpe:2.3:a:xinruidz:sundray_wan_controller_firmware:*:*:*:*:*:*:*:*",
                "version_start_including": None, "version_start_excluding": None,
                "version_end_including": "3.7.4.2", "version_end_excluding": None,
            }],
        }
        confirmed, _, _, _ = check_version_confirmed(cve, "ASSET-001")
        self.assertFalse(confirmed, "sundray <=3.7.4.2 must NOT confirm nginx 1.20.1")

    @patch("matching.get_asset_services")
    def test_bigbluebutton_cpe_does_not_match_nginx(self, mock_svc):
        """CVE-2020-12443: bigbluebutton <2.2.6 must NOT match nginx."""
        mock_svc.return_value = self._svc("1.18.0")
        cve = {
            "cve_id": "CVE-2020-12443",
            "vendor": "nginx", "product": "nginx",
            "date_added": None,
            "description": "BigBlueButton path traversal",
            "cpe_ranges": [{
                "criteria": "cpe:2.3:a:bigbluebutton:bigbluebutton:*:*:*:*:*:*:*:*",
                "version_start_including": None, "version_start_excluding": None,
                "version_end_including": None, "version_end_excluding": "2.2.6",
            }],
        }
        confirmed, _, _, _ = check_version_confirmed(cve, "ASSET-001")
        self.assertFalse(confirmed, "bigbluebutton <2.2.6 must NOT confirm nginx 1.18.0")

    @patch("matching.get_asset_services")
    def test_nginx_resolver_true_positive_preserved(self, mock_svc):
        """CVE-2021-23017: genuine nginx resolver bug must still confirm nginx 1.18.0.

        This is the one true positive that must survive all fixes.
        """
        mock_svc.return_value = self._svc("1.18.0")
        cve = {
            "cve_id": "CVE-2021-23017",
            "vendor": "nginx", "product": "nginx",
            "date_added": None,
            "description": "nginx resolver off-by-one heap write",
            "cpe_ranges": [{
                "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                "version_start_including": "0.6.18",
                "version_start_excluding": None,
                "version_end_including": None,
                "version_end_excluding": "1.20.1",
            }],
        }
        confirmed, version, method, _ = check_version_confirmed(cve, "ASSET-001")
        self.assertTrue(confirmed, "CVE-2021-23017 must confirm nginx 1.18.0")
        self.assertEqual(method, "cpe_range")
        self.assertEqual(version, "1.18.0")


if __name__ == "__main__":
    unittest.main()
