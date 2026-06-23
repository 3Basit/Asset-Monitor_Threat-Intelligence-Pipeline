"""Tests for CVE-to-asset matching logic — version parsing, CPE ranges, confidence."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from matching import (
    parse_version,
    version_in_cpe_range,
    extract_cpe_version,
    compute_match_confidence,
    detect_vuln_type,
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


if __name__ == "__main__":
    unittest.main()
