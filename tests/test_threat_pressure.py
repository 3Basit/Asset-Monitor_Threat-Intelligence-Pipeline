"""Tests for TPF (Threat Pressure Factor) computation — the core scoring logic."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from threat_pressure import compute_tpf, get_alert_level


class TestComputeTPF(unittest.TestCase):

    def _make_record(self, **overrides):
        base = {
            "cvss_score": None,
            "epss_score": None,
            "known_ransomware": False,
            "vuln_type": "unknown",
            "business_criticality": "low",
            "date_added": "2020-01-01",
            "version_confirmed": False,
            "confirmation_method": "none",
            "has_public_exploit": False,
        }
        base.update(overrides)
        return base

    def test_tpf_range(self):
        """TPF must always be between 1.0 and 2.0."""
        record = self._make_record()
        _, tpf = compute_tpf(record)
        self.assertGreaterEqual(tpf, 1.0)
        self.assertLessEqual(tpf, 2.0)

    def test_max_severity_record(self):
        """A worst-case record should produce high TPF."""
        record = self._make_record(
            cvss_score=10.0,
            epss_score=0.95,
            known_ransomware=True,
            vuln_type="rce",
            business_criticality="critical",
            date_added="2026-06-01",
            version_confirmed=True,
            confirmation_method="cpe_range",
            has_public_exploit=True,
        )
        score, tpf = compute_tpf(record)
        self.assertGreaterEqual(tpf, 1.7)

    def test_minimal_record(self):
        """A record with no severity signals should produce low TPF."""
        record = self._make_record(
            cvss_score=2.0,
            epss_score=0.01,
        )
        _, tpf = compute_tpf(record)
        self.assertLess(tpf, 1.5)

    def test_kev_always_adds(self):
        """KEV presence always adds 0.13."""
        record = self._make_record()
        score, _ = compute_tpf(record)
        self.assertGreaterEqual(score, 0.13)

    def test_cvss_thresholds(self):
        """CVSS 9+ should contribute more than CVSS 7."""
        rec_critical = self._make_record(cvss_score=9.5)
        rec_high = self._make_record(cvss_score=7.5)
        rec_medium = self._make_record(cvss_score=5.0)

        s_crit, _ = compute_tpf(rec_critical)
        s_high, _ = compute_tpf(rec_high)
        s_med, _ = compute_tpf(rec_medium)

        self.assertGreater(s_crit, s_high)
        self.assertGreater(s_high, s_med)

    def test_epss_thresholds(self):
        """Higher EPSS should produce higher score."""
        rec_high = self._make_record(epss_score=0.8)
        rec_low = self._make_record(epss_score=0.05)

        s_high, _ = compute_tpf(rec_high)
        s_low, _ = compute_tpf(rec_low)
        self.assertGreater(s_high, s_low)

    def test_exploit_bonus(self):
        """Public exploit should increase score."""
        rec_with = self._make_record(has_public_exploit=True)
        rec_without = self._make_record(has_public_exploit=False)

        s_with, _ = compute_tpf(rec_with)
        s_without, _ = compute_tpf(rec_without)
        self.assertGreater(s_with, s_without)

    def test_version_confirmed_cpe_only(self):
        """Only CPE-range confirmation adds bonus, not text_search."""
        rec_cpe = self._make_record(version_confirmed=True, confirmation_method="cpe_range")
        rec_text = self._make_record(version_confirmed=True, confirmation_method="text_search")
        rec_none = self._make_record(version_confirmed=False)

        s_cpe, _ = compute_tpf(rec_cpe)
        s_text, _ = compute_tpf(rec_text)
        s_none, _ = compute_tpf(rec_none)

        self.assertGreater(s_cpe, s_text)
        self.assertEqual(s_text, s_none)

    def test_none_fields_dont_crash(self):
        """None values for optional fields should not raise."""
        record = self._make_record(cvss_score=None, epss_score=None)
        score, tpf = compute_tpf(record)
        self.assertIsInstance(tpf, float)


class TestAlertLevel(unittest.TestCase):

    def test_critical(self):
        self.assertEqual(get_alert_level(1.8), "CRITICAL")

    def test_high(self):
        self.assertEqual(get_alert_level(1.5), "HIGH")

    def test_medium(self):
        self.assertEqual(get_alert_level(1.3), "MEDIUM")

    def test_low(self):
        self.assertEqual(get_alert_level(1.1), "LOW")

    def test_boundary_critical(self):
        self.assertEqual(get_alert_level(1.7), "CRITICAL")

    def test_boundary_high(self):
        self.assertEqual(get_alert_level(1.5), "HIGH")


if __name__ == "__main__":
    unittest.main()
