"""Tests for FAIR engine — feature vector building, credibility weighting, risk classification."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import numpy as np
from prediction_model.fair_engine import (
    credibility_weight,
    classify_risk_tier,
    _build_feature_vector,
    VULN_TYPE_TO_ATTACK,
)
from prediction_model.ibm_benchmarks import get_breach_rate, get_region_multiplier


class TestCredibilityWeight(unittest.TestCase):

    def test_zero_samples(self):
        self.assertAlmostEqual(credibility_weight(0), 0.0)

    def test_k_samples(self):
        self.assertAlmostEqual(credibility_weight(20, k=20), 0.5)

    def test_large_samples(self):
        z = credibility_weight(1000, k=20)
        self.assertGreater(z, 0.95)

    def test_monotonic(self):
        z10 = credibility_weight(10)
        z50 = credibility_weight(50)
        z200 = credibility_weight(200)
        self.assertLess(z10, z50)
        self.assertLess(z50, z200)


class TestClassifyRiskTier(unittest.TestCase):

    def test_critical(self):
        self.assertEqual(classify_risk_tier(3_000_000), "CRITICAL")

    def test_high(self):
        self.assertEqual(classify_risk_tier(1_000_000), "HIGH")

    def test_medium(self):
        self.assertEqual(classify_risk_tier(200_000), "MEDIUM")

    def test_low(self):
        self.assertEqual(classify_risk_tier(50_000), "LOW")

    def test_boundary_critical(self):
        self.assertEqual(classify_risk_tier(2_000_001), "CRITICAL")

    def test_boundary_high(self):
        self.assertEqual(classify_risk_tier(500_001), "HIGH")


class TestBuildFeatureVector(unittest.TestCase):

    def setUp(self):
        self.feature_names = [
            "company_size_score",
            "log_records_cost",
            "log_records_affected",
            "data_sensitivity_score",
            "incident_year_normalized",
            "industry_sector_healthcare",
            "industry_sector_financial",
            "attack_type_hacking",
            "attack_type_social",
        ]
        self.company = {
            "industry_sector": "healthcare",
            "employee_count_range": "1001 to 10000",
            "estimated_records": 50000,
            "data_sensitivity": "customer_pii",
            "region": "US",
        }
        self.vuln = {
            "vuln_type": "sqli",
            "asset_type": "web_application",
        }

    def test_output_shape(self):
        df = _build_feature_vector(self.vuln, self.company, self.feature_names)
        self.assertEqual(list(df.columns), self.feature_names)
        self.assertEqual(len(df), 1)

    def test_industry_one_hot(self):
        df = _build_feature_vector(self.vuln, self.company, self.feature_names)
        self.assertEqual(df["industry_sector_healthcare"].iloc[0], 1.0)
        self.assertEqual(df["industry_sector_financial"].iloc[0], 0.0)

    def test_attack_type_mapping(self):
        df = _build_feature_vector(self.vuln, self.company, self.feature_names)
        self.assertEqual(df["attack_type_hacking"].iloc[0], 1.0)
        self.assertEqual(df["attack_type_social"].iloc[0], 0.0)

    def test_numeric_features_positive(self):
        df = _build_feature_vector(self.vuln, self.company, self.feature_names)
        self.assertGreater(df["log_records_affected"].iloc[0], 0)
        self.assertGreater(df["incident_year_normalized"].iloc[0], 0)

    def test_unknown_features_zero(self):
        names = self.feature_names + ["nonexistent_feature"]
        df = _build_feature_vector(self.vuln, self.company, names)
        self.assertEqual(df["nonexistent_feature"].iloc[0], 0.0)

    def test_all_vuln_types_mapped(self):
        for vt in ["rce", "sqli", "xss", "auth_bypass", "ssrf", "path_traversal", "other", "unknown"]:
            attack_type, _ = VULN_TYPE_TO_ATTACK.get(vt, ("hacking", "Unknown"))
            self.assertEqual(attack_type, "hacking")


class TestIBMBenchmarks(unittest.TestCase):

    def test_breach_rate_known_industry(self):
        rate = get_breach_rate("healthcare")
        self.assertGreater(rate, 0)
        self.assertLess(rate, 1)

    def test_breach_rate_unknown_fallback(self):
        rate = get_breach_rate("nonexistent_industry")
        self.assertEqual(rate, get_breach_rate("global_average"))

    def test_region_multiplier_us(self):
        mult = get_region_multiplier("US")
        self.assertGreater(mult, 1.5)

    def test_region_multiplier_unknown(self):
        mult = get_region_multiplier("unknown_region")
        self.assertAlmostEqual(mult, 1.0)


if __name__ == "__main__":
    unittest.main()
