"""Tests for configuration module and basic project integrity."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest


class TestConfig(unittest.TestCase):

    def test_config_imports(self):
        import config
        self.assertTrue(hasattr(config, "DB_PATH"))
        self.assertTrue(hasattr(config, "NVD_API_KEY"))
        self.assertTrue(hasattr(config, "MODEL_DIR"))

    def test_db_path_default(self):
        import config
        self.assertTrue(config.DB_PATH.endswith("threat_intelligence.db"))

    def test_logger_imports(self):
        from logger import get_logger
        log = get_logger("test")
        self.assertIsNotNone(log)


class TestSchemaConsistency(unittest.TestCase):

    def test_training_features_match_schema(self):
        from prediction_model.schema import (
            TRAINING_NUMERIC_FEATURES,
            TRAINING_CATEGORICAL_FEATURES,
            get_magnitude_training_features,
        )
        raw = set(get_magnitude_training_features())
        cats = set(TRAINING_CATEGORICAL_FEATURES)
        self.assertTrue(cats.issubset(raw))

    def test_no_frequency_magnitude_overlap(self):
        from prediction_model.schema import (
            FREQUENCY_FEATURES,
            MAGNITUDE_COMPANY_FEATURES,
            MAGNITUDE_INCIDENT_FEATURES,
        )
        freq = set(FREQUENCY_FEATURES.keys())
        mag = set(MAGNITUDE_COMPANY_FEATURES.keys()) | set(MAGNITUDE_INCIDENT_FEATURES.keys())
        overlap = freq & mag
        self.assertEqual(overlap, set(), f"Overlap between frequency and magnitude: {overlap}")

    def test_region_excluded_from_training(self):
        from prediction_model.schema import get_magnitude_training_features
        features = get_magnitude_training_features()
        self.assertNotIn("region", features)


class TestAllModulesImport(unittest.TestCase):

    def test_import_database(self):
        import database
        self.assertTrue(hasattr(database, "init_db"))

    def test_import_matching(self):
        import matching
        self.assertTrue(hasattr(matching, "run_matching"))

    def test_import_threat_pressure(self):
        import threat_pressure
        self.assertTrue(hasattr(threat_pressure, "compute_tpf"))

    def test_import_fair_engine(self):
        from prediction_model import fair_engine
        self.assertTrue(hasattr(fair_engine, "calculate_fair"))

    def test_import_ibm_benchmarks(self):
        from prediction_model import ibm_benchmarks
        self.assertTrue(hasattr(ibm_benchmarks, "IBM_INDUSTRY_COST"))


if __name__ == "__main__":
    unittest.main()
