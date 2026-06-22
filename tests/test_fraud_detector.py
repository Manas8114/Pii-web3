import os
import sys

# Need to make sure enhanced_fraud_detector is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from enhanced_fraud_detector import EnhancedFraudDetector

def test_fraud_detector_init():
    detector = EnhancedFraudDetector()
    assert detector is not None

import pytest

def test_fraud_analysis_invalid_file():
    detector = EnhancedFraudDetector()
    with pytest.raises(Exception):
        detector.analyze_document("non_existent_file.pdf")
