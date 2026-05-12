# src/pii/__init__.py
"""
MedViet PII Detection & Anonymization Module.
Regex-based implementation (no AI/ML models).
"""
from .detector import (
    RecognizerResult,
    SimpleRecognizer,
    AnalyzerEngine,
    build_vietnamese_analyzer,
    detect_pii,
    get_recognizer,
    get_default_analyzer,
)
from .anonymizer import MedVietAnonymizer

__all__ = [
    "RecognizerResult",
    "SimpleRecognizer",
    "AnalyzerEngine",
    "build_vietnamese_analyzer",
    "detect_pii",
    "get_recognizer",
    "get_default_analyzer",
    "MedVietAnonymizer",
]
