"""
Tests for PIIDetector
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from pii_detector import PIIDetector


@pytest.fixture(scope="module")
def detector():
    return PIIDetector()


class TestCleanInputs:
    def test_empty_string(self, detector):
        res = detector.analyze("")
        assert not res.has_pii
        assert res.entities == []
        assert res.max_confidence == 0.0

    def test_safe_question(self, detector):
        res = detector.analyze("What is the capital of France?")
        assert not res.has_pii

    def test_plain_text(self, detector):
        res = detector.analyze("The quick brown fox jumps over the lazy dog.")
        # No PII in this sentence
        assert res.max_confidence < 0.7 or not res.has_pii


class TestEmailDetection:
    def test_simple_email(self, detector):
        res = detector.analyze("Contact me at alice@example.com")
        assert res.has_pii
        types = [e["type"] for e in res.entities]
        assert any("EMAIL" in t.upper() or "email" in t.lower() for t in types)

    def test_complex_email(self, detector):
        res = detector.analyze("Send reports to john.doe+filter@company.co.uk")
        assert res.has_pii


class TestPhoneDetection:
    def test_pakistan_phone(self, detector):
        res = detector.analyze("Call me at 03001234567")
        assert res.has_pii

    def test_international_phone(self, detector):
        res = detector.analyze("Reach me at +923001234567")
        assert res.has_pii


class TestApiKeyDetection:
    def test_openai_key(self, detector):
        res = detector.analyze("My API key is sk-abcdefghijklmnopqrstuvwx1234567890")
        assert res.has_pii
        types = [e["type"] for e in res.entities]
        assert any("API" in t.upper() or "KEY" in t.upper() for t in types)

    def test_aws_key(self, detector):
        res = detector.analyze("AWS access key: AKIAIOSFODNN7EXAMPLE")
        assert res.has_pii

    def test_github_token(self, detector):
        res = detector.analyze("ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXX1234AB")
        assert res.has_pii


class TestCNICDetection:
    def test_valid_cnic(self, detector):
        res = detector.analyze("My CNIC is 42201-1234567-9")
        assert res.has_pii


class TestMasking:
    def test_mask_replaces_text(self, detector):
        text = "Email me at alice@example.com please."
        res = detector.analyze(text)
        if res.has_pii:
            masked = detector.mask(text, res.entities)
            assert "alice@example.com" not in masked
            assert "[REDACTED]" in masked

    def test_mask_empty_entities(self, detector):
        text = "Hello world"
        assert detector.mask(text, []) == text

    def test_multiple_pii_masked(self, detector):
        text = "Call 03001234567 or email me at bob@test.com"
        res = detector.analyze(text)
        if res.has_pii:
            masked = detector.mask(text, res.entities)
            assert "[REDACTED]" in masked
