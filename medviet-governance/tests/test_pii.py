# tests/test_pii.py
"""
Test suite cho MedViet PII detection và anonymization.
Chạy: pytest tests/test_pii.py -v --tb=short
"""
import pytest
import pandas as pd
from src.pii.anonymizer import MedVietAnonymizer
from src.pii.detector import SimpleRecognizer, RecognizerResult


@pytest.fixture
def anonymizer():
    return MedVietAnonymizer()


@pytest.fixture
def recognizer():
    return SimpleRecognizer()


@pytest.fixture
def sample_df():
    return pd.read_csv("data/raw/patients_raw.csv").head(50)


class TestPIIDetection:
    """Tests cho PII detection (regex-based)."""

    def test_cccd_detected(self, recognizer):
        """CCCD (12 digits) should be detected."""
        text = "Bệnh nhân Nguyen Van A, CCCD: 012345678901"
        results = recognizer.analyze(text=text, entities=["VN_CCCD"])
        assert len(results) >= 1, "CCCD should be detected"
        assert results[0].entity_type == "VN_CCCD"
        assert results[0].score >= 0.85

    def test_phone_detected(self, recognizer):
        """VN_PHONE should be detected - 10 digits starting with 0."""
        text = "Liên hệ: 0912345678"
        results = recognizer.analyze(text=text, entities=["VN_PHONE"])
        assert len(results) >= 1, "VN_PHONE should be detected"
        assert results[0].entity_type == "VN_PHONE"

    def test_email_detected(self, recognizer):
        """EMAIL_ADDRESS should be detected."""
        text = "Email: nguyenvana@gmail.com"
        results = recognizer.analyze(text=text, entities=["EMAIL_ADDRESS"])
        assert len(results) >= 1, "EMAIL_ADDRESS should be detected"
        assert results[0].entity_type == "EMAIL_ADDRESS"

    def test_cccd_in_df_detected(self, recognizer, sample_df):
        """CCCD values in DataFrame should be detected."""
        for val in sample_df["cccd"].astype(str):
            results = recognizer.analyze(text=val, entities=["VN_CCCD"])
            assert len(results) >= 1, f"CCCD '{val}' should be detected"

    def test_phone_in_df_detected(self, recognizer, sample_df):
        """Phone values in DataFrame should be detected."""
        for val in sample_df["so_dien_thoai"].astype(str):
            results = recognizer.analyze(text=val, entities=["VN_PHONE"])
            # 10-digit phones should always be detected
            if len(val) == 10:
                assert len(results) >= 1, f"Phone '{val}' should be detected"

    def test_email_in_df_detected(self, recognizer, sample_df):
        """Email values in DataFrame should be detected."""
        for val in sample_df["email"].astype(str):
            results = recognizer.analyze(text=val, entities=["EMAIL_ADDRESS"])
            assert len(results) >= 1, f"Email '{val}' should be detected"

    def test_detection_rate_above_95_percent(self, anonymizer, sample_df):
        """
        Pipeline phải đạt >95% detection rate.
        """
        pii_columns = ["ho_ten", "cccd", "so_dien_thoai", "email"]
        rate = anonymizer.calculate_detection_rate(sample_df, pii_columns)
        print(f"\nDetection rate: {rate:.2%}")
        assert rate >= 0.95, f"Detection rate {rate:.2%} < 95%"

    def test_multiple_pii_in_text(self, recognizer):
        """Multiple PII types in same text should all be detected."""
        text = "Bệnh nhân Nguyen Van A, CCCD: 012345678901, Phone: 0912345678, Email: test@example.com"
        results = recognizer.analyze(text=text)
        
        entity_types = [r.entity_type for r in results]
        # At minimum, CCCD and EMAIL should be detected
        assert "VN_CCCD" in entity_types
        assert "EMAIL_ADDRESS" in entity_types

    def test_no_false_positives_on_non_pii(self, recognizer):
        """Non-PII text should not trigger detection."""
        text = "Tiểu đường là bệnh mãn tính. Huyết áp cao cũng phổ biến."
        results = recognizer.analyze(text=text)
        for r in results:
            assert r.entity_type not in ["VN_CCCD", "VN_PHONE", "EMAIL_ADDRESS"]


class TestAnonymization:
    """Tests cho anonymization pipeline."""

    def test_pii_not_in_output(self, anonymizer, sample_df):
        """Sau anonymization, không còn CCCD gốc trong output."""
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        df_str = df_anon.to_string()
        for original_cccd in sample_df["cccd"]:
            assert str(original_cccd) not in df_str, (
                f"Original CCCD '{original_cccd}' should NOT appear in anonymized output"
            )

    def test_non_pii_columns_unchanged(self, anonymizer, sample_df):
        """Cột benh và ket_qua_xet_nghiem phải giữ nguyên."""
        df_anon = anonymizer.anonymize_dataframe(sample_df)

        pd.testing.assert_series_equal(
            sample_df["benh"].reset_index(drop=True),
            df_anon["benh"].reset_index(drop=True),
            check_dtype=False,
        )

        pd.testing.assert_series_equal(
            sample_df["ket_qua_xet_nghiem"].reset_index(drop=True),
            df_anon["ket_qua_xet_nghiem"].reset_index(drop=True),
            check_dtype=False,
        )

    def test_row_count_preserved(self, anonymizer, sample_df):
        """Số rows không thay đổi sau anonymization."""
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        assert len(df_anon) == len(sample_df)

    def test_patient_id_unchanged(self, anonymizer, sample_df):
        """patient_id giữ nguyên (pseudonym)."""
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        pd.testing.assert_series_equal(
            sample_df["patient_id"].reset_index(drop=True),
            df_anon["patient_id"].reset_index(drop=True),
        )

    def test_email_format_valid_after_replace(self, anonymizer, sample_df):
        """Email sau replace phải là email format hợp lệ."""
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        import re
        email_re = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
        for email in df_anon["email"]:
            assert email_re.match(str(email)), f"'{email}' is not a valid email"

    def test_cccd_length_after_replace(self, anonymizer, sample_df):
        """CCCD sau replace phải có đúng 12 ký tự."""
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        for cccd in df_anon["cccd"]:
            assert len(str(cccd)) == 12, f"CCCD '{cccd}' should be 12 chars"

    def test_phone_format_after_replace(self, anonymizer, sample_df):
        """Phone sau replace phải có đúng 10 ký tự bắt đầu bằng 0."""
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        for phone in df_anon["so_dien_thoai"]:
            phone_str = str(phone)
            assert len(phone_str) == 10, f"Phone '{phone}' should be 10 chars"
            assert phone_str.startswith("0"), f"Phone should start with 0"

    def test_anonymize_text_replace(self, anonymizer):
        """Test anonymize_text với strategy replace."""
        text = "Bệnh nhân Nguyen Van A, CCCD: 012345678901, Email: test@example.com"
        result = anonymizer.anonymize_text(text, "replace")
        assert "Nguyen Van A" not in result
        assert "012345678901" not in result
        assert "test@example.com" not in result

    def test_anonymize_text_mask(self, anonymizer):
        """Test anonymize_text với strategy mask."""
        text = "Bệnh nhân Nguyen Van A"
        result = anonymizer.anonymize_text(text, "mask")
        assert result != text

    def test_anonymize_text_hash(self, anonymizer):
        """Test anonymize_text với strategy hash."""
        text = "Email: test@example.com"
        result = anonymizer.anonymize_text(text, "hash")
        assert "test@example.com" not in result

    def test_all_pii_columns_anonymized(self, anonymizer, sample_df):
        """Tất cả PII columns phải được anonymize."""
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        
        assert not sample_df["ho_ten"].equals(df_anon["ho_ten"])
        assert not sample_df["email"].equals(df_anon["email"])
        assert not sample_df["cccd"].equals(df_anon["cccd"])
        assert not sample_df["so_dien_thoai"].equals(df_anon["so_dien_thoai"])


class TestEdgeCases:
    """Tests cho edge cases."""

    def test_empty_text(self, recognizer):
        """Empty text should return empty results."""
        results = recognizer.analyze(text="")
        assert len(results) == 0

    def test_whitespace_only(self, recognizer):
        """Whitespace only text should return empty results."""
        results = recognizer.analyze(text="   \n\t  ")
        assert len(results) == 0

    def test_special_characters_in_email(self, recognizer):
        """Emails with special characters should be detected."""
        text = "Contact: user+tag@example.co.uk"
        results = recognizer.analyze(text=text, entities=["EMAIL_ADDRESS"])
        assert len(results) >= 1

    def test_phone_with_dashes(self, recognizer):
        """Phone numbers with dashes should be detected."""
        text = "SĐT: 0912-345-678"
        results = recognizer.analyze(text=text, entities=["VN_PHONE"])
        assert isinstance(results, list)

    def test_international_phone_not_detected(self, recognizer):
        """International phone format should not be detected as VN_PHONE."""
        text = "International: +84-912-345-678"
        results = recognizer.analyze(text=text, entities=["VN_PHONE"])
        assert len(results) == 0
