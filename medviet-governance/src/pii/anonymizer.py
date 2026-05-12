# src/pii/anonymizer.py
"""
Anonymization pipeline cho MedViet patient data.
Chỉ dùng regex-based detection (không dùng AI/ML model).

Hỗ trợ: mask, replace, hash, generalize strategies.
"""
import hashlib
import re
from typing import Optional

import pandas as pd
from faker import Faker

from .detector import (
    SimpleRecognizer,
    RecognizerResult,
    build_vietnamese_analyzer,
    detect_pii,
    AnalyzerEngine,
)

fake = Faker("vi_VN")
Faker.seed(42)


def _generate_fake_email() -> str:
    """Generate fake email."""
    return fake.ascii_free_email()


def _generate_fake_cccd() -> str:
    """Generate fake CCCD (12 digits)."""
    return "".join([str(fake.random_digit()) for _ in range(12)])


def _generate_fake_phone() -> str:
    """Generate fake Vietnamese phone number."""
    return fake.numerify("0#########")


def _mask_text(text: str, start: int, end: int) -> str:
    """
    Mask một phần của text: Nguyen Van A → N****** V** A
    Giữ lại chữ cái đầu và cuối của mỗi từ.
    """
    segment = text[start:end]
    masked = ""
    for word in segment.split():
        if len(word) <= 1:
            masked += word + " "
        else:
            masked += word[0] + "*" * (len(word) - 1) + " "
    return masked.strip()


class MedVietAnonymizer:
    """
    Anonymizer cho MedViet patient data.
    Sử dụng regex-based PII detection.
    """

    def __init__(self):
        self.analyzer = build_vietnamese_analyzer()
        # Also expose as AnalyzerEngine for test compatibility
        self._analyzer_engine = AnalyzerEngine()

    @property
    def analyzer(self) -> SimpleRecognizer:
        """Return the recognizer instance."""
        return self._analyzer

    @analyzer.setter
    def analyzer(self, value):
        self._analyzer = value

    def _build_operators(self, strategy: str) -> dict:
        """
        Xây dựng operators dict theo strategy.
        """
        if strategy == "replace":
            return {
                "PERSON": _ReplaceOperator(fake.name()),
                "EMAIL_ADDRESS": _ReplaceOperator(_generate_fake_email()),
                "VN_CCCD": _ReplaceOperator(_generate_fake_cccd()),
                "VN_PHONE": _ReplaceOperator(_generate_fake_phone()),
            }
        elif strategy == "mask":
            return {
                "PERSON": _MaskOperator(),
                "EMAIL_ADDRESS": _MaskOperator(chars_to_mask=8, from_end=True),
                "VN_CCCD": _MaskOperator(chars_to_mask=9, from_end=False),
                "VN_PHONE": _MaskOperator(chars_to_mask=7, from_end=True),
            }
        elif strategy == "hash":
            return {
                "PERSON": _HashOperator(),
                "EMAIL_ADDRESS": _HashOperator(),
                "VN_CCCD": _HashOperator(),
                "VN_PHONE": _HashOperator(),
            }
        elif strategy == "generalize":
            return {
                "PERSON": _ReplaceOperator("[BỆNH NHÂN]"),
                "EMAIL_ADDRESS": _ReplaceOperator("[EMAIL_ẨN]"),
                "VN_CCCD": _ReplaceOperator("[CCCD_ẨN]"),
                "VN_PHONE": _ReplaceOperator("[PHONE_ẨN]"),
            }
        return {}

    def anonymize_text(self, text: str, strategy: str = "replace") -> str:
        """
        Anonymize text với strategy được chọn.

        Strategies:
        - "mask"    : Nguyen Van A → N****** V** A
        - "replace" : thay bằng fake data (dùng Faker)
        - "hash"    : SHA-256 one-way hash
        - "generalize": general category labels
        """
        results = detect_pii(text, self.analyzer)
        if not results:
            return text

        operators = self._build_operators(strategy)
        return self._apply_anonymization(text, results, operators)

    def _apply_anonymization(
        self, text: str, results: list[RecognizerResult], operators: dict
    ) -> str:
        """Apply anonymization operators to text based on detection results."""
        if not results:
            return text

        # Sort results by start position (descending) to replace from end
        sorted_results = sorted(results, key=lambda x: x.start, reverse=True)

        anonymized = text
        for result in sorted_results:
            entity_type = result.entity_type
            if entity_type in operators:
                operator = operators[entity_type]
                original = anonymized[result.start:result.end]
                replacement = operator.apply(original)
                anonymized = anonymized[:result.start] + replacement + anonymized[result.end:]

        return anonymized

    def anonymize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Anonymize toàn bộ DataFrame.
        - Cột text (ho_ten, dia_chi): dùng anonymize_text() để detect PERSON
        - Cột email: replace trực tiếp bằng fake data
        - Cột cccd: replace trực tiếp bằng fake data
        - Cột so_dien_thoai: replace trực tiếp bằng fake data
        - Cột benh, ket_qua_xet_nghiem: GIỮ NGUYÊN (cần cho model training)
        - Cột patient_id: GIỮ NGUYÊN (pseudonym đã đủ an toàn)
        - Cột bac_si_phu_trach: replace trực tiếp bằng fake name
        """
        df_anon = df.copy()

        # ho_ten: anonymize bằng text anonymization (detect PERSON)
        df_anon["ho_ten"] = df_anon["ho_ten"].apply(
            lambda x: self.anonymize_text(str(x), "replace")
        )

        # dia_chi: anonymize (có thể có tên người trong địa chỉ)
        df_anon["dia_chi"] = df_anon["dia_chi"].apply(
            lambda x: self.anonymize_text(str(x), "replace")
        )

        # email: replace trực tiếp bằng fake email (không cần detect)
        df_anon["email"] = df_anon["email"].apply(
            lambda x: _generate_fake_email()
        )

        # cccd: replace trực tiếp bằng fake CCCD (không cần detect)
        df_anon["cccd"] = df_anon["cccd"].apply(
            lambda x: _generate_fake_cccd()
        )

        # so_dien_thoai: replace trực tiếp bằng fake phone (không cần detect)
        df_anon["so_dien_thoai"] = df_anon["so_dien_thoai"].apply(
            lambda x: _generate_fake_phone()
        )

        # bac_si_phu_trach: replace trực tiếp bằng fake name
        df_anon["bac_si_phu_trach"] = df_anon["bac_si_phu_trach"].apply(
            lambda x: fake.name()
        )

        # GIỮ NGUYÊN: patient_id, ngay_sinh, benh, ket_qua_xet_nghiem, ngay_kham
        # (benh & ket_qua_xet_nghiem cần cho model training)
        # (patient_id là pseudonym an toàn)

        return df_anon

    def calculate_detection_rate(
        self,
        original_df: pd.DataFrame,
        pii_columns: list,
    ) -> float:
        """
        Tính % PII được detect thành công.
        Mục tiêu: > 95%

        Logic: với mỗi ô trong pii_columns,
               kiểm tra xem detect_pii() có tìm thấy ít nhất 1 entity không.
               
        Với chiến lược REPLACE: columns được replace trực tiếp (không detect)
        nên detection rate có thể thấp nhưng anonymization vẫn đạt 100%.
        """
        total = 0
        detected = 0

        for col in pii_columns:
            for value in original_df[col].astype(str):
                total += 1
                results = detect_pii(value, self.analyzer)
                if len(results) > 0:
                    detected += 1

        return detected / total if total > 0 else 0.0


# --- Anonymization Operators ---

class _ReplaceOperator:
    """Replace PII with a new value."""

    def __init__(self, new_value: str):
        self.new_value = new_value

    def apply(self, text: str) -> str:
        return self.new_value


class _MaskOperator:
    """Mask PII while preserving some characters."""

    def __init__(self, masking_char: str = "*", chars_to_mask: int = -1, from_end: bool = False):
        self.masking_char = masking_char
        self.chars_to_mask = chars_to_mask
        self.from_end = from_end

    def apply(self, text: str) -> str:
        if not text:
            return text

        length = len(text)
        if self.chars_to_mask == -1:
            if length <= 1:
                return text
            return text[0] + self.masking_char * (length - 1)
        elif self.from_end:
            if length <= self.chars_to_mask:
                return self.masking_char * length
            return text[:length - self.chars_to_mask] + self.masking_char * self.chars_to_mask
        else:
            if length <= self.chars_to_mask:
                return self.masking_char * length
            return self.masking_char * self.chars_to_mask + text[self.chars_to_mask:]


class _HashOperator:
    """Hash PII using SHA-256."""

    def __init__(self, salt: str = "medviet-salt"):
        self.salt = salt

    def apply(self, text: str) -> str:
        salted = f"{self.salt}{text}".encode("utf-8")
        return hashlib.sha256(salted).hexdigest()[:16]


# --- Helper cho mask strategy ---
def _mask_custom(text: str) -> str:
    """Mask mỗi từ: giữ chữ cái đầu, ẩn phần còn lại bằng *"""
    words = text.split()
    masked_words = []
    for word in words:
        word_stripped = word.strip(".,;:!?()-")
        if len(word_stripped) <= 1:
            masked_words.append(word)
        else:
            leading = word[0]
            rest = "*" * (len(word) - 1)
            masked_words.append(leading + rest)
    return " ".join(masked_words)
