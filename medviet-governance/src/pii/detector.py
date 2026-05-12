# src/pii/detector.py
"""
PII Detector cho tiếng Việt - Regex Only (Không dùng model AI/ML).

Regex patterns cho:
  - VN_CCCD: Số CCCD VN (11-12 chữ số)
  - VN_PHONE: Số điện thoại VN (9-10 chữ số)
  - EMAIL_ADDRESS: Email address
  - PERSON: Vietnamese names
"""
import re
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class RecognizerResult:
    """Simple data class cho PII detection result."""
    entity_type: str
    start: int
    end: int
    score: float
    recognition_metadata: Optional[dict] = None


class SimpleRecognizer:
    """
    Regex-based PII recognizer.
    Detect VN_CCCD, VN_PHONE, EMAIL_ADDRESS, PERSON (Vietnamese names).
    """

    def __init__(self):
        # VN CCCD: 11-12 chữ số liên tiếp
        # Data có cả 11 và 12 chữ số
        self._cccd_pattern = re.compile(r'\b(\d{11,12})\b')
        self._cccd_context = ['cccd', 'căn cước', 'chứng minh', 'cmnd', 'số cccd']

        # VN Phone: 9-10 chữ số
        # Format: 0[3-9]xxxxxxxx (10 chữ số) hoặc 9 chữ số
        # 0912345678 = 10 digits (0 + 1 + 8 = 10)
        self._phone_10_pattern = re.compile(r'0[3-9]\d{8}')  # 10 digits total
        self._phone_9_pattern = re.compile(r'\b(\d{9})\b')  # exactly 9 digits
        self._phone_context = ['điện thoại', 'sđt', 'sdt', 'phone', 'liên hệ', 'tel', 'gọi']

        # Email: standard email pattern
        self._email_pattern = re.compile(
            r'\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b'
        )

        # Vietnamese person names
        self._vn_upper = 'A-ZÀÁÂÃÈÉÊÌÍÒÓÔÕÙÚĂĐĨŨƠƯĂẠẢẤẦẨẪẬẮẰẲẴẶẸẺẼỀỀỂỄỆỈỊỌỎỐỒỔỖỘỚỜỞỠỢỤỦỨỪỬỮỰỲỴÝ'
        self._vn_lower = 'a-zàáâãèéêìíòóôõùúăđĩũơưăạảấầẩẫậắằẳẵặẹẻẽềềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵý'
        
        # Full name pattern: 2-5 words, each starting with uppercase
        self._fullname_pattern = re.compile(
            rf'\b([{self._vn_upper}][{self._vn_lower}]+'
            rf'(?:[\s]+[{self._vn_upper}][{self._vn_lower}]+){{1,4}})\b'
        )

        self._name_prefixes = ['Ông', 'Bà', 'Anh', 'Chị', 'Cô', 'Bs', 'Bác sĩ', 'Dr.', 'Người']

    def _get_context(self, text: str, start: int, end: int, window: int = 30) -> str:
        """Lấy context xung quanh match để tăng accuracy."""
        context_start = max(0, start - window)
        context_end = min(len(text), end + window)
        return text[context_start:context_end].lower()

    def _has_context(self, text: str, keywords: list) -> bool:
        """Kiểm tra xem text có chứa context keywords không."""
        text_lower = text.lower()
        return any(kw in text_lower for kw in keywords)

    def _extract_vietnamese_name(self, text: str) -> List[RecognizerResult]:
        """Extract Vietnamese person names từ text."""
        results = []
        seen = set()

        for match in self._fullname_pattern.finditer(text):
            name = match.group(1).strip()
            words = name.split()
            
            if 2 <= len(words) <= 5:
                key = (match.start(), match.end())
                if key not in seen:
                    seen.add(key)
                    
                    context = self._get_context(text, match.start(), match.end())
                    context_keywords = [
                        'bệnh nhân', 'tên', 'họ tên', 'bs', 'bác sĩ', 
                        'người', 'khách hàng', 'bs.', 'bn:', 'bn '
                    ]
                    
                    has_prefix = any(p.lower() in context for p in self._name_prefixes)
                    score = 0.85 if has_prefix or self._has_context(context, context_keywords) else 0.7
                    
                    results.append(RecognizerResult(
                        entity_type="PERSON",
                        start=match.start(),
                        end=match.end(),
                        score=score,
                        recognition_metadata={"method": "fullname_pattern", "name": name}
                    ))

        return results

    def analyze(self, text: str, entities: List[str] = None) -> List[RecognizerResult]:
        """Analyze text for PII entities."""
        if not text or not text.strip():
            return []

        results = []
        text_for_detection = str(text)

        # VN_CCCD detection - 11-12 chữ số
        if entities is None or "VN_CCCD" in entities:
            for match in self._cccd_pattern.finditer(text_for_detection):
                val = match.group()
                # Chỉ accept 11-12 chữ số
                if len(val) not in (11, 12):
                    continue
                # Check boundaries
                start, end = match.start(), match.end()
                before_ok = start == 0 or not text_for_detection[start-1:start].isdigit()
                after_ok = end >= len(text_for_detection) or not text_for_detection[end:end+1].isdigit()
                
                if before_ok and after_ok:
                    context = self._get_context(text_for_detection, start, end)
                    score = 0.95 if self._has_context(context, self._cccd_context) else 0.9
                    results.append(RecognizerResult(
                        entity_type="VN_CCCD",
                        start=start,
                        end=end,
                        score=score,
                        recognition_metadata={"pattern": f"{len(val)}_digits"}
                    ))

        # VN_PHONE detection
        if entities is None or "VN_PHONE" in entities:
            # 10-digit phones: 0[3-9]xxxxxxxx (10 digits)
            for match in self._phone_10_pattern.finditer(text_for_detection):
                context = self._get_context(text_for_detection, match.start(), match.end())
                score = 0.9 if self._has_context(context, self._phone_context) else 0.85
                results.append(RecognizerResult(
                    entity_type="VN_PHONE",
                    start=match.start(),
                    end=match.end(),
                    score=score,
                    recognition_metadata={"pattern": "10_digits"}
                ))
            
            # 9-digit phones
            for match in self._phone_9_pattern.finditer(text_for_detection):
                val = match.group()
                start, end = match.start(), match.end()
                before_ok = start == 0 or not text_for_detection[start-1:start].isdigit()
                after_ok = end >= len(text_for_detection) or not text_for_detection[end:end+1].isdigit()
                
                if before_ok and after_ok:
                    context = self._get_context(text_for_detection, start, end)
                    score = 0.75
                    results.append(RecognizerResult(
                        entity_type="VN_PHONE",
                        start=start,
                        end=end,
                        score=score,
                        recognition_metadata={"pattern": "9_digits"}
                    ))

        # EMAIL_ADDRESS detection
        if entities is None or "EMAIL_ADDRESS" in entities:
            for match in self._email_pattern.finditer(text_for_detection):
                email = match.group(1)
                if self._is_valid_email(email):
                    results.append(RecognizerResult(
                        entity_type="EMAIL_ADDRESS",
                        start=match.start(),
                        end=match.end(),
                        score=0.95,
                        recognition_metadata={"email": email}
                    ))

        # PERSON detection
        if entities is None or "PERSON" in entities:
            name_results = self._extract_vietnamese_name(text_for_detection)
            results.extend(name_results)

        # Sort by start position
        results.sort(key=lambda x: x.start)

        # Remove overlapping results
        results = self._remove_overlaps(results)

        return results

    def _is_valid_email(self, email: str) -> bool:
        """Validate email format."""
        if not email or '@' not in email:
            return False
        parts = email.split('@')
        if len(parts) != 2:
            return False
        local, domain = parts
        if not local or not domain:
            return False
        if '.' not in domain:
            return False
        return True

    def _remove_overlaps(self, results: List[RecognizerResult]) -> List[RecognizerResult]:
        """Remove overlapping results, keeping the one with higher score."""
        if not results:
            return []

        filtered = []
        for result in results:
            overlap = False
            for existing in filtered:
                if (result.start < existing.end and result.end > existing.start):
                    overlap = True
                    if result.score > existing.score:
                        filtered.remove(existing)
                        overlap = False
                    break
            if not overlap:
                filtered.append(result)

        return filtered


# Global recognizer instance
_recognizer: Optional[SimpleRecognizer] = None


def get_recognizer() -> SimpleRecognizer:
    """Get singleton recognizer instance."""
    global _recognizer
    if _recognizer is None:
        _recognizer = SimpleRecognizer()
    return _recognizer


def build_vietnamese_analyzer() -> SimpleRecognizer:
    """Build Vietnamese PII analyzer (regex-based)."""
    return SimpleRecognizer()


def detect_pii(text: str, analyzer: SimpleRecognizer = None) -> List[RecognizerResult]:
    """Detect PII in Vietnamese text."""
    if analyzer is None:
        analyzer = get_recognizer()
    
    return analyzer.analyze(
        text=text,
        entities=["PERSON", "EMAIL_ADDRESS", "VN_CCCD", "VN_PHONE"]
    )


class AnalyzerEngine:
    """Compatibility wrapper for Presidio-style AnalyzerEngine interface."""

    def __init__(self, nlp_engine=None, supported_languages=None):
        self.recognizer = SimpleRecognizer()
        self.supported_languages = supported_languages or ["vi"]

    def analyze(self, text: str, language: str = "vi", entities: list = None) -> list:
        """Analyze text for PII entities."""
        return self.recognizer.analyze(text=text, entities=entities)

    class registry:
        @staticmethod
        def add_recognizer(recognizer):
            pass


def get_default_analyzer() -> SimpleRecognizer:
    """Get default analyzer instance."""
    return get_recognizer()
