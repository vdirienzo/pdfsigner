"""
Main PII detection engine with pattern matching and confidence scoring.

The PIIDetector class provides comprehensive detection of Protected Health
Information (PHI) and Personally Identifiable Information (PII) using
regex patterns and context analysis.
"""

from pdfsigner.core.detection import patterns
from pdfsigner.core.detection.pii_types import PIIMatch, PIIType


class PIIDetector:
    """
    Main PII detection engine.

    Detects various types of PII/PHI in text using pattern matching,
    context analysis, and confidence scoring.
    """

    def scan_text(self, text: str) -> list[PIIMatch]:
        """
        Scan text for PII/PHI.

        Args:
            text: Text to scan

        Returns:
            List of PIIMatch objects with detected PII
        """
        matches: list[PIIMatch] = []

        # Detect each PII type
        matches.extend(self._detect_ssn(text))
        matches.extend(self._detect_credit_cards(text))
        matches.extend(self._detect_emails(text))
        matches.extend(self._detect_phones(text))
        matches.extend(self._detect_dob(text))
        matches.extend(self._detect_medical_records(text))
        matches.extend(self._detect_health_plan_ids(text))
        matches.extend(self._detect_diagnosis_codes(text))
        matches.extend(self._detect_prescriptions(text))

        # Sort by position in text
        matches.sort(key=lambda m: m.start_pos)

        return matches

    def scan_with_confidence(self, text: str, min_confidence: float = 0.5) -> list[PIIMatch]:
        """
        Scan text for PII with confidence threshold.

        Args:
            text: Text to scan
            min_confidence: Minimum confidence threshold (0.0-1.0)

        Returns:
            List of PIIMatch objects with confidence >= min_confidence
        """
        all_matches = self.scan_text(text)
        return [m for m in all_matches if m.confidence >= min_confidence]

    def get_risk_score(self, matches: list[PIIMatch]) -> float:
        """
        Calculate overall risk score based on detected PII.

        Risk score is calculated as a weighted average of:
        - Number of matches (more matches = higher risk)
        - Sensitivity of PII types (SSN/CC = highest)
        - Confidence levels (higher confidence = higher risk)

        Args:
            matches: List of PIIMatch objects

        Returns:
            Risk score from 0.0 (no risk) to 1.0 (maximum risk)
        """
        if not matches:
            return 0.0

        # Calculate weighted score
        total_weight = 0.0
        weighted_sum = 0.0

        for match in matches:
            sensitivity = match.pii_type.sensitivity_weight
            weight = sensitivity * match.confidence
            weighted_sum += weight
            total_weight += 1.0

        # Average weighted score
        avg_score = weighted_sum / total_weight if total_weight > 0 else 0.0

        # Apply scaling factor based on count (more matches = higher risk)
        count_factor = min(1.0, len(matches) / 10.0)  # Cap at 10 matches

        # Combined score
        risk_score = (avg_score * 0.7) + (count_factor * 0.3)

        return min(1.0, risk_score)

    # --- Private Detection Methods ---

    def _detect_ssn(self, text: str) -> list[PIIMatch]:
        """Detect Social Security Numbers."""
        matches: list[PIIMatch] = []

        # Try pattern with dashes
        for match in patterns.SSN_PATTERN.finditer(text):
            value = match.group(0)
            start = match.start()
            end = match.end()

            # Check for context words
            has_context = patterns.has_context_word(
                text, start, patterns.SSN_CONTEXT_WORDS, window=30
            )

            confidence = 0.95 if has_context else 0.85

            matches.append(
                PIIMatch(
                    pii_type=PIIType.SSN,
                    value=value,
                    redacted_value=patterns.redact_value(value, "ssn"),
                    confidence=confidence,
                    start_pos=start,
                    end_pos=end,
                    context=self._get_context(text, start, end),
                )
            )

        # Try pattern without dashes
        for match in patterns.SSN_NO_DASH_PATTERN.finditer(text):
            value = match.group(0)
            start = match.start()
            end = match.end()

            # Lower confidence for no-dash format (more false positives)
            has_context = patterns.has_context_word(
                text, start, patterns.SSN_CONTEXT_WORDS, window=30
            )

            confidence = 0.85 if has_context else 0.70

            matches.append(
                PIIMatch(
                    pii_type=PIIType.SSN,
                    value=value,
                    redacted_value=patterns.redact_value(value, "ssn"),
                    confidence=confidence,
                    start_pos=start,
                    end_pos=end,
                    context=self._get_context(text, start, end),
                )
            )

        return matches

    def _detect_credit_cards(self, text: str) -> list[PIIMatch]:
        """Detect credit card numbers with Luhn validation."""
        matches: list[PIIMatch] = []

        for pattern in [
            patterns.VISA_PATTERN,
            patterns.MASTERCARD_PATTERN,
            patterns.AMEX_PATTERN,
            patterns.DISCOVER_PATTERN,
        ]:
            for match in pattern.finditer(text):
                value = match.group(0)
                start = match.start()
                end = match.end()

                # Validate with Luhn algorithm
                if not patterns.luhn_checksum(value):
                    continue

                # Check for context words
                has_context = patterns.has_context_word(
                    text, start, patterns.CC_CONTEXT_WORDS, window=30
                )

                # High confidence if Luhn valid + context
                confidence = 0.95 if has_context else 0.85

                matches.append(
                    PIIMatch(
                        pii_type=PIIType.CREDIT_CARD,
                        value=value,
                        redacted_value=patterns.redact_value(value, "credit_card"),
                        confidence=confidence,
                        start_pos=start,
                        end_pos=end,
                        context=self._get_context(text, start, end),
                    )
                )

        return matches

    def _detect_emails(self, text: str) -> list[PIIMatch]:
        """Detect email addresses."""
        matches: list[PIIMatch] = []

        for match in patterns.EMAIL_PATTERN.finditer(text):
            value = match.group(0)
            start = match.start()
            end = match.end()

            # Medium confidence for emails (common but lower sensitivity)
            confidence = 0.90

            matches.append(
                PIIMatch(
                    pii_type=PIIType.EMAIL,
                    value=value,
                    redacted_value=patterns.redact_value(value, "email"),
                    confidence=confidence,
                    start_pos=start,
                    end_pos=end,
                    context=self._get_context(text, start, end),
                )
            )

        return matches

    def _detect_phones(self, text: str) -> list[PIIMatch]:
        """Detect phone numbers."""
        matches: list[PIIMatch] = []

        for pattern in patterns.PHONE_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                start = match.start()
                end = match.end()

                # Check for context words
                has_context = patterns.has_context_word(
                    text, start, patterns.PHONE_CONTEXT_WORDS, window=30
                )

                confidence = 0.85 if has_context else 0.70

                matches.append(
                    PIIMatch(
                        pii_type=PIIType.PHONE,
                        value=value,
                        redacted_value=patterns.redact_value(value, "phone"),
                        confidence=confidence,
                        start_pos=start,
                        end_pos=end,
                        context=self._get_context(text, start, end),
                    )
                )

        return matches

    def _detect_dob(self, text: str) -> list[PIIMatch]:
        """Detect dates of birth."""
        matches: list[PIIMatch] = []

        for pattern in patterns.DOB_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                start = match.start()
                end = match.end()

                # DOB requires context (otherwise just a date)
                has_context = patterns.has_context_word(
                    text, start, patterns.DOB_CONTEXT_WORDS, window=30
                )

                if not has_context:
                    continue  # Skip dates without DOB context

                confidence = 0.90

                matches.append(
                    PIIMatch(
                        pii_type=PIIType.DOB,
                        value=value,
                        redacted_value=patterns.redact_value(value, "date_of_birth"),
                        confidence=confidence,
                        start_pos=start,
                        end_pos=end,
                        context=self._get_context(text, start, end),
                    )
                )

        return matches

    def _detect_medical_records(self, text: str) -> list[PIIMatch]:
        """Detect medical record numbers."""
        matches: list[PIIMatch] = []

        # Try pattern with explicit labels
        for match in patterns.MRN_PATTERN.finditer(text):
            value = match.group(1)  # Capture group
            start = match.start(1)
            end = match.end(1)

            confidence = 0.95  # High confidence with label

            matches.append(
                PIIMatch(
                    pii_type=PIIType.MEDICAL_RECORD,
                    value=value,
                    redacted_value=patterns.redact_value(value, "medical_record_number"),
                    confidence=confidence,
                    start_pos=start,
                    end_pos=end,
                    context=self._get_context(text, start, end),
                )
            )

        # Try generic pattern with context
        for match in patterns.MRN_GENERIC_PATTERN.finditer(text):
            value = match.group(0)
            start = match.start()
            end = match.end()

            # Require context for generic pattern
            has_context = patterns.has_context_word(
                text, start, patterns.MRN_CONTEXT_WORDS, window=50
            )

            if not has_context:
                continue

            confidence = 0.80

            matches.append(
                PIIMatch(
                    pii_type=PIIType.MEDICAL_RECORD,
                    value=value,
                    redacted_value=patterns.redact_value(value, "medical_record_number"),
                    confidence=confidence,
                    start_pos=start,
                    end_pos=end,
                    context=self._get_context(text, start, end),
                )
            )

        return matches

    def _detect_health_plan_ids(self, text: str) -> list[PIIMatch]:
        """Detect health plan / insurance IDs."""
        matches: list[PIIMatch] = []

        for match in patterns.HEALTH_PLAN_PATTERN.finditer(text):
            value = match.group(1)  # Capture group
            start = match.start(1)
            end = match.end(1)

            confidence = 0.95  # High confidence with label

            matches.append(
                PIIMatch(
                    pii_type=PIIType.HEALTH_PLAN_ID,
                    value=value,
                    redacted_value=patterns.redact_value(value, "health_plan_id"),
                    confidence=confidence,
                    start_pos=start,
                    end_pos=end,
                    context=self._get_context(text, start, end),
                )
            )

        return matches

    def _detect_diagnosis_codes(self, text: str) -> list[PIIMatch]:
        """Detect ICD-10 diagnosis codes."""
        matches: list[PIIMatch] = []

        for match in patterns.ICD10_PATTERN.finditer(text):
            value = match.group(0)
            start = match.start()
            end = match.end()

            # Check if it's a known ICD-10 code
            is_known = value.upper() in patterns.COMMON_ICD10_CODES

            # Check for context words
            has_context = patterns.has_context_word(
                text, start, patterns.ICD10_CONTEXT_WORDS, window=50
            )

            # Higher confidence for known codes or with context
            if is_known:
                confidence = 0.95
            elif has_context:
                confidence = 0.85
            else:
                confidence = 0.70

            matches.append(
                PIIMatch(
                    pii_type=PIIType.DIAGNOSIS_CODE,
                    value=value,
                    redacted_value=patterns.redact_value(value, "diagnosis_code"),
                    confidence=confidence,
                    start_pos=start,
                    end_pos=end,
                    context=self._get_context(text, start, end),
                )
            )

        return matches

    def _detect_prescriptions(self, text: str) -> list[PIIMatch]:
        """Detect prescription information."""
        matches: list[PIIMatch] = []

        for match in patterns.PRESCRIPTION_PATTERN.finditer(text):
            value = match.group(0)
            start = match.start()
            end = match.end()

            # Check if contains known medication names
            value_lower = value.lower()
            has_medication = any(med in value_lower for med in patterns.MEDICATION_NAMES)

            confidence = 0.90 if has_medication else 0.75

            matches.append(
                PIIMatch(
                    pii_type=PIIType.PRESCRIPTION,
                    value=value,
                    redacted_value=patterns.redact_value(value, "prescription"),
                    confidence=confidence,
                    start_pos=start,
                    end_pos=end,
                    context=self._get_context(text, start, end),
                )
            )

        return matches

    def _get_context(self, text: str, start: int, end: int, window: int = 20) -> str:
        """
        Get surrounding context for a match.

        Args:
            text: Full text
            start: Match start position
            end: Match end position
            window: Characters to include before/after

        Returns:
            Context string with "..." markers
        """
        context_start = max(0, start - window)
        context_end = min(len(text), end + window)

        prefix = "..." if context_start > 0 else ""
        suffix = "..." if context_end < len(text) else ""

        context = text[context_start:context_end]

        return f"{prefix}{context}{suffix}"


# --- Singleton Instance ---

_detector_instance: PIIDetector | None = None


def get_pii_detector() -> PIIDetector:
    """
    Get PIIDetector singleton instance.

    Returns:
        PIIDetector instance
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = PIIDetector()
    return _detector_instance
