"""
Main PII detection engine — orchestrator.

The PIIDetector class delegates pattern matching to specialized detector
modules (financial, medical) and provides confidence filtering and risk scoring.
"""

from pdfsigner.core.detection import patterns
from pdfsigner.core.detection.detectors_financial import (
    detect_credit_cards,
    detect_ssn,
    get_context,
)
from pdfsigner.core.detection.detectors_medical import (
    detect_diagnosis_codes,
    detect_health_plan_ids,
    detect_medical_records,
    detect_prescriptions,
)
from pdfsigner.core.detection.pii_types import PIIMatch, PIIType


class PIIDetector:
    """
    Main PII detection engine.

    Detects various types of PII/PHI in text by orchestrating
    specialized detector functions for each PII category.
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

        # Financial detectors
        matches.extend(detect_ssn(text))
        matches.extend(detect_credit_cards(text))

        # General PII detectors (kept inline — low complexity)
        matches.extend(self._detect_emails(text))
        matches.extend(self._detect_phones(text))
        matches.extend(self._detect_dob(text))

        # Medical detectors
        matches.extend(detect_medical_records(text))
        matches.extend(detect_health_plan_ids(text))
        matches.extend(detect_diagnosis_codes(text))
        matches.extend(detect_prescriptions(text))

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

    # --- Private Detection Methods (general PII, low complexity) ---

    def _detect_emails(self, text: str) -> list[PIIMatch]:
        """Detect email addresses."""
        matches: list[PIIMatch] = []

        for match in patterns.EMAIL_PATTERN.finditer(text):
            value = match.group(0)
            start = match.start()
            end = match.end()

            confidence = 0.90

            matches.append(
                PIIMatch(
                    pii_type=PIIType.EMAIL,
                    value=value,
                    redacted_value=patterns.redact_value(value, "email"),
                    confidence=confidence,
                    start_pos=start,
                    end_pos=end,
                    context=get_context(text, start, end),
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
                        context=get_context(text, start, end),
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
                        context=get_context(text, start, end),
                    )
                )

        return matches


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
