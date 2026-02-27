"""
Medical PII detection functions.

Standalone detectors for medical record numbers, health plan IDs,
diagnosis codes, and prescriptions, extracted from PIIDetector
for single-responsibility.
"""

from pdfsigner.core.detection import patterns
from pdfsigner.core.detection.detectors_financial import get_context
from pdfsigner.core.detection.pii_types import PIIMatch, PIIType


def detect_medical_records(text: str) -> list[PIIMatch]:
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
                context=get_context(text, start, end),
            )
        )

    # Try generic pattern with context
    for match in patterns.MRN_GENERIC_PATTERN.finditer(text):
        value = match.group(0)
        start = match.start()
        end = match.end()

        # Require context for generic pattern
        has_context = patterns.has_context_word(text, start, patterns.MRN_CONTEXT_WORDS, window=50)

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
                context=get_context(text, start, end),
            )
        )

    return matches


def detect_health_plan_ids(text: str) -> list[PIIMatch]:
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
                context=get_context(text, start, end),
            )
        )

    return matches


def detect_diagnosis_codes(text: str) -> list[PIIMatch]:
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
                context=get_context(text, start, end),
            )
        )

    return matches


def detect_prescriptions(text: str) -> list[PIIMatch]:
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
                context=get_context(text, start, end),
            )
        )

    return matches
