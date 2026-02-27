"""
Financial PII detection functions.

Standalone detectors for SSN and credit card numbers,
extracted from PIIDetector for single-responsibility.
"""

from pdfsigner.core.detection import patterns
from pdfsigner.core.detection.pii_types import PIIMatch, PIIType


def get_context(text: str, start: int, end: int, window: int = 20) -> str:
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


def detect_ssn(text: str) -> list[PIIMatch]:
    """Detect Social Security Numbers."""
    matches: list[PIIMatch] = []

    # Try pattern with dashes
    for match in patterns.SSN_PATTERN.finditer(text):
        value = match.group(0)
        start = match.start()
        end = match.end()

        has_context = patterns.has_context_word(text, start, patterns.SSN_CONTEXT_WORDS, window=30)

        confidence = 0.95 if has_context else 0.85

        matches.append(
            PIIMatch(
                pii_type=PIIType.SSN,
                value=value,
                redacted_value=patterns.redact_value(value, "ssn"),
                confidence=confidence,
                start_pos=start,
                end_pos=end,
                context=get_context(text, start, end),
            )
        )

    # Try pattern without dashes
    for match in patterns.SSN_NO_DASH_PATTERN.finditer(text):
        value = match.group(0)
        start = match.start()
        end = match.end()

        # Lower confidence for no-dash format (more false positives)
        has_context = patterns.has_context_word(text, start, patterns.SSN_CONTEXT_WORDS, window=30)

        confidence = 0.85 if has_context else 0.70

        matches.append(
            PIIMatch(
                pii_type=PIIType.SSN,
                value=value,
                redacted_value=patterns.redact_value(value, "ssn"),
                confidence=confidence,
                start_pos=start,
                end_pos=end,
                context=get_context(text, start, end),
            )
        )

    return matches


def detect_credit_cards(text: str) -> list[PIIMatch]:
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
                    context=get_context(text, start, end),
                )
            )

    return matches
