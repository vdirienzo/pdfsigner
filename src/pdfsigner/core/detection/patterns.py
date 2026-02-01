"""
Regular expression patterns for PII detection.

Contains compiled regex patterns for detecting various types of
Protected Health Information and Personally Identifiable Information.
"""

import re
from re import Pattern

# --- SSN Patterns ---

SSN_PATTERN: Pattern = re.compile(
    r"\b(?!000|666|9\d{2})(?:[0-6]\d{2}|7(?:[0-6]\d|7[012]))-(?!00)\d{2}-(?!0000)\d{4}\b"
)

SSN_NO_DASH_PATTERN: Pattern = re.compile(
    r"\b(?!000|666|9\d{2})(?:[0-6]\d{2}|7(?:[0-6]\d|7[012]))(?!00)\d{2}(?!0000)\d{4}\b"
)

SSN_CONTEXT_WORDS: list[str] = [
    "ssn",
    "social security",
    "social security number",
    "soc sec",
]

# --- Credit Card Patterns ---

# Visa: 4xxx xxxx xxxx xxxx (13 or 16 digits)
VISA_PATTERN: Pattern = re.compile(r"\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?(?:\d{4}|\d{1})\b")

# Mastercard: 5[1-5]xx xxxx xxxx xxxx or 2[2-7]xx xxxx xxxx xxxx (16 digits)
MASTERCARD_PATTERN: Pattern = re.compile(
    r"\b(?:5[1-5]\d{2}|2[2-7]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
)

# American Express: 3[47]xx xxxxxx xxxxx (15 digits)
AMEX_PATTERN: Pattern = re.compile(r"\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b")

# Discover: 6011 xxxx xxxx xxxx or 65xx xxxx xxxx xxxx (16 digits)
DISCOVER_PATTERN: Pattern = re.compile(r"\b(?:6011|65\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")

CC_CONTEXT_WORDS: list[str] = [
    "credit card",
    "card number",
    "cc",
    "visa",
    "mastercard",
    "amex",
    "discover",
]

# --- Email Patterns ---

EMAIL_PATTERN: Pattern = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    re.IGNORECASE,
)

# --- Phone Patterns ---

PHONE_PATTERNS: list[Pattern] = [
    # (555) 123-4567
    re.compile(r"\(\d{3}\)\s?\d{3}-\d{4}\b"),
    # 555-123-4567
    re.compile(r"\b\d{3}-\d{3}-\d{4}\b"),
    # 555.123.4567
    re.compile(r"\b\d{3}\.\d{3}\.\d{4}\b"),
    # +1 555 123 4567 or +1-555-123-4567
    re.compile(r"\+1[\s\-]?\d{3}[\s\-]?\d{3}[\s\-]?\d{4}\b"),
    # 1-555-123-4567
    re.compile(r"\b1-\d{3}-\d{3}-\d{4}\b"),
]

PHONE_CONTEXT_WORDS: list[str] = [
    "phone",
    "tel",
    "telephone",
    "mobile",
    "cell",
    "contact",
]

# --- Date of Birth Patterns ---

DOB_PATTERNS: list[Pattern] = [
    # MM/DD/YYYY or MM-DD-YYYY
    re.compile(r"\b(?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12]\d|3[01])[-/](?:19|20)\d{2}\b"),
    # YYYY-MM-DD (ISO format)
    re.compile(r"\b(?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01])\b"),
    # Month DD, YYYY
    re.compile(
        r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
        r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
        r"\s+(?:0?[1-9]|[12]\d|3[01]),?\s+(?:19|20)\d{2}\b",
        re.IGNORECASE,
    ),
]

DOB_CONTEXT_WORDS: list[str] = [
    "dob",
    "date of birth",
    "birth date",
    "born",
    "birthday",
]

# --- Medical Record Number Patterns ---

MRN_PATTERN: Pattern = re.compile(
    r"\b(?:MRN|Medical Record|Patient ID|Chart #?)[\s:]+([A-Z0-9\-]{6,20})\b",
    re.IGNORECASE,
)

MRN_GENERIC_PATTERN: Pattern = re.compile(r"\b[A-Z]{2,4}\d{6,10}\b")

MRN_CONTEXT_WORDS: list[str] = [
    "mrn",
    "medical record",
    "patient id",
    "chart number",
    "patient number",
]

# --- Health Plan ID Patterns ---

HEALTH_PLAN_PATTERN: Pattern = re.compile(
    r"\b(?:Member ID|Health Plan|Insurance ID|Policy #?)[\s:]+([A-Z0-9\-]{8,20})\b",
    re.IGNORECASE,
)

HEALTH_PLAN_CONTEXT_WORDS: list[str] = [
    "member id",
    "health plan",
    "insurance id",
    "policy number",
    "subscriber id",
]

# --- ICD-10 Diagnosis Code Patterns ---

ICD10_PATTERN: Pattern = re.compile(
    r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b",  # ICD-10 format: Letter + 2 digits + optional .digits
)

# Common ICD-10 codes for additional validation
COMMON_ICD10_CODES: set[str] = {
    "F32.1",  # Major depressive disorder, single episode, moderate
    "F32.2",  # Major depressive disorder, single episode, severe
    "F41.1",  # Generalized anxiety disorder
    "E11.9",  # Type 2 diabetes without complications
    "I10",  # Essential hypertension
    "J18.9",  # Pneumonia, unspecified
    "J44.0",  # COPD with acute lower respiratory infection
    "N18.3",  # Chronic kidney disease, stage 3
    "K21.9",  # GERD
    "M79.3",  # Panniculitis, unspecified
}

ICD10_CONTEXT_WORDS: list[str] = [
    "diagnosis",
    "dx",
    "icd",
    "icd-10",
    "code",
]

# --- Prescription Patterns ---

PRESCRIPTION_PATTERN: Pattern = re.compile(
    r"\b(?:Rx|Prescription|Take|Sig)[\s:]+.{5,100}(?:tablet|capsule|mg|ml|daily|bid|tid|qid|prn)\b",
    re.IGNORECASE,
)

MEDICATION_NAMES: set[str] = {
    "aspirin",
    "ibuprofen",
    "acetaminophen",
    "lisinopril",
    "metformin",
    "amlodipine",
    "metoprolol",
    "omeprazole",
    "simvastatin",
    "losartan",
    "albuterol",
    "gabapentin",
    "hydrocodone",
    "atorvastatin",
    "levothyroxine",
}

PRESCRIPTION_CONTEXT_WORDS: list[str] = [
    "rx",
    "prescription",
    "medication",
    "drug",
    "take",
    "sig",
]


def luhn_checksum(card_number: str) -> bool:
    """
    Validate credit card number using Luhn algorithm.

    Args:
        card_number: Credit card number (digits only)

    Returns:
        True if checksum is valid, False otherwise
    """
    # Remove spaces and dashes
    card_number = card_number.replace(" ", "").replace("-", "")

    if not card_number.isdigit():
        return False

    # Luhn algorithm
    digits = [int(d) for d in card_number]
    checksum = 0

    # Process from right to left
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:  # Every second digit from the right
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


def has_context_word(text: str, position: int, context_words: list[str], window: int = 50) -> bool:
    """
    Check if any context word appears near the detected pattern.

    Args:
        text: Full text
        position: Position of detected pattern
        context_words: List of context words to search for
        window: Character window to search (before and after)

    Returns:
        True if context word found, False otherwise
    """
    start = max(0, position - window)
    end = min(len(text), position + window)
    context = text[start:end].lower()

    return any(word in context for word in context_words)


def redact_value(value: str, pii_type: str, show_last: int = 4) -> str:
    """
    Redact PII value for display.

    Args:
        value: Original value
        pii_type: Type of PII
        show_last: Number of characters to show at end

    Returns:
        Redacted value (e.g., "***-**-1234" for SSN)
    """
    if pii_type == "ssn":
        # Show last 4 digits: ***-**-1234
        clean = value.replace("-", "")
        if len(clean) >= 4:
            return f"***-**-{clean[-4:]}"
        return "***-**-****"

    elif pii_type == "credit_card":
        # Show last 4 digits: **** **** **** 1234
        clean = value.replace(" ", "").replace("-", "")
        if len(clean) >= 4:
            return f"**** **** **** {clean[-4:]}"
        return "**** **** **** ****"

    elif pii_type == "email":
        # Show domain: ***@example.com
        if "@" in value:
            _, domain = value.split("@", 1)
            return f"***@{domain}"
        return "***@***.***"

    elif pii_type == "phone":
        # Show last 4 digits: (***) ***-1234
        digits = "".join(c for c in value if c.isdigit())
        if len(digits) >= 4:
            return f"(***) ***-{digits[-4:]}"
        return "(***) ***-****"

    elif pii_type in ("date_of_birth", "medical_record_number", "health_plan_id"):
        # Fully redact sensitive identifiers
        return "***REDACTED***"

    elif pii_type == "diagnosis_code":
        # Show code structure: X**.* (keep first letter and structure)
        if value:
            return f"{value[0]}**" + (".*" if "." in value else "")
        return "***"

    elif pii_type == "prescription":
        # Show first few words only
        words = value.split()[:2]
        return " ".join(words) + " [...]"

    else:
        # Default: show last few characters
        if len(value) > show_last:
            return "*" * (len(value) - show_last) + value[-show_last:]
        return "*" * len(value)
