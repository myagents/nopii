"""
Pattern-based PII detectors using regular expressions.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseDetector


class EmailDetector(BaseDetector):
    """Detector for email addresses."""

    def __init__(self):
        super().__init__("email", "Detects email addresses")
        # Comprehensive email regex pattern
        self.pattern = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", re.IGNORECASE
        )

    def detect(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[int, int, float]]:
        """Detect email addresses in text."""
        matches = []
        for match in self.pattern.finditer(text):
            # Higher confidence if in email-related column
            confidence = 0.95
            if context and context.get("column_name"):
                column_name = context["column_name"].lower()
                if any(
                    keyword in column_name for keyword in ["email", "mail", "contact"]
                ):
                    confidence = 0.99

            matches.append((match.start(), match.end(), confidence))
        return matches


class PhoneDetector(BaseDetector):
    """Detector for phone numbers."""

    def __init__(self):
        super().__init__("phone", "Detects phone numbers")
        # Multiple phone number patterns
        self.patterns = [
            re.compile(r"\b\d{3}-\d{3}-\d{4}\b"),  # 123-456-7890
            re.compile(r"\b\(\d{3}\)\s*\d{3}-\d{4}\b"),  # (123) 456-7890
            re.compile(r"\b\d{3}\.\d{3}\.\d{4}\b"),  # 123.456.7890
            re.compile(r"\b\d{10}\b"),  # 1234567890
            re.compile(r"\+1\s*\d{3}\s*\d{3}\s*\d{4}\b"),  # +1 123 456 7890
        ]

    def detect(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[int, int, float]]:
        """Detect phone numbers in text."""
        matches = []
        for pattern in self.patterns:
            for match in pattern.finditer(text):
                # Confidence varies by pattern specificity
                confidence = 0.85
                if (
                    pattern == self.patterns[0] or pattern == self.patterns[1]
                ):  # Formatted patterns
                    confidence = 0.95
                elif pattern == self.patterns[3]:  # 10 digits - could be other things
                    confidence = 0.70

                # Higher confidence if in phone-related column
                if context and context.get("column_name"):
                    column_name = context["column_name"].lower()
                    if any(
                        keyword in column_name
                        for keyword in ["phone", "tel", "mobile", "cell"]
                    ):
                        confidence = min(confidence + 0.1, 0.99)

                matches.append((match.start(), match.end(), confidence))
        return matches


class CreditCardDetector(BaseDetector):
    """Detector for credit card numbers."""

    def __init__(self):
        super().__init__("credit_card", "Detects credit card numbers")
        # Credit card patterns (with optional spaces/dashes)
        self.pattern = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")

    def detect(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[int, int, float]]:
        """Detect credit card numbers in text."""
        matches = []
        for match in self.pattern.finditer(text):
            # Extract just digits for Luhn validation
            digits = re.sub(r"[-\s]", "", match.group())

            # Basic length check (13-19 digits for most cards)
            if len(digits) < 13 or len(digits) > 19:
                continue

            # Luhn algorithm validation
            if self._luhn_check(digits):
                confidence = 0.95

                # Higher confidence if in payment-related column
                if context and context.get("column_name"):
                    column_name = context["column_name"].lower()
                    if any(
                        keyword in column_name
                        for keyword in ["card", "credit", "payment", "cc"]
                    ):
                        confidence = 0.99

                matches.append((match.start(), match.end(), confidence))
            else:
                # Still might be a credit card with typo
                matches.append((match.start(), match.end(), 0.60))

        return matches

    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""

        def luhn_checksum(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]

            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d * 2))
            return checksum % 10

        return luhn_checksum(card_number) == 0


class SSNDetector(BaseDetector):
    """Detector for Social Security Numbers."""

    def __init__(self):
        super().__init__("ssn", "Detects Social Security Numbers")
        # SSN patterns
        self.patterns = [
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # 123-45-6789
            re.compile(r"\b\d{9}\b"),  # 123456789
        ]

    def detect(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[int, int, float]]:
        """Detect SSNs in text."""
        matches = []
        for i, pattern in enumerate(self.patterns):
            for match in pattern.finditer(text):
                # Formatted SSN has higher confidence
                confidence = 0.95 if i == 0 else 0.75

                # Higher confidence if in SSN-related column
                if context and context.get("column_name"):
                    column_name = context["column_name"].lower()
                    if any(
                        keyword in column_name
                        for keyword in ["ssn", "social", "security"]
                    ):
                        confidence = 0.99

                matches.append((match.start(), match.end(), confidence))
        return matches


class IPAddressDetector(BaseDetector):
    """Detector for IP addresses."""

    def __init__(self):
        super().__init__("ip_address", "Detects IP addresses")
        # IPv4 pattern
        self.ipv4_pattern = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        )
        # IPv6 pattern (simplified)
        self.ipv6_pattern = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")

    def detect(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[int, int, float]]:
        """Detect IP addresses in text."""
        matches = []

        # IPv4 addresses
        for match in self.ipv4_pattern.finditer(text):
            confidence = 0.90
            if context and context.get("column_name"):
                column_name = context["column_name"].lower()
                if any(keyword in column_name for keyword in ["ip", "address", "host"]):
                    confidence = 0.95
            matches.append((match.start(), match.end(), confidence))

        # IPv6 addresses
        for match in self.ipv6_pattern.finditer(text):
            confidence = 0.85
            if context and context.get("column_name"):
                column_name = context["column_name"].lower()
                if any(
                    keyword in column_name
                    for keyword in ["ip", "address", "host", "ipv6"]
                ):
                    confidence = 0.95
            matches.append((match.start(), match.end(), confidence))

        return matches


class URLDetector(BaseDetector):
    """Detector for URLs."""

    def __init__(self):
        super().__init__("url", "Detects URLs")
        self.pattern = re.compile(
            r"https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?",
            re.IGNORECASE,
        )

    def detect(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[int, int, float]]:
        """Detect URLs in text."""
        matches = []
        for match in self.pattern.finditer(text):
            confidence = 0.90
            if context and context.get("column_name"):
                column_name = context["column_name"].lower()
                if any(
                    keyword in column_name
                    for keyword in ["url", "link", "website", "href"]
                ):
                    confidence = 0.95
            matches.append((match.start(), match.end(), confidence))
        return matches


class PersonNameDetector(BaseDetector):
    """Detector for person names (basic pattern-based)."""

    def __init__(self):
        super().__init__("person_name", "Detects person names")
        # Simple pattern for names (capitalized words)
        self.pattern = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b")

    def detect(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[int, int, float]]:
        """Detect person names in text."""
        matches = []
        for match in self.pattern.finditer(text):
            # Lower confidence as this is a simple pattern
            confidence = 0.60

            # Higher confidence if in name-related column
            if context and context.get("column_name"):
                column_name = context["column_name"].lower()
                if any(
                    keyword in column_name
                    for keyword in ["name", "first", "last", "full"]
                ):
                    confidence = 0.85

            matches.append((match.start(), match.end(), confidence))
        return matches


class AddressDetector(BaseDetector):
    """Detector for addresses."""

    def __init__(self):
        super().__init__("address", "Detects street addresses")
        # Pattern for street addresses (number + street name)
        self.pattern = re.compile(
            r"\b\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Way|Court|Ct)\b",
            re.IGNORECASE,
        )

    def detect(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[int, int, float]]:
        """Detect addresses in text."""
        matches = []
        for match in self.pattern.finditer(text):
            confidence = 0.75

            # Higher confidence if in address-related column
            if context and context.get("column_name"):
                column_name = context["column_name"].lower()
                if any(
                    keyword in column_name
                    for keyword in ["address", "street", "location"]
                ):
                    confidence = 0.90

            matches.append((match.start(), match.end(), confidence))
        return matches


class DateOfBirthDetector(BaseDetector):
    """Detector for dates of birth."""

    def __init__(self):
        super().__init__("date_of_birth", "Detects dates of birth")
        # Common date patterns
        self.patterns = [
            re.compile(r"\b\d{1,2}/\d{1,2}/\d{4}\b"),  # MM/DD/YYYY
            re.compile(r"\b\d{1,2}-\d{1,2}-\d{4}\b"),  # MM-DD-YYYY
            re.compile(r"\b\d{4}-\d{1,2}-\d{1,2}\b"),  # YYYY-MM-DD
        ]

    def detect(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[int, int, float]]:
        """Detect dates of birth in text."""
        matches = []
        for pattern in self.patterns:
            for match in pattern.finditer(text):
                # Lower confidence unless in DOB-related column
                confidence = 0.50

                if context and context.get("column_name"):
                    column_name = context["column_name"].lower()
                    if any(
                        keyword in column_name for keyword in ["birth", "dob", "born"]
                    ):
                        confidence = 0.90
                    elif any(keyword in column_name for keyword in ["date"]):
                        confidence = 0.70

                matches.append((match.start(), match.end(), confidence))
        return matches


class DriversLicenseDetector(BaseDetector):
    """Detector for driver's license numbers."""

    def __init__(self):
        super().__init__("drivers_license", "Detects driver's license numbers")
        # Generic pattern for license numbers (varies by state)
        self.patterns = [
            re.compile(r"\b[A-Z]\d{7,8}\b"),  # Letter followed by 7-8 digits
            re.compile(r"\b\d{8,9}\b"),  # 8-9 digits
            re.compile(r"\b[A-Z]{1,2}\d{6,7}\b"),  # 1-2 letters + 6-7 digits
        ]

    def detect(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[int, int, float]]:
        """Detect driver's license numbers in text."""
        matches = []
        for pattern in self.patterns:
            for match in pattern.finditer(text):
                # Lower confidence due to generic patterns
                confidence = 0.60

                if context and context.get("column_name"):
                    column_name = context["column_name"].lower()
                    if any(
                        keyword in column_name
                        for keyword in ["license", "dl", "driver"]
                    ):
                        confidence = 0.85

                matches.append((match.start(), match.end(), confidence))
        return matches
