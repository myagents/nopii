"""Mask transformer for PII protection."""

from typing import Any, Dict
from .base import BaseTransformer
from ..core.models import TransformationResult


class MaskTransformer(BaseTransformer):
    """Replace PII with mask characters."""

    def __init__(self, mask_char: str = "*", preserve_format: bool = False):
        super().__init__("mask", "Replace PII with mask characters")
        self.mask_char = mask_char
        self.preserve_format = preserve_format

    def transform(
        self, value: str, pii_type: str, options: Dict[str, Any] = None
    ) -> TransformationResult:
        """Mask the value by replacing characters with mask characters."""
        try:
            if not options:
                options = {}

            # Get options with defaults
            mask_char = options.get("mask_char", self.mask_char)
            # Default to preserving format for structured PII types
            default_preserve_format = pii_type in [
                "phone",
                "ssn",
                "credit_card",
                "email",
            ]
            preserve_format = options.get("preserve_format", default_preserve_format)
            preserve_last = options.get(
                "preserve_last", 4 if pii_type in ["phone", "ssn", "credit_card"] else 0
            )

            # Handle format preservation
            if preserve_format:
                # Special handling for emails - preserve domain
                if pii_type == "email" and "@" in value:
                    local_part, domain = value.split("@", 1)
                    masked_local = mask_char * len(local_part)
                    masked_value = f"{masked_local}@{domain}"
                else:
                    # For format preservation, mask alphanumeric characters but keep structure
                    masked_chars = []
                    for char in value:
                        if char.isalnum():
                            masked_chars.append(mask_char)
                        else:
                            masked_chars.append(char)
                    masked_value = "".join(masked_chars)

                    # For specific PII types, preserve last N characters
                    if preserve_last > 0 and pii_type in [
                        "phone",
                        "ssn",
                        "credit_card",
                    ]:
                        # Extract alphanumeric characters for last N preservation
                        alnum_chars = [c for c in value if c.isalnum()]
                        if len(alnum_chars) >= preserve_last:
                            # Replace the last N alphanumeric characters in the masked value
                            last_chars = alnum_chars[-preserve_last:]
                            masked_chars = list(masked_value)
                            alnum_positions = [
                                i for i, c in enumerate(value) if c.isalnum()
                            ]

                            for i, pos in enumerate(alnum_positions[-preserve_last:]):
                                masked_chars[pos] = last_chars[i]

                            masked_value = "".join(masked_chars)
            else:
                # Simple masking without format preservation
                masked_value = mask_char * len(value)

            return TransformationResult(
                original_value=value,
                transformed_value=masked_value,
                transformation_type="mask",
                pii_type=pii_type,
                success=True,
                metadata={
                    "mask_char": mask_char,
                    "preserve_format": preserve_format,
                    "preserve_last": preserve_last,
                    "original_length": len(value),
                },
            )
        except Exception as e:
            return TransformationResult(
                original_value=value,
                transformed_value=value,
                transformation_type="mask",
                pii_type=pii_type,
                success=False,
                error_message=str(e),
            )

    def is_reversible(self) -> bool:
        """Masking is not reversible."""
        return False
