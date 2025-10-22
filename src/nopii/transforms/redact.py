"""
Redact transformer for PII protection.
"""

from typing import Any, Dict, Optional
from .base import BaseTransformer
from ..core.models import TransformationResult


class RedactTransformer(BaseTransformer):
    """Replace PII with redaction placeholders."""

    def __init__(
        self,
        placeholder: str = "[transformed]",
        preserve_length: bool = False,
        type_specific_placeholders: Optional[Dict[str, str]] = None,
        redaction_char: str = "*",
    ):
        super().__init__("redact", "Replace PII with redaction placeholders")
        self.placeholder = placeholder
        self.preserve_length = preserve_length
        self.type_specific_placeholders = type_specific_placeholders or {}
        self.redaction_char = redaction_char

    def transform(
        self, value: str, pii_type: str, options: Optional[Dict[str, Any]] = None
    ) -> TransformationResult:
        """Replace the value with a redaction placeholder."""
        try:
            if not options:
                options = {}

            # Use instance attributes as defaults, allow options to override
            placeholder = options.get("placeholder", self.placeholder)
            preserve_length = options.get("preserve_length", self.preserve_length)
            include_type = options.get("include_type", False)
            type_specific_placeholders = options.get(
                "type_specific_placeholders", self.type_specific_placeholders
            )
            redaction_char = options.get("redaction_char", self.redaction_char)

            # Check for type-specific placeholder first
            if pii_type in type_specific_placeholders:
                transformed_value = type_specific_placeholders[pii_type]
            elif include_type:
                transformed_value = f"[{pii_type.upper()}_transformed]"
            elif preserve_length:
                # Use redaction character repeated to match length
                transformed_value = redaction_char * len(value)
            else:
                transformed_value = placeholder

            return TransformationResult(
                original_value=value,
                transformed_value=transformed_value,
                transformation_type="redact",
                pii_type=pii_type,
                success=True,
                metadata={
                    "placeholder": placeholder,
                    "include_type": include_type,
                    "preserve_length": preserve_length,
                    "original_length": len(value),
                },
            )
        except Exception as e:
            return TransformationResult(
                original_value=value,
                transformed_value=value,
                transformation_type="redact",
                pii_type=pii_type,
                success=False,
                error_message=str(e),
            )

    def is_reversible(self) -> bool:
        """TRANSFORM is not reversible."""
        return False
