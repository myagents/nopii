"""
Nullify transformer for PII protection.
"""

from typing import Any, Dict
from .base import BaseTransformer
from ..core.models import TransformationResult


class NullifyTransformer(BaseTransformer):
    """Replace PII with null/empty values."""

    def __init__(self, use_placeholder: bool = False, placeholder: str = "NULL"):
        super().__init__("nullify", "Replace PII with null values")
        self.use_placeholder = use_placeholder
        self.placeholder = placeholder

    def transform(
        self, value: str, pii_type: str, options: Dict[str, Any] = None
    ) -> TransformationResult:
        """Replace value with null/empty string."""
        try:
            if not options:
                options = {}

            # Use instance attributes as defaults, allow options to override
            use_placeholder = options.get("use_placeholder", self.use_placeholder)
            placeholder = options.get("placeholder", self.placeholder)

            if use_placeholder:
                transformed_value = placeholder
            else:
                transformed_value = None

            return TransformationResult(
                original_value=value,
                transformed_value=transformed_value,
                transformation_type="nullify",
                pii_type=pii_type,
                success=True,
                metadata={
                    "use_placeholder": use_placeholder,
                    "placeholder": placeholder,
                },
            )
        except Exception as e:
            return TransformationResult(
                original_value=value,
                transformed_value=None,
                transformation_type="nullify",
                pii_type=pii_type,
                success=False,
                error_message=str(e),
            )

    def is_reversible(self) -> bool:
        """Nullification is not reversible."""
        return False
