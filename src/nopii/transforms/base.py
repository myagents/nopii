"""
Base transformer interface for PII transformations.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from ..core.models import TransformationResult


class BaseTransformer(ABC):
    """
    Abstract base class for PII transformers.

    All transformers must implement the transform method to convert
    sensitive data into a protected form.
    """

    def __init__(self, name: str, description: str = ""):
        """
        Initialize the transformer.

        Args:
            name: Unique name for this transformer
            description: Human-readable description of the transformation
        """
        self.name = name
        self.description = description

    @abstractmethod
    def transform(
        self, value: str, pii_type: str, options: Optional[Dict[str, Any]] = None
    ) -> TransformationResult:
        """
        Transform a PII value.

        Args:
            value: The PII value to transform
            pii_type: Type of PII being transformed
            options: Optional transformation parameters

        Returns:
            TransformationResult with transformation details
        """
        pass

    def get_info(self) -> Dict[str, Any]:
        """Return information about this transformer."""
        return {
            "name": self.name,
            "description": self.description,
        }

    def validate_options(self, options: Dict[str, Any]) -> bool:
        """
        Validate transformation options.

        Args:
            options: Options to validate

        Returns:
            True if options are valid
        """
        # Default implementation accepts any options
        return True

    def is_reversible(self) -> bool:
        """
        Check if this transformation is reversible.

        Returns:
            True if the transformation can be reversed
        """
        return False
