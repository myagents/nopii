"""
Base detector interface for PII detection.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple


class BaseDetector(ABC):
    """
    Abstract base class for PII detectors.

    All detectors must implement the detect method to identify PII patterns
    in text and return their positions and confidence scores.
    """

    def __init__(self, name: str, description: str = ""):
        """
        Initialize the detector.

        Args:
            name: Unique name for this detector
            description: Human-readable description of what this detector finds
        """
        self.name = name
        self.description = description

    @abstractmethod
    def detect(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[int, int, float]]:
        """
        Detect PII in the given text.

        Args:
            text: Text to scan for PII
            context: Optional context information (column name, data type, etc.)

        Returns:
            List of tuples (start_pos, end_pos, confidence_score)
            where confidence_score is between 0.0 and 1.0
        """
        pass

    def find(
        self, text: str, context: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[int, int, float]]:
        """
        Alias for detect method for backward compatibility.

        Args:
            text: Text to scan for PII
            context: Optional context information

        Returns:
            List of tuples (start_pos, end_pos, confidence_score)
        """
        return self.detect(text, context)

    @property
    def pii_type(self) -> str:
        """Return the type of PII this detector identifies."""
        return self.name

    def get_info(self) -> Dict[str, Any]:
        """Return information about this detector."""
        return {
            "name": self.name,
            "description": self.description,
            "pii_type": self.pii_type,
        }

    def configure(self, config: Dict[str, Any]) -> None:
        """
        Configure the detector with custom settings.

        Args:
            config: Configuration dictionary
        """
        # Default implementation does nothing
        pass

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate detector configuration.

        Args:
            config: Configuration to validate

        Returns:
            True if configuration is valid
        """
        # Default implementation accepts any config
        return True
