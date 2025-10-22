"""
Registry for managing PII detectors.
"""

from typing import Any, Dict, List, Optional

from .base import BaseDetector


class DetectorRegistry:
    """
    Registry for managing and accessing PII detectors.

    The registry allows registration of custom detectors and provides
    methods to retrieve detectors by name or type.
    """

    def __init__(self):
        """Initialize the detector registry."""
        self._detectors: Dict[str, BaseDetector] = {}
        self._load_default_detectors()

    def register(self, detector: BaseDetector) -> None:
        """
        Register a detector.

        Args:
            detector: Detector instance to register
        """
        self._detectors[detector.name] = detector

    def unregister(self, name: str) -> bool:
        """
        Unregister a detector by name.

        Args:
            name: Name of detector to remove

        Returns:
            True if detector was found and removed
        """
        if name in self._detectors:
            del self._detectors[name]
            return True
        return False

    def get_detector(self, name: str) -> Optional[BaseDetector]:
        """
        Get a detector by name.

        Args:
            name: Name of the detector

        Returns:
            Detector instance or None if not found
        """
        return self._detectors.get(name)

    def list_detectors(self) -> List[str]:
        """
        List all registered detector names.

        Returns:
            List of detector names
        """
        return list(self._detectors.keys())

    def get_detectors_by_type(self, pii_type: str) -> List[BaseDetector]:
        """
        Get all detectors that can detect a specific PII type.

        Args:
            pii_type: Type of PII to find detectors for

        Returns:
            List of matching detectors
        """
        return [
            detector
            for detector in self._detectors.values()
            if detector.pii_type == pii_type
        ]

    def get_all_detectors(self) -> List[BaseDetector]:
        """
        Get all registered detectors.

        Returns:
            List of all detector instances
        """
        return list(self._detectors.values())

    def get_detector_info(self) -> List[Dict[str, Any]]:
        """
        Get information about all registered detectors.

        Returns:
            List of detector information dictionaries
        """
        return [detector.get_info() for detector in self._detectors.values()]

    def configure_detector(self, name: str, config: Dict[str, Any]) -> bool:
        """
        Configure a specific detector.

        Args:
            name: Name of the detector to configure
            config: Configuration dictionary

        Returns:
            True if detector was found and configured successfully
        """
        detector = self.get_detector(name)
        if detector and detector.validate_config(config):
            detector.configure(config)
            return True
        return False

    def load_locale_pack(self, locale_pack: str) -> None:
        """
        Load detectors for a specific locale pack.

        Args:
            locale_pack: Name of the locale pack to load
        """
        # For now, just load default detectors regardless of locale
        # TODO: Implement locale-specific detector loading
        pass

    def get_detectors(
        self, pii_types: Optional[List[str]] = None
    ) -> List[BaseDetector]:
        """
        Get detectors for specific PII types or all detectors.

        Args:
            pii_types: List of PII types to get detectors for, or None for all

        Returns:
            List of detector instances
        """
        if pii_types is None:
            return self.get_all_detectors()

        detectors = []
        for pii_type in pii_types:
            detectors.extend(self.get_detectors_by_type(pii_type))

        # Remove duplicates while preserving order
        seen = set()
        unique_detectors = []
        for detector in detectors:
            if detector.name not in seen:
                seen.add(detector.name)
                unique_detectors.append(detector)

        return unique_detectors

    def get_detector_names(self) -> List[str]:
        """
        Get names of all registered detectors.

        Returns:
            List of detector names
        """
        return self.list_detectors()

    def _load_default_detectors(self) -> None:
        """Load the default set of PII detectors."""
        # Import and register default detectors
        from .patterns import (
            CreditCardDetector,
            EmailDetector,
            PhoneDetector,
            SSNDetector,
            IPAddressDetector,
            URLDetector,
            PersonNameDetector,
            AddressDetector,
            DateOfBirthDetector,
            DriversLicenseDetector,
        )

        # Register all default detectors
        default_detectors = [
            EmailDetector(),
            PhoneDetector(),
            CreditCardDetector(),
            SSNDetector(),
            IPAddressDetector(),
            URLDetector(),
            PersonNameDetector(),
            AddressDetector(),
            DateOfBirthDetector(),
            DriversLicenseDetector(),
        ]

        for detector in default_detectors:
            self.register(detector)
