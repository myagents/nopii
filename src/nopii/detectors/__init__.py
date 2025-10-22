"""
PII detection module for nopii.

This module provides various detectors for identifying personally identifiable
information (PII) in text data.
"""

from .registry import DetectorRegistry

__all__ = ["DetectorRegistry"]
