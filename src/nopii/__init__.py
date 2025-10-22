"""
nopii: Detect, transform, and audit PII in your data.

This package provides comprehensive tools for detecting, transforming, and auditing
personally identifiable information (PII) across various data formats and sources.
"""

__version__ = "0.1.3"
__author__ = "ay-mich"


# Core functionality
from .core.models import Policy, Rule, Finding, ScanResult, AuditReport
from .core.scanner import Scanner
from .core.transform import Transform

# Policy management
from .policy.loader import load_policy, create_default_policy, save_policy

# Detector and transformer registries
from .detectors.registry import DetectorRegistry
from .transforms.registry import TransformRegistry

# SDK - High-level interface
from .sdk.client import NoPIIClient
from .sdk.scanner import SDKScanner
from .sdk.transform import SDKTransform
from .sdk.policy import SDKPolicy

# Reporting
from .reporting.generators import (
    HTMLReportGenerator,
    MarkdownReportGenerator,
    JSONReportGenerator,
)
from .reporting.coverage import CoverageCalculator

__all__ = [
    # Core classes
    "Policy",
    "Rule",
    "Finding",
    "ScanResult",
    "AuditReport",
    "Scanner",
    "Transform",
    # Policy management
    "load_policy",
    "create_default_policy",
    "save_policy",
    # Registries
    "DetectorRegistry",
    "TransformRegistry",
    # SDK - High-level interface
    "NoPIIClient",
    "SDKScanner",
    "SDKTransform",
    "SDKPolicy",
    # Reporting
    "HTMLReportGenerator",
    "MarkdownReportGenerator",
    "JSONReportGenerator",
    "CoverageCalculator",
    # Package info
    "__version__",
    "__author__",
]


def main():
    """Main entry point for the CLI."""
    print("Hello from nopii!")
