"""
Reporting module for nopii.

Provides audit report generation and coverage scoring functionality.
"""

from .coverage import CoverageCalculator
from .generators import (
    HTMLReportGenerator,
    MarkdownReportGenerator,
    JSONReportGenerator,
)
from .templates import get_template, list_templates

__all__ = [
    "CoverageCalculator",
    "HTMLReportGenerator",
    "MarkdownReportGenerator",
    "JSONReportGenerator",
    "get_template",
    "list_templates",
]
