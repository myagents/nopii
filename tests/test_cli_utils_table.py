"""
Unit tests for CLI utils format_findings_table.
"""

from nopii.cli.utils import format_findings_table
from nopii.core.models import Finding


def test_format_findings_table_contains_headers_and_values():
    findings = [
        Finding("email", "a@example.com", (0, 5), "email", 0, 0.9, "e"),
        Finding("phone", "555-111-2222", (0, 5), "phone", 1, 0.8, "e"),
    ]
    table = format_findings_table(findings)
    assert "Type" in table and "Context" in table
    assert "email" in table and "phone" in table
