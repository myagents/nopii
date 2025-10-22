"""
SDKScanner operations for text and dictionary scanning, coverage metrics, and analysis.
"""

from nopii.sdk.scanner import SDKScanner
from nopii.core.models import ScanResult, Finding
from datetime import datetime


def test_sdk_scanner_scan_text_and_dict():
    scanner = SDKScanner()
    text_findings = scanner.scan_text("Contact me: test@example.com and 555-123-4567")
    types = {f["type"] for f in text_findings}
    assert {"email", "phone"} & types

    dict_findings = scanner.scan_dictionary({"note": "ssn 123-45-6789"})
    assert any(f["type"] == "ssn" for f in dict_findings)


def test_sdk_scanner_coverage_and_analysis():
    # Build a minimal ScanResult and pass to coverage calculator via SDKScanner
    findings = [
        Finding(
            type="email",
            value="a@example.com",
            span=(0, 5),
            column="email",
            row_index=0,
            confidence=0.9,
            evidence="e",
        ),
        Finding(
            type="phone",
            value="555-123-4567",
            span=(0, 5),
            column="phone",
            row_index=0,
            confidence=0.8,
            evidence="e",
        ),
    ]
    sr = ScanResult(
        findings=findings,
        coverage_score=0.5,
        scan_metadata={"columns": ["email", "phone"], "total_columns": 2},
        policy_hash="h",
        timestamp=datetime.now(),
        dataset_name="d",
        total_rows=1,
        total_columns=2,
    )
    scanner = SDKScanner()
    cov = scanner.get_coverage_score(sr)
    assert cov["column_coverage"] > 0

    # Analyze findings
    stats = scanner.analyze_findings(findings)
    assert stats["total_findings"] == 2
    assert stats["average_confidence"] > 0
