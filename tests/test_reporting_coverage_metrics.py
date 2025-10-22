"""
Tests for CoverageCalculator across detection, transform, and residual risk.
"""

from datetime import datetime
from nopii.reporting.coverage import CoverageCalculator
from nopii.core.models import ScanResult, Finding, AuditReport


def _mk_scan_result_with(findings):
    return ScanResult(
        findings=findings,
        coverage_score=0.5,
        scan_metadata={"total_columns": 2},
        policy_hash="h",
        timestamp=datetime.now(),
        dataset_name="d",
        total_rows=1,
        total_columns=2,
    )


def test_detection_coverage_various_metrics():
    calc = CoverageCalculator()
    sr = _mk_scan_result_with(
        [
            Finding("email", "a@example.com", (0, 1), "email", 0, 0.9, "e"),
            Finding("phone", "555-111-2222", (0, 1), "phone", 0, 0.8, "e"),
        ]
    )
    cov = calc.calculate_detection_coverage(sr, total_cells=10)
    assert cov["overall_coverage"] == 2 / 10
    assert cov["column_coverage"] > 0
    assert 0 < cov["confidence_weighted_coverage"] <= 1


def test_transform_coverage_policy_compliance_and_success():
    calc = CoverageCalculator()
    sr = _mk_scan_result_with(
        [
            Finding("email", "a@example.com", (0, 1), "email", 0, 0.9, "e"),
            Finding("phone", "555-111-2222", (0, 1), "phone", 0, 0.7, "e"),
        ]
    )
    # Build audit: mark first processed, second skipped
    a = AuditReport(
        job_name="j",
        timestamp=datetime.now(),
        policy_hash="h",
        coverage_score=0.5,
        residual_risk=0.5,
        summary_stats={"total_findings": 2},
        findings_by_type={
            "email": [sr.findings[0]],
            "phone": [sr.findings[1]],
        },
        performance_metrics={"total_time": 0.0},
        samples={},
        scan_result=sr,
    )
    # annotate actions
    sr.findings[0].action_taken = "mask"
    sr.findings[1].action_taken = "skip"

    cov = calc.calculate_transform_coverage(a)
    # Both findings counted as "transformed" (including skip), so rate is 1.0
    assert cov["transform_rate"] == 1.0
    # Only non-skip counts as success
    assert cov["transformation_success_rate"] == 0.5
    # Only high-confidence email is processed
    assert 0.0 <= cov["policy_compliance_rate"] <= 1.0


def test_residual_risk_components():
    calc = CoverageCalculator()
    sr = _mk_scan_result_with(
        [
            Finding("ssn", "123-45-6789", (0, 1), "ssn", 0, 0.95, "e"),
            Finding("email", "a@example.com", (0, 1), "email", 0, 0.4, "e"),
        ]
    )
    a = AuditReport(
        job_name="j",
        timestamp=datetime.now(),
        policy_hash="h",
        coverage_score=0.5,
        residual_risk=0.5,
        summary_stats={"total_findings": 2},
        findings_by_type={"ssn": [sr.findings[0]], "email": [sr.findings[1]]},
        performance_metrics={"total_time": 0.0},
        samples={},
        scan_result=sr,
    )
    # Mark none processed
    rr = calc.calculate_residual_risk(a)
    assert 0.0 < rr["overall_risk"] <= 1.0
    assert 0.0 < rr["high_confidence_risk"] <= 1.0
    assert 0.0 < rr["sensitive_type_risk"] <= 1.0
    assert 0.0 < rr["risk_score"] <= 1.0
