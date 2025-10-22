"""
Extra tests for core model helpers on AuditReport and ScanResult.
"""

from datetime import datetime
from nopii.core.models import Finding, ScanResult, AuditReport


def test_audit_report_helpers():
    f1 = Finding("email", "a@example.com", (0, 1), "email", 0, 0.9, "e")
    f2 = Finding("phone", "555-111-2222", (0, 1), "phone", 0, 0.6, "e")
    sr = ScanResult(
        findings=[f1, f2],
        coverage_score=0.5,
        scan_metadata={},
        policy_hash="h",
        timestamp=datetime.now(),
        dataset_name="d",
        total_rows=1,
        total_columns=2,
    )
    # mark only one protected
    f1.action_taken = "mask"
    report = AuditReport(
        job_name="job",
        timestamp=datetime.now(),
        policy_hash="h",
        coverage_score=0.5,
        residual_risk=0.2,
        summary_stats={"total_findings": 2},
        findings_by_type={"email": [f1], "phone": [f2]},
        performance_metrics={"total_time": 0.0},
        samples={},
        scan_result=sr,
    )
    cov_by_type = report.get_coverage_by_type()
    assert cov_by_type["email"] == 1.0
    assert cov_by_type["phone"] == 0.0

    risk_factors = report.get_risk_factors()
    assert 0.0 <= risk_factors["coverage_gap"] <= 1.0
    assert report.passes_threshold(0.4) is True
