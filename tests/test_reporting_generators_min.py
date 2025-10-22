"""
Minimal tests for JSONReportGenerator sanitization and context fields.
"""

from datetime import datetime
from pathlib import Path

from nopii.reporting.generators import JSONReportGenerator
from nopii.core.models import Finding, ScanResult, AuditReport


def make_audit_with_sample() -> AuditReport:
    # One finding with a value that should be removed when include_samples=False
    finding = Finding(
        type="email",
        value="user@example.com",
        span=(0, 16),
        column="text",
        row_index=0,
        confidence=0.9,
        evidence="detected",
    )
    scan = ScanResult(
        findings=[finding],
        coverage_score=0.5,
        scan_metadata={"source": "unit"},
        policy_hash="abc",
        timestamp=datetime.now(),
        dataset_name="text",
        total_rows=1,
        total_columns=1,
    )
    return AuditReport(
        job_name="job",
        timestamp=datetime.now(),
        policy_hash="abc",
        coverage_score=0.5,
        residual_risk=0.2,
        summary_stats={"total_findings": 1},
        findings_by_type={"email": [finding]},
        performance_metrics={"total_time": 0.01},
        samples={},
        scan_result=scan,
    )


def test_json_report_sanitizes_samples(tmp_path: Path):
    audit = make_audit_with_sample()
    gen = JSONReportGenerator()
    out = tmp_path / "r.json"
    content = gen.generate(audit, output_path=out, include_samples=False)
    assert out.exists()
    # Parse back to validate sanitization specifically in audit_report.scan_result.findings
    import json

    data = json.loads(content)
    findings = data["audit_report"]["scan_result"]["findings"]
    assert all("value" not in f for f in findings)
    # Basic required groups present
    assert "report_metadata" in data
    assert "summary" in data
