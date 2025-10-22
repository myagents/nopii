"""
Lightweight smoke tests for SDK high-level flows without pandas.
"""

from pathlib import Path
from datetime import datetime

from nopii.sdk import NoPIIClient
from nopii.core.models import ScanResult, AuditReport


def test_quick_scan_text_summary():
    client = NoPIIClient()
    summary = client.quick_scan("Email me at test@example.com")
    assert summary["total_findings"] >= 1
    assert "email" in summary["pii_types"]


def test_generate_report_json(tmp_path: Path):
    client = NoPIIClient()

    # Build a minimal ScanResult and AuditReport
    sr = ScanResult(
        findings=[],
        coverage_score=1.0,
        scan_metadata={"source": "unit"},
        policy_hash="abc123",
        timestamp=datetime.now(),
        dataset_name="text",
        total_rows=1,
        total_columns=1,
    )
    report = AuditReport(
        job_name="sdk_smoke",
        timestamp=datetime.now(),
        policy_hash="abc123",
        coverage_score=1.0,
        residual_risk=0.0,
        summary_stats={"total_findings": 0},
        findings_by_type={},
        performance_metrics={"total_time": 0.0},
        samples={},
        scan_result=sr,
    )

    out = tmp_path / "report.json"
    content = client.generate_report(report, format_type="json", output_path=out)
    assert out.exists()
    assert "report_metadata" in content
