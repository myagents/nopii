"""
More tests for NoPIIClient quick_scan and report generation.
"""

from pathlib import Path
from datetime import datetime
from nopii.sdk import NoPIIClient
from nopii.core.models import ScanResult, AuditReport


def test_quick_scan_on_file_path(tmp_path: Path):
    p = tmp_path / "note.txt"
    p.write_text("reach me at user@example.com", encoding="utf-8")
    client = NoPIIClient()
    summary = client.quick_scan(str(p))
    assert summary["total_findings"] >= 1
    assert "email" in summary["pii_types"]


def test_generate_report_markdown_and_html(tmp_path: Path):
    client = NoPIIClient()
    sr = ScanResult(
        findings=[],
        coverage_score=1.0,
        scan_metadata={"source": "unit"},
        policy_hash="h",
        timestamp=datetime.now(),
        dataset_name="d",
        total_rows=1,
        total_columns=1,
    )
    ar = AuditReport(
        job_name="job",
        timestamp=datetime.now(),
        policy_hash="h",
        coverage_score=1.0,
        residual_risk=0.0,
        summary_stats={"total_findings": 0},
        findings_by_type={},
        performance_metrics={"total_time": 0.0},
        samples={},
        scan_result=sr,
    )

    md_out = tmp_path / "r.md"
    md = client.generate_report(ar, format_type="markdown", output_path=md_out)
    assert md_out.exists()
    assert "Audit Report" in md

    html_out = tmp_path / "r.html"
    html = client.generate_report(ar, format_type="html", output_path=html_out)
    assert html_out.exists()
    assert "Audit Report" in html
