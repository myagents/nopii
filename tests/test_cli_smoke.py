"""
Lightweight smoke tests for the CLI that do not require optional deps.
"""

from pathlib import Path
import json
from click.testing import CliRunner
from nopii.cli.main import cli
from nopii import __version__


def test_cli_version_shows_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_report_command_generates_json_and_html(tmp_path: Path):
    # Minimal audit JSON compatible with CLI report rendering
    audit = {
        "job_name": "smoke_job",
        "timestamp": "2024-01-01T00:00:00Z",
        "coverage_score": 0.8,
        "residual_risk": 0.1,
        "findings_by_type": {"email": 2, "phone": 1},
    }
    audit_file = tmp_path / "audit.json"
    audit_file.write_text(json.dumps(audit), encoding="utf-8")

    runner = CliRunner()

    # JSON passthrough
    out_json = tmp_path / "out.json"
    r1 = runner.invoke(
        cli, ["report", str(audit_file), "--format", "json", "-o", str(out_json)]
    )
    assert r1.exit_code == 0
    assert out_json.exists()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data == audit

    # HTML default template
    out_html = tmp_path / "out.html"
    r2 = runner.invoke(
        cli, ["report", str(audit_file), "--format", "html", "-o", str(out_html)]
    )
    assert r2.exit_code == 0
    assert out_html.exists()
    assert "PII Audit Report" in out_html.read_text(encoding="utf-8")
