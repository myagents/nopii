from pathlib import Path
import json
import pandas as pd
from click.testing import CliRunner

from nopii.cli.main import cli
from nopii.cli.utils import format_findings_table


def test_cli_scan_json_output_and_exit_code(tmp_path: Path):
    # Create a small CSV with obvious PII
    df = pd.DataFrame(
        {
            "email": ["john@example.com", "no-pii"],
            "phone": ["555-123-4567", "n/a"],
        }
    )
    csv_path = tmp_path / "data.csv"
    df.to_csv(csv_path, index=False)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(csv_path), "--format", "json"])

    # Should return non-zero when findings are present
    assert result.exit_code != 0
    # Output should be valid JSON when requested
    out = json.loads(result.stdout)
    assert out["scan_metadata"]["input_file"].endswith("data.csv")
    assert isinstance(out["findings"], list) and len(out["findings"]) >= 1


def test_cli_transform_dry_run_writes_audit(tmp_path: Path):
    # Minimal input file
    df = pd.DataFrame({"email": ["user@example.com"]})
    input_csv = tmp_path / "in.csv"
    df.to_csv(input_csv, index=False)

    output_csv = tmp_path / "out.csv"
    audit_json = tmp_path / "audit.json"

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "transform",
            str(input_csv),
            str(output_csv),
            "--dry-run",
            "--audit-report",
            str(audit_json),
        ],
    )

    # Dry run message is printed regardless of residual risk
    assert "Dry run completed" in result.output
    # Audit report should be generated
    assert audit_json.exists()
    audit = json.loads(audit_json.read_text(encoding="utf-8"))
    assert audit["job_name"].startswith("transform_")
    assert "coverage_score" in audit and "residual_risk" in audit


def test_cli_diff_detects_changes_and_writes_json(tmp_path: Path):
    original = pd.DataFrame({"col": ["A", "B", "C"]})
    transform = pd.DataFrame({"col": ["A", "X", "C"]})
    orig_path = tmp_path / "orig.csv"
    trans_path = tmp_path / "trans.csv"
    original.to_csv(orig_path, index=False)
    transform.to_csv(trans_path, index=False)

    out_json = tmp_path / "diff.json"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "diff",
            str(orig_path),
            str(trans_path),
            "--format",
            "json",
            "-o",
            str(out_json),
        ],
    )

    assert result.exit_code == 0
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["changed_cells"] == 1
    assert data["total_rows"] == 3


def test_cli_utils_format_findings_table_empty_list():
    assert format_findings_table([]) == "No PII findings detected."
