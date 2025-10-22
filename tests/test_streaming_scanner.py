"""
Tests for streaming scan in core Scanner and CLI scan path without pandas.
"""

from pathlib import Path
from click.testing import CliRunner

from nopii.core.scanner import Scanner
from nopii.policy.loader import create_default_policy
from nopii.cli.main import cli


def test_stream_scan_text_file(tmp_path: Path):
    p = tmp_path / "sample.txt"
    p.write_text("Contact me at user@example.com\nNo pii here\n", encoding="utf-8")

    scanner = Scanner(create_default_policy())
    result = scanner.scan_file(p)

    assert result.total_rows == 2
    assert any(f.type == "email" for f in result.findings)
    assert result.scan_metadata.get("streaming") is True


def test_stream_scan_csv_file(tmp_path: Path):
    p = tmp_path / "sample.csv"
    p.write_text(
        "name,email\nJohn,user@example.com\nJane,jane@test.org\n", encoding="utf-8"
    )

    scanner = Scanner(create_default_policy())
    result = scanner.scan_file(p)

    assert result.total_rows >= 1  # header not counted
    assert result.total_columns == 2
    assert {f.type for f in result.findings} >= {"email"}
    # Ensure columns are populated from header
    assert all(f.column in {"name", "email"} for f in result.findings)


def test_cli_scan_streaming_json_output(tmp_path: Path):
    # Create a tiny text file with PII to trigger exit code 1 and JSON output
    src = tmp_path / "sample.txt"
    src.write_text("email me at user@example.com", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["scan", str(src), "--format", "json", "--dataset-name", "text"]
    )
    # When PII is found, scan exits non-zero (usually 1)
    assert result.exit_code != 0
    # Basic sanity: output should include findings_by_type
    assert "findings_by_type" in result.output
