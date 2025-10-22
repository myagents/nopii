"""CLI utility functions."""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

try:
    import pandas as pd
except Exception:  # pragma: no cover
    pd = None
import yaml

from ..core.models import Finding, ScanResult
from ..policy import Policy
from ..policy.loader import load_policy as _load_policy


def load_dataframe(file_path: str) -> pd.DataFrame:
    """Load a DataFrame from various file formats."""
    path = Path(file_path)

    if not path.exists():
        raise click.ClickException(f"File not found: {file_path}")

    suffix = path.suffix.lower()

    try:
        if pd is None:
            raise click.ClickException(
                "pandas is required to load tabular files. Install pandas to proceed."
            )
        if suffix == ".csv":
            return pd.read_csv(file_path)
        elif suffix == ".json":
            return pd.read_json(file_path)
        elif suffix in [".xlsx", ".xls"]:
            return pd.read_excel(file_path)
        elif suffix == ".parquet":
            return pd.read_parquet(file_path)
        else:
            raise click.ClickException(f"Unsupported file format: {suffix}")
    except Exception as e:
        raise click.ClickException(f"Error loading file {file_path}: {str(e)}")


def save_dataframe(
    df: pd.DataFrame, file_path: str, format: Optional[str] = None
) -> None:
    """Save a DataFrame to various file formats."""
    path = Path(file_path)

    # Create parent directories if they don't exist
    path.parent.mkdir(parents=True, exist_ok=True)

    # Determine format from file extension if not specified
    if format is None:
        format = path.suffix.lower().lstrip(".")

    try:
        if pd is None:
            raise click.ClickException(
                "pandas is required to save tabular files. Install pandas to proceed."
            )
        if format == "csv":
            df.to_csv(file_path, index=False)
        elif format == "json":
            df.to_json(file_path, orient="records", indent=2)
        elif format in ["xlsx", "xls"]:
            df.to_excel(file_path, index=False)
        elif format == "parquet":
            df.to_parquet(file_path, index=False)
        else:
            raise click.ClickException(f"Unsupported output format: {format}")
    except Exception as e:
        raise click.ClickException(f"Error saving file {file_path}: {str(e)}")


def load_policy(policy_path: str) -> Policy:
    """Load a policy from a YAML file via policy.loader."""
    try:
        return _load_policy(policy_path)
    except Exception as e:
        raise click.ClickException(f"Error loading policy from {policy_path}: {str(e)}")


def save_scan_results(
    results: List[ScanResult], output_path: str, format: str = "json"
) -> None:
    """Save scan results to a file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Convert results to serializable format
    data: List[Dict[str, Any]] = []
    for result in results:
        result_dict: Dict[str, Any] = {
            "dataset_name": result.dataset_name,
            "total_findings": len(result.findings),
            "coverage_score": result.coverage_score,
            "timestamp": result.timestamp.isoformat(),
            "policy_hash": result.policy_hash,
            "total_rows": result.total_rows,
            "total_columns": result.total_columns,
            "findings": [],
        }

        for finding in result.findings:
            finding_dict = {
                "type": finding.type,
                "value": finding.value,
                "confidence": finding.confidence,
                "span": finding.span,
                "column": finding.column,
                "row_index": finding.row_index,
                "evidence": finding.evidence,
                "transformed_value": finding.transformed_value,
                "action_taken": finding.action_taken,
            }
            result_dict["findings"].append(finding_dict)

        data.append(result_dict)

    try:
        if format.lower() == "json":
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)
        elif format.lower() in ["yaml", "yml"]:
            with open(output_path, "w") as f:
                yaml.dump(data, f, default_flow_style=False)
        else:
            raise click.ClickException(f"Unsupported output format: {format}")
    except Exception as e:
        raise click.ClickException(f"Error saving results to {output_path}: {str(e)}")


def format_findings_table(findings: List[Finding]) -> str:
    """Format findings as a table for display."""
    if not findings:
        return "No PII findings detected."

    # Create table data
    headers = ["Type", "Value", "Confidence", "Position", "Context"]
    rows = []

    for finding in findings:
        context = (
            finding.evidence[:50] + "..."
            if len(finding.evidence) > 50
            else finding.evidence
        )
        rows.append(
            [
                finding.type,
                finding.value[:20] + "..."
                if len(finding.value) > 20
                else finding.value,
                f"{finding.confidence:.2f}",
                f"{finding.span[0]}-{finding.span[1]}",
                context,
            ]
        )

    # Calculate column widths
    col_widths = [len(header) for header in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    # Format table
    separator = "+" + "+".join("-" * (width + 2) for width in col_widths) + "+"
    header_row = (
        "|"
        + "|".join(f" {header:<{col_widths[i]}} " for i, header in enumerate(headers))
        + "|"
    )

    table_lines = [separator, header_row, separator]

    for row in rows:
        row_line = (
            "|"
            + "|".join(f" {str(cell):<{col_widths[i]}} " for i, cell in enumerate(row))
            + "|"
        )
        table_lines.append(row_line)

    table_lines.append(separator)

    return "\n".join(table_lines)


def validate_file_path(ctx, _param, value):
    """Validate that a file path exists."""
    if value and not Path(value).exists():
        raise click.BadParameter(f"File not found: {value}")
    return value


def validate_output_dir(ctx, _param, value):
    """Validate and create output directory if needed."""
    if value:
        path = Path(value)
        if path.exists() and not path.is_dir():
            raise click.BadParameter(
                f"Output path exists but is not a directory: {value}"
            )
        path.mkdir(parents=True, exist_ok=True)
    return value


def get_file_size_mb(file_path: str) -> float:
    """Get file size in megabytes."""
    return Path(file_path).stat().st_size / (1024 * 1024)


def confirm_large_file_operation(file_path: str, threshold_mb: float = 100.0) -> bool:
    """Confirm operation on large files."""
    size_mb = get_file_size_mb(file_path)
    if size_mb > threshold_mb:
        return click.confirm(
            f"File {file_path} is {size_mb:.1f}MB. This operation may take a while. Continue?"
        )
    return True


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Setup logging configuration."""
    import logging

    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )


def print_summary(scan_results: List[ScanResult]) -> None:
    """Print a summary of scan results."""
    if not scan_results:
        click.echo("No files scanned.")
        return

    total_files = len(scan_results)
    total_findings = sum(len(result.findings) for result in scan_results)
    avg_coverage = sum(result.coverage_score for result in scan_results) / total_files

    click.echo("\nScan Summary:")
    click.echo(f"  Files scanned: {total_files}")
    click.echo(f"  Total findings: {total_findings}")
    click.echo(f"  Average coverage score: {avg_coverage:.2f}")

    # Show files with highest risk
    high_risk_files = [r for r in scan_results if len(r.findings) > 0]
    if high_risk_files:
        click.echo("\nFiles with PII detected:")
        for result in sorted(
            high_risk_files, key=lambda x: len(x.findings), reverse=True
        )[:5]:
            click.echo(f"  {result.dataset_name}: {len(result.findings)} findings")


def get_config_dir() -> Path:
    """Get the configuration directory for nopii."""
    config_dir = Path.home() / ".nopii"
    config_dir.mkdir(exist_ok=True)
    return config_dir


def get_default_policy_path() -> Path:
    """Get the default policy file path."""
    return get_config_dir() / "default_policy.yaml"


def create_default_policy() -> None:
    """Create a default policy file if it doesn't exist."""
    policy_path = get_default_policy_path()
    if not policy_path.exists():
        default_policy = Policy()
        # Save as YAML
        import yaml

        with open(policy_path, "w") as f:
            yaml.dump(
                {
                    "version": default_policy.version,
                    "locale_packs": default_policy.locale_packs,
                    "default_action": default_policy.default_action,
                    "thresholds": default_policy.thresholds,
                    "reporting": default_policy.reporting,
                    "secrets": default_policy.secrets,
                    "rules": [vars(rule) for rule in default_policy.rules],
                    "exceptions": [vars(exc) for exc in default_policy.exceptions],
                },
                f,
                default_flow_style=False,
            )
        click.echo(f"Created default policy at: {policy_path}")


## Deprecated CLI report/output helpers removed; CLI commands implement their own rendering.
