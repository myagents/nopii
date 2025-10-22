"""
Scan command for detecting PII in data files.
"""

import csv
import json
import sys
from pathlib import Path

import click

from ...core.scanner import Scanner
from ..utils import format_findings_table, load_dataframe


@click.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file for scan results",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "table", "csv"]),
    default="table",
    help="Output format for results",
)
@click.option(
    "--dataset-name", default="unknown", help="Name of the dataset being scanned"
)
@click.option(
    "--confidence-threshold",
    type=float,
    default=0.5,
    help="Minimum confidence threshold for PII detection",
)
@click.option(
    "--show-samples",
    is_flag=True,
    help="Include sample values in output (use with caution)",
)
@click.pass_context
def scan_command(
    ctx,
    input_file,
    output,
    output_format,
    dataset_name,
    confidence_threshold,
    show_samples,
):
    """
    Scan a data file for PII.

    Analyzes the input file and reports detected PII with confidence scores
    and coverage metrics.

    INPUT_FILE: Path to the data file to scan (CSV, JSON, or Parquet)
    """
    policy = ctx.obj["policy"]
    verbose = ctx.obj["verbose"]

    try:
        # Load the data
        if verbose:
            click.echo(f"Loading data from: {input_file}")

        # Create scanner
        scanner = Scanner(policy)

        # Prefer streaming for CSV/text to avoid large memory usage
        if input_file.suffix.lower() in [".csv", ".txt", ".md"]:
            scan_result = scanner.scan_file(input_file, confidence_threshold)
            if verbose:
                click.echo(
                    f"Stream-scanned {scan_result.total_rows} rows and {scan_result.total_columns} columns"
                )
        else:
            df = load_dataframe(input_file)
            if verbose:
                click.echo(f"Loaded {len(df)} rows and {len(df.columns)} columns")
            scan_result = scanner.scan_dataframe(df, dataset_name)

        # Filter findings by confidence threshold
        # If using streaming with threshold, findings already filtered; but safe to filter again
        filtered_findings = [
            f for f in scan_result.findings if f.confidence >= confidence_threshold
        ]

        if verbose:
            click.echo(
                f"Found {len(filtered_findings)} PII instances above confidence threshold {confidence_threshold}"
            )

        # Prepare output data
        by_type = {k: len(v) for k, v in scan_result.get_findings_by_type().items()}
        output_data = {
            "scan_metadata": {
                "input_file": str(input_file),
                "dataset_name": dataset_name,
                "total_rows": scan_result.total_rows,
                "total_columns": scan_result.total_columns,
                "coverage_score": scan_result.coverage_score,
                "confidence_threshold": confidence_threshold,
                "policy_name": policy.name,
                "policy_version": policy.version,
            },
            "summary": scan_result.get_summary_stats(),
            "findings_by_type": by_type,
            "findings": [],
        }

        # Add findings details
        for finding in filtered_findings:
            finding_data = {
                "type": finding.type,
                "column": finding.column,
                "row_index": finding.row_index,
                "confidence": finding.confidence,
                "span": finding.span,
            }

            if show_samples:
                finding_data["value"] = finding.value

            output_data["findings"].append(finding_data)

        # Output results
        if output:
            # Save to file
            if output_format == "json":
                with open(output, "w", encoding="utf-8") as f:
                    json.dump(output_data, f, indent=2, default=str)
            elif output_format == "csv":
                with open(output, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    header = ["type", "column", "row_index", "confidence", "span"]
                    if show_samples:
                        header.append("value")
                    writer.writerow(header)
                    for item in output_data["findings"]:
                        row = [
                            item["type"],
                            item["column"],
                            item["row_index"],
                            item["confidence"],
                            item["span"],
                        ]
                        if show_samples:
                            row.append(item.get("value", ""))
                        writer.writerow(row)
            elif output_format == "table":
                # Table output to file as plain text
                table_text = format_findings_table(filtered_findings)
                with open(output, "w", encoding="utf-8") as f:
                    f.write(table_text + "\n")
            click.echo(f"Scan results saved to: {output}")
        else:
            # Display to stdout
            if output_format == "json":
                click.echo(json.dumps(output_data, indent=2, default=str))
            elif output_format == "csv":
                writer = csv.writer(sys.stdout)
                header = ["type", "column", "row_index", "confidence", "span"]
                if show_samples:
                    header.append("value")
                writer.writerow(header)
                for item in output_data["findings"]:
                    row = [
                        item["type"],
                        item["column"],
                        item["row_index"],
                        item["confidence"],
                        item["span"],
                    ]
                    if show_samples:
                        row.append(item.get("value", ""))
                    writer.writerow(row)
            else:  # table
                click.echo(format_findings_table(filtered_findings))

        # Exit with appropriate code
        if filtered_findings:
            click.echo(f"\\nFound {len(filtered_findings)} PII instances", err=True)
            sys.exit(1)
        else:
            click.echo("\\nNo PII detected")
            sys.exit(0)

    except Exception as e:
        click.echo(f"Error during scan: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)
