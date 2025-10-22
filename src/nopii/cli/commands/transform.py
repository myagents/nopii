"""
Redact command for removing PII from data files.
"""

import json
import sys
import shutil
from pathlib import Path

import click

from ...core.transform import Transform
from ..utils import load_dataframe, save_dataframe


@click.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.argument("output_file", type=click.Path(path_type=Path))
@click.option(
    "--audit-report",
    "-a",
    type=click.Path(path_type=Path),
    help="Path to save audit report (JSON format)",
)
@click.option(
    "--dataset-name", default="unknown", help="Name of the dataset being transform"
)
@click.option("--job-name", help="Name for this redaction job (for audit trail)")
@click.option(
    "--dry-run", is_flag=True, help="Perform a dry run without modifying data"
)
@click.option("--backup", is_flag=True, help="Create a backup of the original file")
@click.pass_context
def transform_command(
    ctx, input_file, output_file, audit_report, dataset_name, job_name, dry_run, backup
):
    """
    No PII from a data file.

    Processes the input file according to the policy configuration and
    generates a transform version with an audit report.

    INPUT_FILE: Path to the data file to redact
    OUTPUT_FILE: Path where transform data will be saved
    """
    policy = ctx.obj["policy"]
    verbose = ctx.obj["verbose"]

    try:
        # Load the data
        if verbose:
            click.echo(f"Loading data from: {input_file}")

        df = load_dataframe(input_file)

        if verbose:
            click.echo(f"Loaded {len(df)} rows and {len(df.columns)} columns")

        # Create backup of the original file if requested
        if backup and not dry_run:
            backup_path = input_file.with_suffix(input_file.suffix + ".backup")
            try:
                shutil.copy2(input_file, backup_path)
                if verbose:
                    click.echo(f"Created backup: {backup_path}")
            except Exception as be:
                click.echo(f"Warning: Failed to create backup: {be}", err=True)

        # Create transform and process the data
        transform = Transform(policy)

        if not job_name:
            job_name = f"transform_{dataset_name}_{input_file.stem}"

        transform_df, audit_report_obj = transform.transform_dataframe(
            df, dataset_name, dry_run, job_name
        )

        if verbose:
            findings_count = len(audit_report_obj.scan_result.findings)
            click.echo(f"Processed {findings_count} PII findings")

        # Save transform data (unless dry run)
        if not dry_run:
            save_dataframe(transform_df, output_file)
            click.echo(f"TRANSFORM data saved to: {output_file}")
        else:
            click.echo("Dry run completed - no data was modified")

        # Save audit report
        if audit_report:
            # Convert findings_by_type into counts for JSON stability
            counts_by_type = {
                k: (len(v) if isinstance(v, list) else int(v))
                for k, v in audit_report_obj.findings_by_type.items()
            }

            audit_data = {
                "job_name": audit_report_obj.job_name,
                "timestamp": audit_report_obj.timestamp.isoformat(),
                "policy_hash": audit_report_obj.policy_hash,
                "coverage_score": audit_report_obj.coverage_score,
                "residual_risk": audit_report_obj.residual_risk,
                "summary_stats": audit_report_obj.summary_stats,
                "findings_by_type": counts_by_type,
                "performance_metrics": audit_report_obj.performance_metrics,
                "samples": audit_report_obj.samples,
                "scan_metadata": {
                    "input_file": str(input_file),
                    "output_file": str(output_file) if not dry_run else None,
                    "dataset_name": dataset_name,
                    "dry_run": dry_run,
                    "policy_name": policy.name,
                    "policy_version": policy.version,
                },
            }

            with open(audit_report, "w", encoding="utf-8") as f:
                json.dump(audit_data, f, indent=2, default=str)
            click.echo(f"Audit report saved to: {audit_report}")

        # Display summary
        click.echo("\\n=== TRANSFORM Summary ===")
        click.echo(f"Coverage Score: {audit_report_obj.coverage_score:.2%}")
        click.echo(f"Residual Risk: {audit_report_obj.residual_risk:.2%}")

        for pii_type, findings in audit_report_obj.findings_by_type.items():
            click.echo(f"{pii_type}: {len(findings)} instances")

        # Show performance metrics
        if verbose:
            metrics = audit_report_obj.performance_metrics
            click.echo("\\n=== Performance Metrics ===")
            click.echo(f"Total Duration: {metrics['total_duration']:.2f}s")
            click.echo(f"Rows/Second: {metrics['rows_per_second']:.0f}")

        # Exit with appropriate code based on residual risk
        if audit_report_obj.residual_risk > 0.1:  # 10% threshold
            click.echo(
                f"\\nWarning: High residual risk ({audit_report_obj.residual_risk:.2%})",
                err=True,
            )
            sys.exit(1)
        else:
            sys.exit(0)

    except Exception as e:
        click.echo(f"Error during redaction: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)
