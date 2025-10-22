"""
Diff command for comparing datasets before and after transformation.
"""

import sys
from pathlib import Path

import click
import pandas as pd

from ..utils import load_dataframe


@click.command()
@click.argument("original_file", type=click.Path(exists=True, path_type=Path))
@click.argument("transform_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file for diff results",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "csv", "json"]),
    default="table",
    help="Output format for diff results",
)
@click.option(
    "--show-changes", is_flag=True, help="Show actual value changes (use with caution)"
)
@click.option("--summary-only", is_flag=True, help="Show only summary statistics")
@click.pass_context
def diff_command(
    ctx,
    original_file,
    transform_file,
    output,
    output_format,
    show_changes,
    summary_only,
):
    """
    Compare original and transform datasets.

    Analyzes the differences between original and transform data files
    to verify transformation effectiveness and identify any issues.

    ORIGINAL_FILE: Path to the original data file
    TRANSFORM_FILE: Path to the transform data file
    """
    verbose = ctx.obj["verbose"]

    try:
        # Load both datasets
        if verbose:
            click.echo(f"Loading original data from: {original_file}")
        original_df = load_dataframe(original_file)

        if verbose:
            click.echo(f"Loading transform data from: {transform_file}")
        transform_df = load_dataframe(transform_file)

        # Basic validation
        if original_df.shape != transform_df.shape:
            click.echo("Warning: Datasets have different shapes", err=True)
            click.echo(
                f"Original: {original_df.shape}, TRANSFORM: {transform_df.shape}",
                err=True,
            )

        if list(original_df.columns) != list(transform_df.columns):
            click.echo("Warning: Datasets have different columns", err=True)

        # Calculate differences
        diff_results = calculate_differences(original_df, transform_df, show_changes)

        # Display summary
        click.echo("\\n=== TRANSFORM Diff Summary ===")
        click.echo(f"Total Rows: {diff_results['total_rows']}")
        click.echo(f"Total Columns: {diff_results['total_columns']}")
        click.echo(f"Changed Cells: {diff_results['changed_cells']}")
        click.echo(f"Change Rate: {diff_results['change_rate']:.2%}")

        # Column-level changes
        if diff_results["column_changes"]:
            click.echo("\\nChanges by Column:")
            for column, changes in diff_results["column_changes"].items():
                click.echo(f"  {column}: {changes} changes")

        # Show detailed changes if requested and not summary-only
        if not summary_only:
            if show_changes and diff_results["detailed_changes"]:
                click.echo("\\n=== Detailed Changes ===")
                for change in diff_results["detailed_changes"][
                    :20
                ]:  # Limit to first 20
                    click.echo(
                        f"Row {change['row']}, Column '{change['column']}': "
                        f"'{change['original']}' → '{change['transform']}'"
                    )

                if len(diff_results["detailed_changes"]) > 20:
                    click.echo(
                        f"... and {len(diff_results['detailed_changes']) - 20} more changes"
                    )

            # Data type preservation check
            type_changes = check_data_type_preservation(original_df, transform_df)
            if type_changes:
                click.echo("\\n=== Data Type Changes ===")
                for column, change in type_changes.items():
                    click.echo(
                        f"  {column}: {change['original']} → {change['transform']}"
                    )

        # Save results if output specified
        if output:
            save_diff_results(diff_results, output, output_format)
            click.echo(f"\\nDiff results saved to: {output}")

        # Exit with appropriate code
        if diff_results["changed_cells"] == 0:
            click.echo("\\nNo changes detected", err=True)
            sys.exit(1)
        else:
            sys.exit(0)

    except Exception as e:
        click.echo(f"Error during diff: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


def calculate_differences(original_df, transform_df, include_details=False):
    """Calculate differences between original and transform dataframes."""
    total_cells = original_df.size
    changed_cells = 0
    column_changes = {}
    detailed_changes = []

    # Compare each cell
    for column in original_df.columns:
        if column not in transform_df.columns:
            continue

        column_change_count = 0

        for idx in original_df.index:
            if idx not in transform_df.index:
                continue

            original_val = str(original_df.loc[idx, column])
            transform_val = str(transform_df.loc[idx, column])

            if original_val != transform_val:
                changed_cells += 1
                column_change_count += 1

                if include_details:
                    detailed_changes.append(
                        {
                            "row": idx,
                            "column": column,
                            "original": original_val,
                            "transform": transform_val,
                        }
                    )

        if column_change_count > 0:
            column_changes[column] = column_change_count

    return {
        "total_rows": len(original_df),
        "total_columns": len(original_df.columns),
        "total_cells": total_cells,
        "changed_cells": changed_cells,
        "change_rate": changed_cells / total_cells if total_cells > 0 else 0,
        "column_changes": column_changes,
        "detailed_changes": detailed_changes if include_details else [],
    }


def check_data_type_preservation(original_df, transform_df):
    """Check if data types are preserved after transformation."""
    type_changes = {}

    for column in original_df.columns:
        if column in transform_df.columns:
            original_type = str(original_df[column].dtype)
            transform_type = str(transform_df[column].dtype)

            if original_type != transform_type:
                type_changes[column] = {
                    "original": original_type,
                    "transform": transform_type,
                }

    return type_changes


def save_diff_results(diff_results, output_path, format_type):
    """Save diff results to file."""
    import json

    if format_type == "json":
        with open(output_path, "w") as f:
            json.dump(diff_results, f, indent=2, default=str)
    elif format_type == "csv":
        # Save detailed changes as CSV
        if diff_results["detailed_changes"]:
            df = pd.DataFrame(diff_results["detailed_changes"])
            df.to_csv(output_path, index=False)
        else:
            # Save summary as CSV
            summary_data = {
                "metric": [
                    "total_rows",
                    "total_columns",
                    "changed_cells",
                    "change_rate",
                ],
                "value": [
                    diff_results["total_rows"],
                    diff_results["total_columns"],
                    diff_results["changed_cells"],
                    diff_results["change_rate"],
                ],
            }
            pd.DataFrame(summary_data).to_csv(output_path, index=False)
    else:  # table format
        with open(output_path, "w") as f:
            f.write("=== TRANSFORM Diff Summary ===\\n")
            f.write(f"Total Rows: {diff_results['total_rows']}\\n")
            f.write(f"Total Columns: {diff_results['total_columns']}\\n")
            f.write(f"Changed Cells: {diff_results['changed_cells']}\\n")
            f.write(f"Change Rate: {diff_results['change_rate']:.2%}\\n")

            if diff_results["column_changes"]:
                f.write("\\nChanges by Column:\\n")
                for column, changes in diff_results["column_changes"].items():
                    f.write(f"  {column}: {changes} changes\\n")
