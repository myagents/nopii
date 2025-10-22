"""
Main CLI entry point for nopii.
"""

import sys
from pathlib import Path

import click

from ..policy.loader import create_default_policy, load_policy
from .commands.diff import diff_command
from .commands.policy import policy_command
from .commands.transform import transform_command
from .commands.report import report_command
from .commands.scan import scan_command


from .. import __version__


@click.group()
@click.version_option(version=__version__)
@click.option(
    "--policy",
    "-p",
    type=click.Path(exists=True, path_type=Path),
    help="Path to policy configuration file",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx, policy, verbose):
    """
    nopii: detect, transform, and audit PII in your data.

    Detect, transform, and audit personally identifiable information (PII)
    in your data with policy-driven configuration.
    """
    # Ensure context object exists
    ctx.ensure_object(dict)

    # Store global options in context
    ctx.obj["verbose"] = verbose

    # Load policy
    if policy:
        try:
            ctx.obj["policy"] = load_policy(policy)
            if verbose:
                click.echo(f"Loaded policy from: {policy}")
        except Exception as e:
            click.echo(f"Error loading policy: {e}", err=True)
            sys.exit(1)
    else:
        # Use default policy
        ctx.obj["policy"] = create_default_policy()
        if verbose:
            click.echo("Using default policy")


# Register commands
cli.add_command(scan_command, name="scan")
cli.add_command(transform_command, name="transform")
cli.add_command(report_command, name="report")
cli.add_command(diff_command, name="diff")
cli.add_command(policy_command, name="policy")


def main():
    """Main entry point for the CLI."""
    cli()
