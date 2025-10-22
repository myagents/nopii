"""
Policy command for managing transformation policies.
"""

import json
import sys
from pathlib import Path

import click

from ...policy.loader import (
    create_default_policy,
    load_policy,
    save_policy,
)
from ...policy.validator import PolicyValidator


@click.group()
def policy_command():
    """
    Manage transformation policies.

    Create, validate, and inspect policy configuration files.
    """
    pass


@policy_command.command("create")
@click.argument("output_file", type=click.Path(path_type=Path))
@click.option("--name", default="custom_policy", help="Name for the new policy")
@click.option("--description", help="Description for the new policy")
@click.option(
    "--default-action",
    type=click.Choice(["redact", "mask", "hash", "tokenize", "nullify"]),
    default="redact",
    help="Default action for unmatched PII",
)
@click.pass_context
def create_policy(ctx, output_file, name, description, default_action):
    """
    Create a new policy configuration file.

    OUTPUT_FILE: Path where the new policy will be saved
    """
    verbose = ctx.obj["verbose"]

    try:
        # Create default policy as template
        policy = create_default_policy()

        # Customize with provided options
        policy.name = name
        if description:
            policy.description = description
        policy.default_action = default_action

        # Save the policy
        save_policy(policy, output_file)

        click.echo(f"Policy created: {output_file}")

        if verbose:
            click.echo(f"Policy name: {policy.name}")
            click.echo(f"Default action: {policy.default_action}")
            click.echo(f"Rules defined: {len(policy.rules)}")

    except Exception as e:
        click.echo(f"Error creating policy: {e}", err=True)
        sys.exit(1)


@policy_command.command("validate")
@click.argument("policy_file", type=click.Path(exists=True, path_type=Path))
@click.option("--strict", is_flag=True, help="Treat warnings as errors")
@click.pass_context
def validate_policy(ctx, policy_file, strict):
    """
    Validate a policy configuration file.

    POLICY_FILE: Path to the policy file to validate
    """
    verbose = ctx.obj["verbose"]

    try:
        if verbose:
            click.echo(f"Validating policy: {policy_file}")

        # Load and validate the policy
        policy = load_policy(policy_file)

        # Additional validation using the validator
        with open(policy_file, "r") as f:
            import yaml

            policy_data = yaml.safe_load(f)

        validator = PolicyValidator()
        result = validator.validate(policy_data)

        if result.is_valid:
            click.echo("✓ Policy is valid")

            if verbose:
                click.echo(f"Policy name: {policy.name}")
                click.echo(f"Version: {policy.version}")
                click.echo(f"Rules: {len(policy.rules)}")
                click.echo(f"Exceptions: {len(policy.exceptions)}")
        else:
            click.echo("✗ Policy validation failed", err=True)
            for error in result.errors:
                click.echo(f"  Error: {error}", err=True)

        # Show warnings
        if result.warnings:
            for warning in result.warnings:
                click.echo(f"  Warning: {warning}", err=True)

            if strict:
                click.echo("Treating warnings as errors due to --strict flag", err=True)
                sys.exit(1)

        if not result.is_valid:
            sys.exit(1)

    except Exception as e:
        click.echo(f"Error validating policy: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


@policy_command.command("inspect")
@click.argument("policy_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "yaml"]),
    default="table",
    help="Output format",
)
@click.pass_context
def inspect_policy(ctx, policy_file, output_format):
    """
    Inspect a policy configuration file.

    POLICY_FILE: Path to the policy file to inspect
    """
    verbose = ctx.obj["verbose"]

    try:
        # Load the policy
        policy = load_policy(policy_file)

        if output_format == "json":
            # Output as JSON
            policy_dict = policy.model_dump(exclude={"policy_hash"})
            click.echo(json.dumps(policy_dict, indent=2, default=str))

        elif output_format == "yaml":
            # Output as YAML
            import yaml

            policy_dict = policy.model_dump(exclude={"policy_hash"})
            click.echo(
                yaml.dump(policy_dict, default_flow_style=False, sort_keys=False)
            )

        else:
            # Table format
            click.echo("=== Policy Information ===")
            click.echo(f"Name: {policy.name}")
            click.echo(f"Version: {policy.version}")
            click.echo(f"Description: {policy.description or 'None'}")
            click.echo(f"Default Action: {policy.default_action}")

            click.echo(f"\\n=== Rules ({len(policy.rules)}) ===")
            for i, rule in enumerate(policy.rules, 1):
                click.echo(f"{i}. Rule {i}")
                if rule.match:
                    click.echo(f"   Match: {rule.match}")
                if rule.columns:
                    click.echo(f"   Columns: {rule.columns}")
                click.echo(f"   Action: {rule.action}")
                if rule.options:
                    click.echo(f"   Options: {rule.options}")
                if rule.override_confidence:
                    click.echo(f"   Override Confidence: {rule.override_confidence}")
                click.echo()

            if policy.exceptions:
                click.echo(f"=== Exceptions ({len(policy.exceptions)}) ===")
                for i, exception in enumerate(policy.exceptions, 1):
                    click.echo(f"{i}. Exception {i}")
                    click.echo(f"   Dataset: {exception.dataset}")
                    if exception.allow_types:
                        click.echo(f"   Allow Types: {exception.allow_types}")
                    if exception.conditions:
                        click.echo(f"   Conditions: {exception.conditions}")
                    click.echo()

            click.echo("=== Reporting Configuration ===")
            click.echo(f"Store Samples: {policy.reporting.get('store_samples', 'N/A')}")
            click.echo(f"Formats: {policy.reporting.get('formats', 'N/A')}")
            click.echo(f"Output Dir: {policy.reporting.get('output_dir', 'N/A')}")
            click.echo(
                f"Include Trends: {policy.reporting.get('include_trends', 'N/A')}"
            )

    except Exception as e:
        click.echo(f"Error inspecting policy: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


@policy_command.command("test")
@click.argument("policy_file", type=click.Path(exists=True, path_type=Path))
@click.argument("test_data", type=str)
@click.option("--pii-type", help="Expected PII type for the test data")
@click.pass_context
def test_policy(ctx, policy_file, test_data, pii_type):
    """
    Test a policy against sample data.

    POLICY_FILE: Path to the policy file to test
    TEST_DATA: Sample text or data to test against
    """
    verbose = ctx.obj["verbose"]

    try:
        # Load the policy
        policy = load_policy(policy_file)

        # Test the policy
        from ...core.scanner import Scanner
        from ...core.transform import TRANSFORM

        scanner = Scanner(policy)
        transform = TRANSFORM(policy)

        # Scan the test data
        findings = scanner.scan_text(test_data)

        click.echo("=== Scan Results ===")
        if findings:
            for finding in findings:
                click.echo(
                    f"Found {finding.type}: '{finding.value}' "
                    f"(confidence: {finding.confidence:.2f})"
                )

                if pii_type and finding.type != pii_type:
                    click.echo(
                        f"  Warning: Expected {pii_type}, found {finding.type}",
                        err=True,
                    )
        else:
            click.echo("No PII detected")
            if pii_type:
                click.echo(f"  Warning: Expected to find {pii_type}", err=True)

        # Test transformation
        transform_text, transform_findings = transform.transform_text(test_data)

        click.echo("\\n=== TRANSFORM Results ===")
        click.echo(f"Original: {test_data}")
        click.echo(f"TRANSFORM: {transform_text}")

        if transform_findings:
            click.echo("\\nTransformations applied:")
            for finding in transform_findings:
                if finding.action_taken:
                    click.echo(f"  {finding.type}: {finding.action_taken}")

    except Exception as e:
        click.echo(f"Error testing policy: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)
