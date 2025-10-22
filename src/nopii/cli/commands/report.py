"""
Report command for generating audit reports from CLI audit JSON.

This command reads the audit JSON produced by the transform command and renders
HTML/Markdown/JSON reports. For HTML/Markdown, it uses Jinja2 templates. A
custom template file can be provided via --template.
"""

import json
import sys
from pathlib import Path

import click
from jinja2 import Template


@click.command()
@click.argument("audit_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output", "-o", type=click.Path(path_type=Path), help="Output file for the report"
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["html", "markdown", "json"]),
    default="html",
    help="Report format",
)
@click.option(
    "--template",
    type=click.Path(exists=True, path_type=Path),
    help="Custom template file for HTML/Markdown reports",
)
@click.option(
    "--include-samples",
    is_flag=True,
    help="Include PII samples in the report (use with caution)",
)
@click.pass_context
def report_command(ctx, audit_file, output, output_format, template, include_samples):
    """
    Generate a comprehensive audit report.

    Creates detailed reports from audit data in various formats including
    HTML, Markdown, and JSON.

    AUDIT_FILE: Path to the audit report JSON file
    """
    verbose = ctx.obj["verbose"]

    try:
        # Load audit data
        if verbose:
            click.echo(f"Loading audit data from: {audit_file}")

        with open(audit_file, "r") as f:
            audit_data = json.load(f)

        # Determine output file if not specified
        if not output:
            output = audit_file.with_suffix(f".{output_format}")

        # Generate report based on format
        if output_format == "json":
            report_content = json.dumps(audit_data, indent=2, default=str)
        else:
            # Build a simple context compatible with our templates
            context = {
                "job_name": audit_data.get("job_name")
                or audit_data.get("scan_metadata", {}).get("job_name", "Unknown"),
                "timestamp": audit_data.get("timestamp", "Unknown"),
                "coverage_score": round(audit_data.get("coverage_score", 0.0) * 100, 1)
                if isinstance(audit_data.get("coverage_score"), (int, float))
                else audit_data.get("coverage_score", 0),
                "residual_risk": round(audit_data.get("residual_risk", 0.0) * 100, 1)
                if isinstance(audit_data.get("residual_risk"), (int, float))
                else audit_data.get("residual_risk", 0),
                "total_findings": sum(
                    len(v) if isinstance(v, list) else v
                    for v in (audit_data.get("findings_by_type") or {}).values()
                ),
                "pii_type_counts": {
                    k: (len(v) if isinstance(v, list) else v)
                    for k, v in (audit_data.get("findings_by_type") or {}).items()
                },
                "include_samples": include_samples,
            }

            # Choose template content
            if template:
                template_content = Path(template).read_text(encoding="utf-8")
            else:
                if output_format == "html":
                    template_content = _DEFAULT_HTML_TEMPLATE
                else:
                    template_content = _DEFAULT_MD_TEMPLATE

            report_content = Template(template_content).render(**context)

        # Write report to file
        with open(output, "w", encoding="utf-8") as f:
            f.write(report_content)

        click.echo(f"Report generated: {output}")

        # Display summary
        click.echo("\\n=== Report Summary ===")
        click.echo(f"Job: {audit_data.get('job_name', 'Unknown')}")
        click.echo(f"Timestamp: {audit_data.get('timestamp', 'Unknown')}")
        click.echo(f"Coverage Score: {audit_data.get('coverage_score', 0):.2%}")
        click.echo(f"Residual Risk: {audit_data.get('residual_risk', 0):.2%}")

        findings_by_type = audit_data.get("findings_by_type", {})
        total_findings = sum(
            len(findings) if isinstance(findings, list) else findings
            for findings in findings_by_type.values()
        )
        click.echo(f"Total PII Instances: {total_findings}")

        if findings_by_type:
            click.echo("\\nPII Types Found:")
            for pii_type, findings in findings_by_type.items():
                count = len(findings) if isinstance(findings, list) else findings
                click.echo(f"  {pii_type}: {count}")

    except Exception as e:
        click.echo(f"Error generating report: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


# Simple default templates for CLI report rendering
_DEFAULT_HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><title>PII Audit Report</title>
  <style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}
  h1{margin-bottom:0}.metric{display:flex;gap:1rem;flex-wrap:wrap}.card{border:1px solid #eee;padding:1rem;border-radius:8px;min-width:200px}
  table{width:100%;border-collapse:collapse;margin-top:1rem}th,td{padding:.5rem;border-bottom:1px solid #eee;text-align:left}
  </style>
  </head>
<body>
  <h1>PII Audit Report</h1>
  <p>{{ job_name }} — {{ timestamp }}</p>
  <div class="metric">
    <div class="card"><strong>Coverage</strong><div>{{ coverage_score }}%</div></div>
    <div class="card"><strong>Residual Risk</strong><div>{{ residual_risk }}%</div></div>
    <div class="card"><strong>Total PII</strong><div>{{ total_findings }}</div></div>
  </div>

  {% if pii_type_counts %}
  <h2>PII Types</h2>
  <table>
    <thead><tr><th>Type</th><th>Count</th></tr></thead>
    <tbody>
    {% for t, c in pii_type_counts.items() %}
      <tr><td>{{ t }}</td><td>{{ c }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}
</body>
</html>
"""

_DEFAULT_MD_TEMPLATE = """
# PII Audit Report

**Job:** {{ job_name }}
**Generated:** {{ timestamp }}

| Metric | Value |
|---|---|
| Coverage | {{ coverage_score }}% |
| Residual Risk | {{ residual_risk }}% |
| Total PII | {{ total_findings }} |

{% if pii_type_counts %}
## PII Types
{% for t, c in pii_type_counts.items() %}- **{{ t }}**: {{ c }}
{% endfor %}
{% endif %}
"""
