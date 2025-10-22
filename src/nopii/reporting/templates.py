"""
Report templates for different output formats.
"""

from typing import Dict, List


def get_template(template_name: str, format_type: str = "html") -> str:
    """
    Get a report template by name and format.

    Accepts arguments in either order for compatibility:
    - get_template(template_name, format_type)
    - get_template(format_type, template_name) when format_type is 'html'/'markdown'

    Args:
        template_name: Name of the template or format type
        format_type: Format type (html, markdown) or template name

    Returns:
        Template string

    Raises:
        ValueError: if format_type or template_name is invalid
    """
    templates: Dict[str, Dict[str, str]] = {
        "html": {
            "default": HTML_DEFAULT_TEMPLATE,
            "detailed": HTML_DETAILED_TEMPLATE,
            "summary": HTML_SUMMARY_TEMPLATE,
        },
        "markdown": {
            "default": MARKDOWN_DEFAULT_TEMPLATE,
            "detailed": MARKDOWN_DETAILED_TEMPLATE,
            "summary": MARKDOWN_SUMMARY_TEMPLATE,
        },
    }

    # Support reversed argument order: get_template("html", "default")
    if template_name in templates and format_type not in templates:
        fmt = template_name
        name = format_type
    else:
        fmt = format_type
        name = template_name

    if fmt not in templates:
        raise ValueError(f"Unsupported format type: {fmt}")
    if name not in templates[fmt]:
        raise ValueError(f"Unknown template '{name}' for format '{fmt}'")

    return templates[fmt][name]


def list_templates() -> Dict[str, List[str]]:
    """
    List available templates by format.

    Returns:
        Dictionary mapping format types to template names
    """
    return {
        "html": ["default", "detailed", "summary"],
        "markdown": ["default", "detailed", "summary"],
    }


# HTML Templates
HTML_DEFAULT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PII TRANSFORM Audit Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        .metric-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .risk-low { color: #28a745; }
        .risk-medium { color: #ffc107; }
        .risk-high { color: #dc3545; }
        .coverage-excellent { color: #28a745; }
        .coverage-good { color: #17a2b8; }
        .coverage-fair { color: #ffc107; }
        .coverage-poor { color: #dc3545; }
        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .section h2 {
            margin-top: 0;
            color: #495057;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
        }
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .findings-table th,
        .findings-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        .findings-table th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        .findings-table tr:hover {
            background-color: #f8f9fa;
        }
        .confidence-bar {
            width: 100px;
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
        }
        .confidence-fill {
            height: 100%;
            border-radius: 10px;
            transition: width 0.3s ease;
        }
        .confidence-high { background-color: #28a745; }
        .confidence-medium { background-color: #ffc107; }
        .confidence-low { background-color: #dc3545; }
        .pii-type {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 500;
            text-transform: uppercase;
        }
        .type-email { background-color: #e3f2fd; color: #1976d2; }
        .type-phone { background-color: #f3e5f5; color: #7b1fa2; }
        .type-ssn { background-color: #ffebee; color: #c62828; }
        .type-credit_card { background-color: #fff3e0; color: #ef6c00; }
        .type-default { background-color: #f5f5f5; color: #616161; }
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-item {
            text-align: center;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 8px;
        }
        .stat-value {
            font-size: 1.5em;
            font-weight: bold;
            color: #495057;
        }
        .stat-label {
            font-size: 0.8em;
            color: #6c757d;
            margin-top: 5px;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>PII TRANSFORM Audit Report</h1>
        <p>{{ job_name }} - {{ timestamp }}</p>
    </div>

    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-label">Coverage Score</div>
            <div class="metric-value {{ coverage_class }}">{{ coverage_score }}%</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Residual Risk</div>
            <div class="metric-value {{ risk_class }}">{{ residual_risk }}%</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">PII Instances</div>
            <div class="metric-value">{{ total_findings }}</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Processing Time</div>
            <div class="metric-value">{{ processing_time }}s</div>
        </div>
    </div>

    <div class="section">
        <h2>Summary Statistics</h2>
        <div class="summary-stats">
            <div class="stat-item">
                <div class="stat-value">{{ transform_rate }}%</div>
                <div class="stat-label">TRANSFORM Rate</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{ unique_types }}</div>
                <div class="stat-label">PII Types Found</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{ affected_columns }}</div>
                <div class="stat-label">Affected Columns</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{ policy_compliance }}%</div>
                <div class="stat-label">Policy Compliance</div>
            </div>
        </div>
    </div>

    {% if show_findings %}
    <div class="section">
        <h2>PII Findings</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Column</th>
                    <th>Row</th>
                    <th>Confidence</th>
                    <th>Action Taken</th>
                    {% if include_samples %}<th>Sample</th>{% endif %}
                </tr>
            </thead>
            <tbody>
                {% for finding in findings %}
                <tr>
                    <td><span class="pii-type type-{{ finding.type }}">{{ finding.type }}</span></td>
                    <td>{{ finding.column or 'N/A' }}</td>
                    <td>{{ finding.row or 'N/A' }}</td>
                    <td>
                        <div class="confidence-bar">
                            <div class="confidence-fill confidence-{{ finding.confidence_level }}"
                                 style="width: {{ finding.confidence * 100 }}%"></div>
                        </div>
                        {{ (finding.confidence * 100)|round(1) }}%
                    </td>
                    <td>{{ finding.action_taken or 'None' }}</td>
                    {% if include_samples %}<td>{{ finding.sample_value or 'N/A' }}</td>{% endif %}
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <div class="footer">
        <p>Generated by nopii v{{ version }} on {{ timestamp }}</p>
    </div>
</body>
</html>
"""

HTML_DETAILED_TEMPLATE = HTML_DEFAULT_TEMPLATE  # Same as default for now

HTML_SUMMARY_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PII TRANSFORM Summary</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .metric-value {
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }
        .risk-low { color: #28a745; }
        .risk-medium { color: #ffc107; }
        .risk-high { color: #dc3545; }
    </style>
</head>
<body>
    <div class="header">
        <h1>PII TRANSFORM Summary</h1>
        <p>{{ job_name }} - {{ timestamp }}</p>
    </div>

    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-label">Coverage Score</div>
            <div class="metric-value">{{ coverage_score }}%</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Residual Risk</div>
            <div class="metric-value {{ risk_class }}">{{ residual_risk }}%</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">PII Instances</div>
            <div class="metric-value">{{ total_findings }}</div>
        </div>
    </div>
</body>
</html>
"""

# Markdown Templates
MARKDOWN_DEFAULT_TEMPLATE = """
# PII TRANSFORM Audit Report

**Job:** {{ job_name }}
**Generated:** {{ timestamp }}
**Version:** {{ version }}

## Executive Summary

| Metric | Value |
|--------|-------|
| Coverage Score | {{ coverage_score }}% |
| Residual Risk | {{ residual_risk }}% |
| PII Instances Found | {{ total_findings }} |
| Processing Time | {{ processing_time }}s |

## Detailed Metrics

### Detection Coverage
- **Overall Coverage:** {{ coverage_score }}%
- **Column Coverage:** {{ column_coverage }}%
- **Type Coverage:** {{ type_coverage }}%
- **Confidence-Weighted Coverage:** {{ confidence_weighted_coverage }}%

### TRANSFORM Performance
- **TRANSFORM Rate:** {{ transform_rate }}%
- **Transformation Success Rate:** {{ transformation_success_rate }}%
- **Policy Compliance Rate:** {{ policy_compliance }}%

### Risk Assessment
- **Overall Risk:** {{ overall_risk }}%
- **High Confidence Risk:** {{ high_confidence_risk }}%
- **Sensitive Type Risk:** {{ sensitive_type_risk }}%
- **Composite Risk Score:** {{ risk_score }}%

## PII Type Distribution

{% for pii_type, count in pii_type_counts.items() %}
- **{{ pii_type }}:** {{ count }} instances
{% endfor %}

{% if show_findings %}
## Findings Details

| Type | Column | Row | Confidence | Action | {% if include_samples %}Sample{% endif %} |
|------|--------|-----|------------|--------|{% if include_samples %}------{% endif %} |
{% for finding in findings %}
| {{ finding.type }} | {{ finding.column or 'N/A' }} | {{ finding.row or 'N/A' }} | {{ (finding.confidence * 100)|round(1) }}% | {{ finding.action_taken or 'None' }} | {% if include_samples %}{{ finding.sample_value or 'N/A' }}{% endif %} |
{% endfor %}
{% endif %}

## Data Quality Impact

| Metric | Value |
|--------|-------|
| Preservation Rate | {{ preservation_rate }}% |
| Null Introduction Rate | {{ null_introduction_rate }}% |
| Data Type Preservation | {{ dtype_preservation_rate }}% |
| Format Preservation | {{ format_preservation_rate }}% |

---

*Generated by nopii v{{ version }} on {{ timestamp }}*
"""

MARKDOWN_DETAILED_TEMPLATE = MARKDOWN_DEFAULT_TEMPLATE  # Same as default for now

MARKDOWN_SUMMARY_TEMPLATE = """
# PII TRANSFORM Summary

**Job:** {{ job_name }}
**Generated:** {{ timestamp }}

## Key Metrics

| Metric | Value |
|--------|-------|
| Coverage Score | {{ coverage_score }}% |
| Residual Risk | {{ residual_risk }}% |
| PII Instances | {{ total_findings }} |

## Risk Level: {{ risk_level }}

{% if risk_level == "HIGH" %}
⚠️ **High residual risk detected.** Review findings and policy configuration.
{% elif risk_level == "MEDIUM" %}
⚡ **Medium residual risk.** Consider additional review of unprocessed findings.
{% else %}
✅ **Low residual risk.** TRANSFORM appears successful.
{% endif %}

---

*Generated by nopii v{{ version }}*
"""
