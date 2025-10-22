"""
Report generators for different output formats.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from jinja2 import Template

from ..core.models import AuditReport
from .. import __version__
from .coverage import CoverageCalculator
from .templates import get_template


class BaseReportGenerator:
    """Base class for report generators."""

    def __init__(self):
        self.coverage_calculator = CoverageCalculator()

    def _prepare_context(
        self, audit_report: AuditReport, include_samples: bool = False, **kwargs
    ) -> Dict[str, Any]:
        """
        Prepare template context from audit report.

        Args:
            audit_report: The audit report to generate from
            include_samples: Whether to include PII samples
            **kwargs: Additional context variables

        Returns:
            Dictionary with template context
        """
        # Calculate coverage metrics
        transform_coverage = self.coverage_calculator.calculate_transform_coverage(
            audit_report
        )
        residual_risk = self.coverage_calculator.calculate_residual_risk(audit_report)
        detection_cov = self.coverage_calculator.calculate_detection_coverage(
            audit_report.scan_result
        )

        # Prepare findings data
        findings_data = []
        pii_type_counts: Dict[str, int] = {}

        for finding in audit_report.findings:
            # Count PII types
            pii_type_counts[finding.type] = pii_type_counts.get(finding.type, 0) + 1

            # Prepare finding data
            finding_data = {
                "type": finding.type,
                "column": finding.column,
                "row": getattr(finding, "row_index", None),
                "confidence": finding.confidence,
                "confidence_level": self._get_confidence_level(finding.confidence),
                "action_taken": finding.action_taken,
                "sample_value": finding.value if include_samples else None,
            }
            findings_data.append(finding_data)

        # Calculate derived metrics
        coverage_score = transform_coverage.get("policy_compliance_rate", 0.0) * 100
        residual_risk_score = residual_risk.get("risk_score", 0.0) * 100
        column_coverage = detection_cov.get("column_coverage", 0.0) * 100
        type_coverage = detection_cov.get("type_coverage", 0.0) * 100
        confidence_weighted_coverage = (
            detection_cov.get("confidence_weighted_coverage", 0.0) * 100
        )

        # Prepare context
        context = {
            # Basic info
            "job_name": audit_report.job_name,
            "timestamp": audit_report.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "version": __version__,
            # Key metrics
            "coverage_score": round(coverage_score, 1),
            "residual_risk": round(residual_risk_score, 1),
            "total_findings": len(audit_report.findings),
            "processing_time": round(
                audit_report.performance_metrics.get(
                    "total_time",
                    audit_report.performance_metrics.get("total_duration", 0),
                ),
                2,
            ),
            # Coverage metrics
            "transform_rate": round(
                transform_coverage.get("transform_rate", 0.0) * 100, 1
            ),
            "transformation_success_rate": round(
                transform_coverage.get("transformation_success_rate", 0.0) * 100, 1
            ),
            "policy_compliance": round(
                transform_coverage.get("policy_compliance_rate", 0.0) * 100, 1
            ),
            # Detection coverage metrics
            "column_coverage": round(column_coverage, 1),
            "type_coverage": round(type_coverage, 1),
            "confidence_weighted_coverage": round(confidence_weighted_coverage, 1),
            # Risk metrics
            "overall_risk": round(residual_risk.get("overall_risk", 0.0) * 100, 1),
            "high_confidence_risk": round(
                residual_risk.get("high_confidence_risk", 0.0) * 100, 1
            ),
            "sensitive_type_risk": round(
                residual_risk.get("sensitive_type_risk", 0.0) * 100, 1
            ),
            "risk_score": round(residual_risk.get("risk_score", 0.0) * 100, 1),
            # Data
            "findings": findings_data,
            "pii_type_counts": pii_type_counts,
            "unique_types": len(pii_type_counts),
            "affected_columns": len(
                set(f.column for f in audit_report.findings if f.column)
            ),
            # Display options
            "show_findings": len(findings_data) > 0,
            "include_samples": include_samples,
            # CSS classes for styling
            "coverage_class": self._get_coverage_class(coverage_score),
            "risk_class": self._get_risk_class(residual_risk_score),
            "risk_level": self._get_risk_level(residual_risk_score),
            # Data quality (if available)
            "preservation_rate": round(
                audit_report.metadata.get("preservation_rate", 100.0), 1
            ),
            "null_introduction_rate": round(
                audit_report.metadata.get("null_introduction_rate", 0.0), 1
            ),
            "dtype_preservation_rate": round(
                audit_report.metadata.get("dtype_preservation_rate", 100.0), 1
            ),
            "format_preservation_rate": round(
                audit_report.metadata.get("format_preservation_rate", 100.0), 1
            ),
        }

        # Add any additional context
        context.update(kwargs)

        return context

    def _get_confidence_level(self, confidence: float) -> str:
        """Get confidence level string."""
        if confidence >= 0.8:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        else:
            return "low"

    def _get_coverage_class(self, coverage_score: float) -> str:
        """Get CSS class for coverage score."""
        if coverage_score >= 90:
            return "coverage-excellent"
        elif coverage_score >= 75:
            return "coverage-good"
        elif coverage_score >= 50:
            return "coverage-fair"
        else:
            return "coverage-poor"

    def _get_risk_class(self, risk_score: float) -> str:
        """Get CSS class for risk score."""
        if risk_score >= 30:
            return "risk-high"
        elif risk_score >= 10:
            return "risk-medium"
        else:
            return "risk-low"

    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level string."""
        if risk_score >= 30:
            return "HIGH"
        elif risk_score >= 10:
            return "MEDIUM"
        else:
            return "LOW"


class HTMLReportGenerator(BaseReportGenerator):
    """Generates HTML audit reports."""

    def generate(
        self,
        audit_report: AuditReport,
        output_path: Optional[Path] = None,
        template_name: str = "default",
        include_samples: bool = False,
        **kwargs,
    ) -> str:
        """
        Generate HTML report.

        Args:
            audit_report: The audit report to generate from
            output_path: Optional path to save the report
            template_name: Name of the template to use
            include_samples: Whether to include PII samples
            **kwargs: Additional template context

        Returns:
            Generated HTML content
        """
        # Get template
        template_content = get_template(template_name, "html")
        template = Template(template_content)

        # Prepare context
        context = self._prepare_context(audit_report, include_samples, **kwargs)

        # Render template
        html_content = template.render(**context)

        # Save if output path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

        return html_content


class MarkdownReportGenerator(BaseReportGenerator):
    """Generates Markdown audit reports."""

    def generate(
        self,
        audit_report: AuditReport,
        output_path: Optional[Path] = None,
        template_name: str = "default",
        include_samples: bool = False,
        **kwargs,
    ) -> str:
        """
        Generate Markdown report.

        Args:
            audit_report: The audit report to generate from
            output_path: Optional path to save the report
            template_name: Name of the template to use
            include_samples: Whether to include PII samples
            **kwargs: Additional template context

        Returns:
            Generated Markdown content
        """
        # Get template
        template_content = get_template(template_name, "markdown")
        template = Template(template_content)

        # Prepare context
        context = self._prepare_context(audit_report, include_samples, **kwargs)

        # Render template
        markdown_content = template.render(**context)

        # Save if output path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)

        return markdown_content


class JSONReportGenerator(BaseReportGenerator):
    """Generates JSON audit reports."""

    def generate(
        self,
        audit_report: AuditReport,
        output_path: Optional[Path] = None,
        include_samples: bool = False,
        pretty: bool = True,
        **kwargs,
    ) -> str:
        """
        Generate JSON report.

        Args:
            audit_report: The audit report to generate from
            output_path: Optional path to save the report
            include_samples: Whether to include PII samples
            pretty: Whether to format JSON with indentation
            **kwargs: Additional data to include

        Returns:
            Generated JSON content
        """
        # Prepare context
        context = self._prepare_context(audit_report, include_samples, **kwargs)

        # Add raw audit report data (optionally sanitizing PII samples)
        report_data = audit_report.model_dump()
        if not include_samples:
            # Remove raw values from nested scan_result findings if present
            try:
                for f in report_data.get("scan_result", {}).get("findings", []):
                    # 'value' and possibly 'evidence' may contain samples
                    f.pop("value", None)
            except Exception as e:
                logging.warning("Failed to remove raw values from findings: %s", e)

        # Combine context and report data
        json_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "generator_version": __version__,
                "include_samples": include_samples,
            },
            "summary": {
                "job_name": context["job_name"],
                "timestamp": context["timestamp"],
                "coverage_score": context["coverage_score"],
                "residual_risk": context["residual_risk"],
                "total_findings": context["total_findings"],
                "processing_time": context["processing_time"],
                "risk_level": context["risk_level"],
            },
            "metrics": {
                "coverage": {
                    "transform_rate": context["transform_rate"],
                    "transformation_success_rate": context[
                        "transformation_success_rate"
                    ],
                    "policy_compliance": context["policy_compliance"],
                },
                "risk": {
                    "overall_risk": context["overall_risk"],
                    "high_confidence_risk": context["high_confidence_risk"],
                    "sensitive_type_risk": context["sensitive_type_risk"],
                    "risk_score": context["risk_score"],
                },
                "data_quality": {
                    "preservation_rate": context["preservation_rate"],
                    "null_introduction_rate": context["null_introduction_rate"],
                    "dtype_preservation_rate": context["dtype_preservation_rate"],
                    "format_preservation_rate": context["format_preservation_rate"],
                },
            },
            "statistics": {
                "pii_type_counts": context["pii_type_counts"],
                "unique_types": context["unique_types"],
                "affected_columns": context["affected_columns"],
            },
            "audit_report": report_data,
        }

        # Add any additional data
        json_data.update(kwargs)

        # Generate JSON
        if pretty:
            json_content = json.dumps(
                json_data, indent=2, default=str, ensure_ascii=False
            )
        else:
            json_content = json.dumps(json_data, default=str, ensure_ascii=False)

        # Save if output path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_content)

        return json_content
