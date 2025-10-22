"""
Coverage calculation utilities for PII detection and transformation.
"""

from typing import Dict, Optional

from ..core.models import ScanResult, AuditReport


class CoverageCalculator:
    """
    Calculates coverage scores and metrics for PII detection and transformation.
    """

    def __init__(self):
        pass

    def calculate_detection_coverage(
        self, scan_result: ScanResult, total_cells: Optional[int] = None
    ) -> Dict[str, float]:
        """
        Calculate detection coverage metrics.

        Args:
            scan_result: Results from PII scanning
            total_cells: Total number of cells scanned (optional)

        Returns:
            Dictionary with coverage metrics
        """
        if not scan_result.findings:
            return {
                "overall_coverage": 0.0,
                "column_coverage": 0.0,
                "type_coverage": 0.0,
                "confidence_weighted_coverage": 0.0,
            }

        # Calculate overall coverage
        pii_cells = len(scan_result.findings)
        overall_coverage = (pii_cells / total_cells) if total_cells else 0.0

        # Calculate column coverage
        columns_with_pii = len(set(f.column for f in scan_result.findings if f.column))
        # Prefer explicit metadata if available
        meta = getattr(scan_result, "scan_metadata", {}) or {}
        total_columns = (
            meta.get("total_columns")
            or len(meta.get("columns", []))
            or scan_result.total_columns
        )
        column_coverage = (columns_with_pii / total_columns) if total_columns else 0.0

        # Calculate type coverage (diversity of PII types found)
        unique_types = len(set(f.type for f in scan_result.findings))
        # Assume we're looking for common PII types
        expected_types = 8  # email, phone, ssn, credit_card, etc.
        type_coverage = min(unique_types / expected_types, 1.0)

        # Calculate confidence-weighted coverage
        total_confidence = sum(f.confidence for f in scan_result.findings)
        confidence_weighted_coverage = total_confidence / len(scan_result.findings)

        return {
            "overall_coverage": overall_coverage,
            "column_coverage": column_coverage,
            "type_coverage": type_coverage,
            "confidence_weighted_coverage": confidence_weighted_coverage,
        }

    def calculate_transform_coverage(
        self, audit_report: AuditReport
    ) -> Dict[str, float]:
        """
        Calculate transform coverage metrics.

        Args:
            audit_report: Audit report from transform process

        Returns:
            Dictionary with transform coverage metrics
        """
        if not audit_report.findings:
            return {
                "transform_rate": 0.0,
                "transformation_success_rate": 0.0,
                "policy_compliance_rate": 0.0,
            }

        # Calculate transform rate
        transform_findings = [f for f in audit_report.findings if f.action_taken]
        transform_rate = len(transform_findings) / len(audit_report.findings)

        # Calculate transformation success rate
        successful_transformations = [
            f for f in transform_findings if f.action_taken and f.action_taken != "skip"
        ]
        transformation_success_rate = (
            len(successful_transformations) / len(transform_findings)
            if transform_findings
            else 0.0
        )

        # Calculate policy compliance rate (high confidence findings processed)
        high_confidence_findings = [
            f for f in audit_report.findings if f.confidence >= 0.8
        ]
        processed_high_confidence = [
            f
            for f in high_confidence_findings
            if f.action_taken and f.action_taken != "skip"
        ]
        policy_compliance_rate = (
            len(processed_high_confidence) / len(high_confidence_findings)
            if high_confidence_findings
            else 1.0
        )

        return {
            "transform_rate": transform_rate,
            "transformation_success_rate": transformation_success_rate,
            "policy_compliance_rate": policy_compliance_rate,
        }

    def calculate_residual_risk(self, audit_report: AuditReport) -> Dict[str, float]:
        """
        Calculate residual risk metrics after transform.

        Args:
            audit_report: Audit report from transform process

        Returns:
            Dictionary with residual risk metrics
        """
        if not audit_report.findings:
            return {
                "overall_risk": 0.0,
                "high_confidence_risk": 0.0,
                "sensitive_type_risk": 0.0,
                "risk_score": 0.0,
            }

        # Identify unprocessed findings
        unprocessed_findings = [
            f
            for f in audit_report.findings
            if not f.action_taken or f.action_taken == "skip"
        ]

        if not unprocessed_findings:
            return {
                "overall_risk": 0.0,
                "high_confidence_risk": 0.0,
                "sensitive_type_risk": 0.0,
                "risk_score": 0.0,
            }

        # Calculate overall residual risk
        overall_risk = len(unprocessed_findings) / len(audit_report.findings)

        # Calculate high confidence residual risk
        high_confidence_unprocessed = [
            f for f in unprocessed_findings if f.confidence >= 0.8
        ]
        high_confidence_total = [
            f for f in audit_report.findings if f.confidence >= 0.8
        ]
        high_confidence_risk = (
            len(high_confidence_unprocessed) / len(high_confidence_total)
            if high_confidence_total
            else 0.0
        )

        # Calculate sensitive type risk
        sensitive_types = {"ssn", "credit_card", "passport", "drivers_license"}
        sensitive_unprocessed = [
            f for f in unprocessed_findings if f.type.lower() in sensitive_types
        ]
        sensitive_total = [
            f for f in audit_report.findings if f.type.lower() in sensitive_types
        ]
        sensitive_type_risk = (
            len(sensitive_unprocessed) / len(sensitive_total)
            if sensitive_total
            else 0.0
        )

        # Calculate composite risk score
        risk_score = (
            overall_risk * 0.3 + high_confidence_risk * 0.4 + sensitive_type_risk * 0.3
        )

        return {
            "overall_risk": overall_risk,
            "high_confidence_risk": high_confidence_risk,
            "sensitive_type_risk": sensitive_type_risk,
            "risk_score": risk_score,
        }

    def calculate_data_quality_metrics(
        self, original_df, transform_df
    ) -> Dict[str, float]:
        """
        Calculate data quality metrics after transform.

        Args:
            original_df: Original dataframe
            transform_df: TRANSFORM dataframe

        Returns:
            Dictionary with data quality metrics
        """
        if original_df.shape != transform_df.shape:
            raise ValueError("DataFrames must have the same shape")

        total_cells = original_df.size

        # Calculate preservation metrics
        unchanged_cells = (original_df == transform_df).sum().sum()
        preservation_rate = unchanged_cells / total_cells

        # Calculate null introduction rate
        original_nulls = original_df.isnull().sum().sum()
        transform_nulls = transform_df.isnull().sum().sum()
        null_introduction_rate = (transform_nulls - original_nulls) / total_cells

        # Calculate data type preservation
        original_dtypes = set(original_df.dtypes.astype(str))
        transform_dtypes = set(transform_df.dtypes.astype(str))
        dtype_preservation_rate = len(original_dtypes & transform_dtypes) / len(
            original_dtypes
        )

        # Calculate format preservation (for string columns)
        format_preservation_scores = []
        for col in original_df.select_dtypes(include=["object"]).columns:
            if col in transform_df.columns:
                orig_lengths = original_df[col].astype(str).str.len()
                transform_lengths = transform_df[col].astype(str).str.len()
                # Check if lengths are similar (within 20% difference)
                length_similarity = (
                    (abs(orig_lengths - transform_lengths) / orig_lengths.clip(lower=1))
                    <= 0.2
                ).mean()
                format_preservation_scores.append(length_similarity)

        format_preservation_rate = (
            sum(format_preservation_scores) / len(format_preservation_scores)
            if format_preservation_scores
            else 1.0
        )

        return {
            "preservation_rate": preservation_rate,
            "null_introduction_rate": null_introduction_rate,
            "dtype_preservation_rate": dtype_preservation_rate,
            "format_preservation_rate": format_preservation_rate,
        }
