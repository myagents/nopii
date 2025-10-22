"""
Core transform functionality for transforming PII in data.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, List, Optional

try:  # optional pandas
    import pandas as pd
except Exception:  # pragma: no cover
    pd = None

from ..transforms.registry import TransformRegistry
from .models import AuditReport, Finding, Policy, ScanResult
from .scanner import Scanner


class Transform:
    """
    Core PII transform that applies transformations to sensitive data.

    The transform uses the scanner to detect PII and then applies policy-defined
    transformations to protect the data while maintaining utility.
    """

    def __init__(self, policy: Policy) -> None:
        """
        Initialize transform with a policy.

        Args:
            policy: Policy configuration for transformation rules
        """
        self.policy = policy
        self.scanner = Scanner(policy)
        self.transform_registry = TransformRegistry()

    def transform_dataframe(
        self,
        df: Any,
        dataset_name: str = "unknown",
        dry_run: bool = False,
        job_name: Optional[str] = None,
    ) -> tuple[Any, AuditReport]:
        """
        No PII in a pandas DataFrame.

        Args:
            df: DataFrame to transform
            dataset_name: Name of the dataset for reporting
            dry_run: If True, only generate report without modifying data
            job_name: Name for the audit report

        Returns:
            Tuple of (transform_dataframe, audit_report)
        """
        start_time = time.time()

        # First scan for PII
        scan_result = self.scanner.scan_dataframe(df, dataset_name)

        if dry_run:
            # For dry run, just return original data with report
            audit_report = self._create_audit_report(
                scan_result, job_name or f"dry_run_{dataset_name}", start_time
            )
            return df.copy(), audit_report

        # Guard optional dependency
        if pd is None:
            raise ImportError(
                "pandas is required for transform_dataframe; install pandas to use this feature"
            )

        # Create a copy to modify
        df_transform = df.copy()

        # Apply transformations (grouped per cell to avoid span drift)
        samples: Dict[str, List[str]] = {}

        cell_map: Dict[tuple[int, str], List[Finding]] = {}
        for f in scan_result.findings:
            cell_map.setdefault((f.row_index, f.column), []).append(f)

        for (row_idx, column), cell_findings in cell_map.items():
            cell_text = str(
                df_transform.iloc[row_idx, df_transform.columns.get_loc(column)]
            )
            # Sort by start position descending
            for finding in sorted(cell_findings, key=lambda x: x.span[0], reverse=True):
                if self.policy.is_allowed(dataset_name, finding.type):
                    finding.action_taken = "allow"
                    continue

                action = self._get_action_for_finding(finding)
                transformed_value = self._apply_transformation(
                    finding.value, action, finding.type
                )

                start, end = finding.span
                if 0 <= start <= end <= len(cell_text):
                    cell_text = cell_text[:start] + transformed_value + cell_text[end:]
                else:
                    cell_text = cell_text.replace(finding.value, transformed_value, 1)

                finding.transformed_value = transformed_value
                finding.action_taken = action

                if action not in samples:
                    samples[action] = []
                if len(samples[action]) < self.policy.reporting["store_samples"]:
                    samples[action].append(f"{finding.value} → {transformed_value}")

            df_transform.iloc[row_idx, df_transform.columns.get_loc(column)] = cell_text

        # Create audit report
        audit_report = self._create_audit_report(
            scan_result, job_name or f"transform_{dataset_name}", start_time, samples
        )

        return df_transform, audit_report

    def _get_action_for_finding(self, finding: Finding) -> str:
        """Determine the transformation action for a finding."""
        # Check column-specific rule first
        column_rule = self.policy.get_rule_for_column(finding.column)
        if column_rule:
            return column_rule.action

        # Check type-specific rule
        type_rule = self.policy.get_rule_for_type(finding.type)
        if type_rule:
            return type_rule.action

        # Use default action
        return self.policy.default_action

    def _apply_transformation(self, value: str, action: str, pii_type: str) -> str:
        """Apply transformation using registry and return the transformed string."""
        options = self._get_transformation_options(action, pii_type)
        result = self.transform_registry.transform(value, pii_type, action, options)
        if not result.success or result.transformed_value is None:
            fallback = self.transform_registry.transform(
                value, pii_type, "transform", options
            )
            return (
                fallback.transformed_value
                if fallback.transformed_value is not None
                else value
            )
        return result.transformed_value

    def _get_transformation_options(self, action: str, pii_type: str) -> Dict[str, Any]:
        """Get transformation options from policy rules."""
        # Check type-specific rule for options
        type_rule = self.policy.get_rule_for_type(pii_type)
        if type_rule and type_rule.options:
            return type_rule.options

        # Return default options
        return {}

    # Note: Replacement is handled inline during transform passes to avoid span drift.

    def _create_audit_report(
        self,
        scan_result: ScanResult,
        job_name: str,
        start_time: float,
        samples: Optional[Dict[str, List[str]]] = None,
    ) -> AuditReport:
        """Create a comprehensive audit report."""
        end_time = time.time()

        # Calculate residual risk
        residual_risk = self._calculate_residual_risk(scan_result)

        # Performance metrics
        performance_metrics = {
            "total_duration": end_time - start_time,
            "total_time": end_time - start_time,
            "scan_duration": scan_result.scan_metadata.get("scan_duration", 0.0),
            "transform_duration": (end_time - start_time)
            - scan_result.scan_metadata.get("scan_duration", 0.0),
            "rows_per_second": scan_result.total_rows / (end_time - start_time)
            if (end_time - start_time) > 0
            else 0,
        }

        return AuditReport(
            job_name=job_name,
            timestamp=datetime.now(),
            policy_hash=self.policy.policy_hash or "",
            coverage_score=scan_result.coverage_score,
            residual_risk=residual_risk,
            summary_stats=scan_result.get_summary_stats(),
            findings_by_type=scan_result.get_findings_by_type(),
            performance_metrics=performance_metrics,
            samples=samples or {},
            scan_result=scan_result,
        )

    def _calculate_residual_risk(self, scan_result: ScanResult) -> float:
        """
        Calculate residual risk score based on unprotected PII and confidence levels.

        Residual Risk = weighted average of:
        - Unprotected PII ratio
        - Low confidence detection ratio
        - Coverage gap
        """
        total_findings = len(scan_result.findings)
        if total_findings == 0:
            return 0.0

        # Count unprotected findings
        unprotected = len([f for f in scan_result.findings if not f.action_taken])
        unprotected_ratio = unprotected / total_findings

        # Count low confidence findings
        low_confidence = len([f for f in scan_result.findings if f.confidence < 0.5])
        low_confidence_ratio = low_confidence / total_findings

        # Coverage gap
        coverage_gap = 1.0 - scan_result.coverage_score

        # Weighted average (can be tuned based on organizational risk tolerance)
        residual_risk = (
            0.5 * unprotected_ratio + 0.3 * coverage_gap + 0.2 * low_confidence_ratio
        )

        return min(residual_risk, 1.0)

    def transform_text(
        self, text: str, dry_run: bool = False
    ) -> tuple[str, List[Finding]]:
        """
        No PII in a text string.

        Args:
            text: Text to transform
            dry_run: If True, only detect without modifying

        Returns:
            Tuple of (transform_text, findings)
        """
        findings = self.scanner.scan_text(text)

        if dry_run:
            return text, findings

        transform_text = text

        # Sort findings by span in reverse order to avoid offset issues
        sorted_findings = sorted(findings, key=lambda f: f.span[0], reverse=True)

        for finding in sorted_findings:
            action = self._get_action_for_finding(finding)
            transformed_value = self._apply_transformation(
                finding.value, action, finding.type
            )

            # Replace in text
            start, end = finding.span
            transform_text = (
                transform_text[:start] + transformed_value + transform_text[end:]
            )

            # Update finding
            finding.transformed_value = transformed_value
            finding.action_taken = action

        return transform_text, findings

    def transform_dict(
        self, data: Dict[str, Any], dry_run: bool = False
    ) -> tuple[Dict[str, Any], List[Finding]]:
        """
        No PII in a dictionary.

        Args:
            data: Dictionary to transform
            dry_run: If True, only detect without modifying

        Returns:
            Tuple of (transform_dict, findings)
        """
        findings = self.scanner.scan_dict(data)

        if dry_run:
            return data.copy(), findings

        transform_data = data.copy()

        for finding in findings:
            if finding.column in transform_data:
                action = self._get_action_for_finding(finding)
                transformed_value = self._apply_transformation(
                    finding.value, action, finding.type
                )

                # Replace in dictionary value
                original_value = str(transform_data[finding.column])
                transform_data[finding.column] = original_value.replace(
                    finding.value, transformed_value, 1
                )

                # Update finding
                finding.transformed_value = transformed_value
                finding.action_taken = action

        return transform_data, findings

    def transform_text_with_report(
        self,
        text: str,
        dataset_name: str = "text",
        job_name: Optional[str] = None,
        dry_run: bool = False,
    ) -> tuple[str, AuditReport]:
        """Redact text and produce an AuditReport."""
        start_time = time.time()
        scan_result = self.scanner.scan_text_result(text, dataset_name)

        if dry_run:
            audit = self._create_audit_report(
                scan_result, job_name or f"dry_run_{dataset_name}", start_time
            )
            return text, audit

        transform_text = text
        samples: Dict[str, List[str]] = {}
        # Sort in reverse order to keep spans valid
        for f in sorted(scan_result.findings, key=lambda f: f.span[0], reverse=True):
            if self.policy.is_allowed(dataset_name, f.type):
                f.action_taken = "allow"
                continue
            action = self._get_action_for_finding(f)
            transformed_value = self._apply_transformation(f.value, action, f.type)
            s, e = f.span
            transform_text = transform_text[:s] + transformed_value + transform_text[e:]
            f.transformed_value = transformed_value
            f.action_taken = action
            if action not in samples:
                samples[action] = []
            if len(samples[action]) < self.policy.reporting["store_samples"]:
                samples[action].append(f"{f.value} → {transformed_value}")

        audit = self._create_audit_report(
            scan_result, job_name or f"transform_{dataset_name}", start_time, samples
        )
        return transform_text, audit
