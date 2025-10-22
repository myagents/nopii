"""
Main client class for the nopii SDK.

This module provides the high-level NoPIIClient interface for easy PII detection
and transformation operations.
"""

from pathlib import Path
from typing import Dict, List, Optional, Union, Any

try:
    import pandas as pd
except Exception:  # pragma: no cover
    pd = None

from ..core.models import Policy, ScanResult, AuditReport
from ..core.scanner import Scanner
from ..core.transform import Transform
from ..policy.loader import load_policy, create_default_policy
from ..reporting.generators import (
    HTMLReportGenerator,
    MarkdownReportGenerator,
    JSONReportGenerator,
)
from .scanner import SDKScanner
from .transform import SDKTransform
from .policy import SDKPolicy


class NoPIIClient:
    """
    Main client class for the nopii SDK.

    Provides a high-level interface for PII detection, transformation, and reporting.
    Supports text, DataFrames, and file processing with automatic policy management.

    Examples:
        Basic usage:
        >>> client = NoPIIClient()
        >>> findings = client.scan_text("Contact john@example.com")
        >>> clean_text, audit = client.transform_text("Contact john@example.com")

        With custom policy:
        >>> client = NoPIIClient("my_policy.yaml")
        >>> df_clean, audit = client.transform_dataframe(df)
    """

    def __init__(self, policy: Optional[Union[str, Path, Policy, dict]] = None):
        """
        Initialize the NoPII client.

        Args:
            policy: Policy configuration. Can be:
                - None: Use default policy
                - str/Path: Path to YAML policy file
                - Policy: Policy object
                - dict: Policy configuration dictionary
        """
        self._policy = self._load_policy(policy)
        self._scanner = Scanner(self._policy)
        self._transform = Transform(self._policy)

        # SDK wrappers
        self.scanner = SDKScanner(self._scanner)
        self.transform = SDKTransform(self._transform)
        self.policy = SDKPolicy(self._policy)

        # Report generators
        self._html_generator = HTMLReportGenerator()
        self._markdown_generator = MarkdownReportGenerator()
        self._json_generator = JSONReportGenerator()

    def _load_policy(self, policy: Optional[Union[str, Path, Policy, dict]]) -> Policy:
        """Load policy from various sources."""
        if policy is None:
            return create_default_policy()
        elif isinstance(policy, Policy):
            return policy
        elif isinstance(policy, dict):
            from ..policy.loader import load_policy_from_dict

            return load_policy_from_dict(policy)
        elif isinstance(policy, (str, Path)):
            return load_policy(policy)
        else:
            raise ValueError(f"Invalid policy type: {type(policy)}")

    @property
    def current_policy(self) -> Policy:
        """Get the current policy."""
        return self._policy

    def update_policy(self, policy: Union[str, Path, Policy, dict]) -> None:
        """
        Update the current policy.

        Args:
            policy: New policy configuration
        """
        self._policy = self._load_policy(policy)
        self._scanner = Scanner(self._policy)
        self._transform = Transform(self._policy)

        # Update SDK wrappers
        self.scanner._scanner = self._scanner
        self.transform._transform = self._transform
        self.policy._policy = self._policy

    def scan_dataframe(
        self,
        df: Any,
        dataset_name: Optional[str] = None,
        confidence_threshold: float = 0.5,
    ) -> ScanResult:
        """
        Scan a pandas DataFrame for PII.

        Args:
            df: DataFrame to scan
            dataset_name: Optional name for the dataset
            confidence_threshold: Minimum confidence threshold for findings

        Returns:
            ScanResult with detected PII
        """
        return self.scanner.scan_dataframe(df, dataset_name, confidence_threshold)

    def scan_text(
        self, text: str, confidence_threshold: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Scan text for PII and return findings.

        Args:
            text: Text to scan for PII
            confidence_threshold: Minimum confidence score (0.0-1.0)

        Returns:
            List of PII findings with location, type, and confidence

        Example:
            >>> findings = client.scan_text("Call me at 555-123-4567")
            >>> print(f"Found {len(findings)} PII items")
        """
        return self.scanner.scan_text(text, confidence_threshold)

    def scan_file(
        self, file_path: Union[str, Path], confidence_threshold: float = 0.5
    ) -> ScanResult:
        """
        Scan a file for PII.

        Args:
            file_path: Path to file to scan
            confidence_threshold: Minimum confidence threshold for findings

        Returns:
            ScanResult with detected PII
        """
        return self.scanner.scan_file(file_path, confidence_threshold)

    def transform_dataframe(
        self,
        df: Any,
        dataset_name: Optional[str] = None,
        dry_run: bool = False,
    ) -> tuple[Any, AuditReport]:
        """
        No PII from a pandas DataFrame.

        Args:
            df: DataFrame to transform
            dataset_name: Optional name for the dataset
            dry_run: If True, don't modify data but show what would be transform

        Returns:
            Tuple of (transform_dataframe, audit_report)
        """
        return self.transform.transform_dataframe(df, dataset_name, dry_run)

    def transform_text(
        self, text: str, dry_run: bool = False
    ) -> tuple[str, List[Dict[str, Any]]]:
        """
        Transform text by applying PII transformations.

        Args:
            text: Text to transform
            dry_run: If True, return what would be transformed without changes

        Returns:
            Tuple of (transformed_text, findings_list)

        Example:
            >>> clean_text, findings = client.transform_text("Email: john@example.com")
            >>> print(clean_text)  # "Email: ****@example.com"
        """
        return self.transform.transform_text(text, dry_run)

    def transform_file(
        self,
        input_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
        dry_run: bool = False,
        backup: bool = True,
    ) -> AuditReport:
        """
        No PII from a file.

        Args:
            input_path: Path to input file
            output_path: Path to output file (defaults to input_path)
            dry_run: If True, don't modify file but show what would be transform
            backup: If True, create backup of original file

        Returns:
            AuditReport with transformation details
        """
        return self.transform.transform_file(input_path, output_path, dry_run, backup)

    def generate_report(
        self,
        audit_report: AuditReport,
        format_type: str = "html",
        output_path: Optional[Union[str, Path]] = None,
        template_name: str = "default",
        include_samples: bool = False,
        format: Optional[str] = None,
        **kwargs,
    ) -> str:
        """
        Generate an audit report.

        Args:
            audit_report: Audit report to generate from
            format_type: Output format ('html', 'markdown', 'json')
            output_path: Optional path to save report
            template_name: Template to use
            include_samples: Whether to include PII samples
            **kwargs: Additional template context

        Returns:
            Generated report content
        """
        output_path = Path(output_path) if output_path else None

        fmt = (format or format_type or "html").lower()
        if fmt == "html":
            return self._html_generator.generate(
                audit_report, output_path, template_name, include_samples, **kwargs
            )
        elif fmt == "markdown":
            return self._markdown_generator.generate(
                audit_report, output_path, template_name, include_samples, **kwargs
            )
        elif fmt == "json":
            return self._json_generator.generate(
                audit_report, output_path, include_samples, **kwargs
            )
        else:
            raise ValueError(f"Unsupported format type: {fmt}")

    def quick_scan(
        self, data: Union[pd.DataFrame, str, Path], confidence_threshold: float = 0.5
    ) -> Dict[str, Any]:
        """
        Perform a quick scan and return summary results.

        Args:
            data: Data to scan (DataFrame, text, or file path)
            confidence_threshold: Minimum confidence threshold

        Returns:
            Dictionary with scan summary
        """
        if isinstance(data, pd.DataFrame):
            result = self.scan_dataframe(
                data, confidence_threshold=confidence_threshold
            )
            return self._summary_from_scan_result(result)
        elif isinstance(data, str):
            if Path(data).exists():
                # It's a file path
                result = self.scan_file(data, confidence_threshold=confidence_threshold)
                return self._summary_from_scan_result(result)
            else:
                # It's text content
                findings = self.scan_text(
                    data, confidence_threshold=confidence_threshold
                )
                return self._summary_from_findings_dicts(findings)
        elif isinstance(data, Path):
            result = self.scan_file(data, confidence_threshold=confidence_threshold)
            return self._summary_from_scan_result(result)
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")

    def _summary_from_scan_result(self, result: ScanResult) -> Dict[str, Any]:
        """Build a summary dict from a ScanResult."""
        return {
            "total_findings": len(result.findings),
            "pii_types": list({f.type for f in result.findings}),
            "affected_columns": list({f.column for f in result.findings if f.column}),
            "coverage_score": result.coverage_score,
            "high_confidence_findings": len(
                [f for f in result.findings if f.confidence >= 0.8]
            ),
        }

    def _summary_from_findings_dicts(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Build a summary dict from a list of finding dictionaries."""
        return {
            "total_findings": len(findings),
            "pii_types": list({f.get("type") for f in findings}),
            "high_confidence_findings": len(
                [f for f in findings if f.get("confidence", 0.0) >= 0.8]
            ),
        }

    def quick_transform(
        self, data: Union[pd.DataFrame, str], dry_run: bool = False
    ) -> Union[pd.DataFrame, str]:
        """
        Perform quick transformation and return the transform data.

        Args:
            data: Data to transform (DataFrame or text)
            dry_run: If True, don't modify data but show what would be transform

        Returns:
            TRANSFORM data
        """
        if isinstance(data, pd.DataFrame):
            transform_df, _ = self.transform_dataframe(data, dry_run=dry_run)
            return transform_df
        elif isinstance(data, str):
            transform_text, _ = self.transform_text(data, dry_run=dry_run)
            return transform_text
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")

    def get_policy_info(self) -> Dict[str, Any]:
        """
        Get information about the current policy.

        Returns:
            Dictionary with policy information
        """
        return self.policy.get_info()

    def list_detectors(self) -> List[Dict[str, Any]]:
        """
        List available PII detectors.

        Returns:
            List of detector information
        """
        return self.scanner.list_detectors()

    def list_transformers(self) -> List[Dict[str, Any]]:
        """
        List available transformers.

        Returns:
            List of transformer information
        """
        return self.transform.list_transformers()

    def validate_policy(self) -> Dict[str, Any]:
        """
        Validate the current policy.

        Returns:
            Dictionary with validation results
        """
        return self.policy.validate()

    def __repr__(self) -> str:
        """String representation of the client."""
        return f"NoPIIClient(policy='{self._policy.name}')"
