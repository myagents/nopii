"""
Core scanner functionality for detecting PII in data.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pathlib import Path
import csv

try:  # optional pandas
    import pandas as pd
except Exception:  # pragma: no cover
    pd = None

from ..detectors.registry import DetectorRegistry
from .models import Finding, Policy, ScanResult


class Scanner:
    """
    Core PII scanner that detects sensitive information in various data formats.

    The scanner uses registered detectors to find PII and applies policy rules
    to determine confidence thresholds and detection strategies.
    """

    def __init__(self, policy: Policy) -> None:
        """
        Initialize scanner with a policy.

        Args:
            policy: Policy configuration for detection rules and thresholds
        """
        self.policy = policy
        self.detector_registry = DetectorRegistry()
        self._load_locale_packs()

    def _load_locale_packs(self) -> None:
        """Load detectors for enabled locale packs."""
        for locale_pack in self.policy.locale_packs:
            self.detector_registry.load_locale_pack(locale_pack)

    def scan_dataframe(
        self,
        df: Any,
        dataset_name: str = "unknown",
        confidence_threshold: Optional[float] = None,
    ) -> ScanResult:
        """
        Scan a pandas DataFrame for PII.

        Args:
            df: DataFrame to scan
            dataset_name: Name of the dataset for reporting
            confidence_threshold: Override policy confidence threshold

        Returns:
            ScanResult with detected PII and metadata
        """
        start_time = time.time()

        threshold = confidence_threshold or self.policy.thresholds["min_confidence"]
        findings: List[Finding] = []

        if pd is None:
            raise ImportError(
                "pandas is required for scan_dataframe; install pandas to use this feature"
            )

        # Scan each column
        for column in df.columns:
            column_findings = self._scan_column(df, column, threshold)
            findings.extend(column_findings)

        # Calculate coverage score
        coverage_score = self._calculate_coverage_score(findings, df, dataset_name)

        # Create scan metadata
        scan_metadata = {
            "scan_duration": time.time() - start_time,
            "confidence_threshold": threshold,
            "detectors_used": list(self.detector_registry.get_detector_names()),
            "locale_packs": self.policy.locale_packs,
        }

        return ScanResult(
            findings=findings,
            coverage_score=coverage_score,
            scan_metadata=scan_metadata,
            policy_hash=self.policy.policy_hash or "",
            timestamp=datetime.now(),
            dataset_name=dataset_name,
            total_rows=len(df),
            total_columns=len(df.columns),
        )

    def _scan_column(self, df: Any, column: str, threshold: float) -> List[Finding]:
        """Scan a single column for PII."""
        findings: List[Finding] = []

        # Check if column has a specific rule
        column_rule = self.policy.get_rule_for_column(column)
        if column_rule and column_rule.override_confidence is not None:
            threshold = column_rule.override_confidence

        # Convert column to string and scan each value
        series = df[column].astype(str)

        for row_idx, value in enumerate(series):
            if pd.isna(value) or value == "nan" or value.strip() == "":
                continue

            # Run all detectors on this value
            ctx = {"column_name": column}
            for detector in self.detector_registry.get_detectors():
                matches = detector.find(value, ctx)

                for match in matches:
                    # Handle tuple format (start_pos, end_pos, confidence)
                    if isinstance(match, tuple) and len(match) == 3:
                        start_pos, end_pos, confidence = match
                        if confidence >= threshold:
                            detected_value = value[start_pos:end_pos]
                            finding = Finding(
                                type=detector.pii_type,
                                value=detected_value,
                                span=(start_pos, end_pos),
                                column=column,
                                row_index=row_idx,
                                confidence=confidence,
                                evidence=f"Detected by {detector.name} detector",
                            )
                            findings.append(finding)
                    else:
                        # Handle object format (for future compatibility)
                        if (  # type: ignore[unreachable]
                            hasattr(match, "confidence")
                            and match.confidence >= threshold
                        ):
                            finding = Finding(
                                type=detector.pii_type,
                                value=match.value,
                                span=match.span,
                                column=column,
                                row_index=row_idx,
                                confidence=match.confidence,
                                evidence=getattr(
                                    match,
                                    "evidence",
                                    f"Detected by {detector.name} detector",
                                ),
                            )
                            findings.append(finding)

        return findings

    def _calculate_coverage_score(
        self, findings: List[Finding], df: pd.DataFrame, dataset_name: str
    ) -> float:
        """
        Calculate PII coverage score based on policy rules.

        Coverage = (Protected PII Items) / (Detected PII Items + Policy-Declared PII Fields)
        """
        if not findings:
            return 1.0  # No PII detected = perfect coverage

        # Count findings that would be protected by policy rules
        protected_count = 0

        for finding in findings:
            # Check if this finding would be protected
            if self._would_be_protected(finding, dataset_name):
                protected_count += 1

        # Add policy-declared PII fields (columns with explicit rules)
        declared_fields = 0
        for rule in self.policy.rules:
            if rule.columns:
                declared_fields += len(rule.columns)

        total_pii_items = len(findings) + declared_fields
        protected_items = protected_count + declared_fields

        return protected_items / total_pii_items if total_pii_items > 0 else 1.0

    def _would_be_protected(self, finding: Finding, dataset_name: str) -> bool:
        """Check if a finding would be protected by policy rules."""
        # Explicitly allowed by exception counts as handled by policy intent
        if self.policy.is_allowed(dataset_name, finding.type):
            return True

        # Check if there's a specific rule for this type or column
        type_rule = self.policy.get_rule_for_type(finding.type)
        column_rule = self.policy.get_rule_for_column(finding.column)

        # If there's a specific rule, it would be protected
        if type_rule or column_rule:
            return True

        # No explicit rule -> treat as not protected for coverage purposes
        return False

    def scan_text(
        self, text: str, confidence_threshold: Optional[float] = None
    ) -> List[Finding]:
        """
        Scan a text string for PII.

        Args:
            text: Text to scan
            confidence_threshold: Override policy confidence threshold

        Returns:
            List of findings
        """
        threshold = confidence_threshold or self.policy.thresholds["min_confidence"]
        findings: List[Finding] = []

        for detector in self.detector_registry.get_detectors():
            matches = detector.find(text)

            for match in matches:
                # Handle tuple format (start_pos, end_pos, confidence)
                if isinstance(match, tuple) and len(match) == 3:
                    start_pos, end_pos, confidence = match
                    if confidence >= threshold:
                        detected_value = text[start_pos:end_pos]
                        finding = Finding(
                            type=detector.pii_type,
                            value=detected_value,
                            span=(start_pos, end_pos),
                            column="text",
                            row_index=0,
                            confidence=confidence,
                            evidence=f"Detected by {detector.name} detector",
                        )
                        findings.append(finding)
                else:
                    # Handle object format (for future compatibility)
                    if hasattr(match, "confidence") and match.confidence >= threshold:  # type: ignore[unreachable]
                        finding = Finding(
                            type=detector.pii_type,
                            value=match.value,
                            span=match.span,
                            column="text",
                            row_index=0,
                            confidence=match.confidence,
                            evidence=getattr(
                                match,
                                "evidence",
                                f"Detected by {detector.name} detector",
                            ),
                        )
                        findings.append(finding)

        return findings

    def scan_text_result(
        self,
        text: str,
        dataset_name: str = "text",
        confidence_threshold: Optional[float] = None,
    ) -> ScanResult:
        """Scan text and return a ScanResult object for reporting."""
        threshold = confidence_threshold or self.policy.thresholds["min_confidence"]
        findings = self.scan_text(text, threshold)

        # Compute coverage score similarly to dataframe path
        if not findings:
            coverage_score = 1.0
        else:
            protected_count = 0
            for finding in findings:
                if self._would_be_protected(finding, dataset_name):
                    protected_count += 1
            declared_fields = 0
            for rule in self.policy.rules:
                if rule.columns:
                    declared_fields += len(rule.columns)
            total_pii_items = len(findings) + declared_fields
            protected_items = protected_count + declared_fields
            coverage_score = (
                protected_items / total_pii_items if total_pii_items > 0 else 1.0
            )

        scan_metadata = {
            "scan_duration": 0.0,
            "confidence_threshold": threshold,
            "detectors_used": list(self.detector_registry.get_detector_names()),
            "locale_packs": self.policy.locale_packs,
        }

        return ScanResult(
            findings=findings,
            coverage_score=coverage_score,
            scan_metadata=scan_metadata,
            policy_hash=self.policy.policy_hash or "",
            timestamp=datetime.now(),
            dataset_name=dataset_name,
            total_rows=1,
            total_columns=1,
        )

    def scan_file(
        self,
        file_path: Union[str, Path],
        confidence_threshold: Optional[float] = None,
    ) -> ScanResult:
        """
        Stream-scan a text or CSV file without loading it fully into memory.

        Supports:
        - .txt/.md: line-by-line
        - .csv: row-by-row via csv module

        For JSON/Parquet and other tabular formats, use SDKScanner (pandas) or
        CLI load helpers.
        """
        start_time = time.time()
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        threshold = confidence_threshold or self.policy.thresholds["min_confidence"]
        findings: List[Finding] = []
        total_rows = 0
        total_columns = 1
        dataset_name = path.stem

        suffix = path.suffix.lower()
        if suffix in [".txt", ".md"]:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line_idx, line in enumerate(f):
                    line = line.rstrip("\n")
                    # Use detectors directly for speed
                    for detector in self.detector_registry.get_detectors():
                        matches = detector.find(line)
                        for match in matches:
                            if isinstance(match, tuple) and len(match) == 3:
                                s, e, conf = match
                                if conf >= threshold:
                                    findings.append(
                                        Finding(
                                            type=detector.pii_type,
                                            value=line[s:e],
                                            span=(s, e),
                                            column="line",
                                            row_index=line_idx,
                                            confidence=conf,
                                            evidence=f"Detected by {detector.name} detector",
                                        )
                                    )
                    total_rows += 1
            total_columns = 1
        elif suffix == ".csv":
            with open(path, "r", encoding="utf-8", newline="") as f:
                reader = csv.reader(f)
                try:
                    headers = next(reader)
                except StopIteration:
                    headers = []
                total_columns = len(headers) if headers else 0
                for row_idx, row in enumerate(reader):
                    # Track rows processed
                    total_rows += 1
                    for col_idx, cell in enumerate(row):
                        column_name = (
                            headers[col_idx]
                            if col_idx < len(headers)
                            else f"col_{col_idx}"
                        )
                        value = str(cell)
                        ctx = {"column_name": column_name}
                        for detector in self.detector_registry.get_detectors():
                            matches = detector.find(value, ctx)
                            for match in matches:
                                if isinstance(match, tuple) and len(match) == 3:
                                    s, e, conf = match
                                    if conf >= threshold:
                                        findings.append(
                                            Finding(
                                                type=detector.pii_type,
                                                value=value[s:e],
                                                span=(s, e),
                                                column=column_name,
                                                row_index=row_idx,
                                                confidence=conf,
                                                evidence=f"Detected by {detector.name} detector",
                                            )
                                        )
        else:
            raise ValueError(
                f"Unsupported file format for streaming scan: {suffix}. "
                "Use SDKScanner (pandas) for JSON/Parquet."
            )

        # Coverage score without full dataframe: mirror text path logic
        if not findings:
            coverage_score = 1.0
        else:
            protected_count = 0
            for finding in findings:
                if self._would_be_protected(finding, dataset_name):
                    protected_count += 1
            declared_fields = 0
            for rule in self.policy.rules:
                if rule.columns:
                    declared_fields += len(rule.columns)
            total_pii_items = len(findings) + declared_fields
            protected_items = protected_count + declared_fields
            coverage_score = (
                protected_items / total_pii_items if total_pii_items > 0 else 1.0
            )

        scan_metadata = {
            "scan_duration": time.time() - start_time,
            "confidence_threshold": threshold,
            "detectors_used": list(self.detector_registry.get_detector_names()),
            "locale_packs": self.policy.locale_packs,
            "file_path": str(path),
            "streaming": True,
        }

        return ScanResult(
            findings=findings,
            coverage_score=coverage_score,
            scan_metadata=scan_metadata,
            policy_hash=self.policy.policy_hash or "",
            timestamp=datetime.now(),
            dataset_name=dataset_name,
            total_rows=total_rows,
            total_columns=total_columns,
        )

    def scan_dict(
        self, data: Dict[str, Any], confidence_threshold: Optional[float] = None
    ) -> List[Finding]:
        """
        Scan a dictionary for PII.

        Args:
            data: Dictionary to scan
            confidence_threshold: Override policy confidence threshold

        Returns:
            List of findings
        """
        threshold = confidence_threshold or self.policy.thresholds["min_confidence"]
        findings: List[Finding] = []

        for key, value in data.items():
            if isinstance(value, str):
                text_findings = self.scan_text(value, threshold)
                # Update column name for each finding
                for finding in text_findings:
                    finding.column = key
                    findings.append(finding)

        return findings
