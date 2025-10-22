"""
Core data models for nopii.

This module defines the fundamental data structures used throughout the package,
including policies, findings, scan results, and audit reports.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class RiskLevel(Enum):
    """Risk level enumeration for residual risk assessment."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Rule:
    """
    A policy rule that defines how to handle specific PII types or columns.

    Attributes:
        match: PII type to match (e.g., 'email', 'phone')
        columns: Specific column names to apply this rule to
        action: Transformation action ('mask', 'hash', 'tokenize', 'redact', 'nullify')
        options: Action-specific configuration options
        override_confidence: Override the detector's confidence score
    """

    action: str = "mask"
    match: Optional[str] = None
    columns: Optional[List[str]] = None
    options: Dict[str, Any] = field(default_factory=dict)
    override_confidence: Optional[float] = None

    def __post_init__(self) -> None:
        """Validate rule configuration."""
        if not self.match and not self.columns:
            raise ValueError("Rule must specify either 'match' or 'columns'")

        valid_actions = {"mask", "hash", "tokenize", "redact", "nullify"}
        if self.action not in valid_actions:
            raise ValueError(
                f"Invalid action '{self.action}'. Must be one of {valid_actions}"
            )

        if self.override_confidence is not None:
            if not 0.0 <= self.override_confidence <= 1.0:
                raise ValueError("override_confidence must be between 0.0 and 1.0")


@dataclass
class PolicyException:
    """
    A policy exception that allows certain PII types in specific contexts.

    Attributes:
        dataset: Dataset/table name where exception applies
        allow_types: List of PII types to allow
        conditions: Additional conditions for the exception
    """

    dataset: str
    allow_types: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    """
    Main policy configuration for PII detection and transformation.

    Attributes:
        name: Policy name for identification
        version: Policy schema version
        locale_packs: List of locale packs to enable
        default_action: Default transformation action
        thresholds: Detection and coverage thresholds
        reporting: Reporting configuration
        secrets: Secret management configuration
        rules: List of transformation rules
        exceptions: List of policy exceptions
        policy_hash: SHA-256 hash of policy content for audit trails
    """

    name: str = "default_policy"
    version: str = "1"
    description: Optional[str] = None
    locale_packs: List[str] = field(default_factory=lambda: ["generic"])
    default_action: str = "mask"
    thresholds: Dict[str, Any] = field(default_factory=dict)
    reporting: Dict[str, Any] = field(default_factory=dict)
    secrets: Dict[str, str] = field(default_factory=dict)
    rules: List[Rule] = field(default_factory=list)
    exceptions: List[PolicyException] = field(default_factory=list)
    policy_hash: Optional[str] = None

    def __post_init__(self) -> None:
        """Set default values and compute policy hash."""
        # Set default thresholds
        default_thresholds = {
            "min_confidence": 0.65,
            "fail_on_untransform": False,
            "coverage_target": 0.85,
        }
        for k1, v1 in default_thresholds.items():
            self.thresholds.setdefault(k1, v1)

        # Set default reporting config
        default_reporting = {
            "formats": ["json"],
            "output_dir": "reports",
            "store_samples": 3,
            "include_trends": False,
        }
        for k2, v2 in default_reporting.items():
            self.reporting.setdefault(k2, v2)

        # Set default secrets config
        default_secrets = {
            "tokenization_key_env": "REDACT_PII_KEY",
            "namespace_env": "REDACT_PII_NS",
        }
        for k3, v3 in default_secrets.items():
            self.secrets.setdefault(k3, v3)

        # Compute policy hash if not provided
        if self.policy_hash is None:
            self.policy_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute SHA-256 hash of policy content for audit trails."""
        # Create a deterministic string representation
        content = f"{self.version}|{sorted(self.locale_packs)}|{self.default_action}"
        content += f"|{sorted(self.thresholds.items())}"
        content += f"|{len(self.rules)}|{len(self.exceptions)}"

        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def get_rule_for_column(self, column: str) -> Optional[Rule]:
        """Get the most specific rule for a column."""
        # First check for column-specific rules
        for rule in self.rules:
            if rule.columns and column in rule.columns:
                return rule
        return None

    def get_rule_for_type(self, pii_type: str) -> Optional[Rule]:
        """Get the rule for a specific PII type."""
        for rule in self.rules:
            if rule.match == pii_type:
                return rule
        return None

    def is_allowed(self, dataset: str, pii_type: str) -> bool:
        """Check if a PII type is allowed in a specific dataset."""
        for exception in self.exceptions:
            if exception.dataset == dataset and pii_type in exception.allow_types:
                return True
        return False

    def model_dump(self, exclude: Optional[set] = None) -> Dict[str, Any]:
        """Convert policy to dictionary for serialization."""
        exclude = exclude or set()

        result = {}
        for field_name in [
            "name",
            "version",
            "description",
            "locale_packs",
            "default_action",
            "thresholds",
            "reporting",
            "secrets",
            "rules",
            "exceptions",
            "policy_hash",
        ]:
            if field_name not in exclude:
                value = getattr(self, field_name)
                if field_name == "rules":
                    result[field_name] = [self._rule_to_dict(rule) for rule in value]
                elif field_name == "exceptions":
                    result[field_name] = [self._exception_to_dict(exc) for exc in value]
                else:
                    result[field_name] = value

        return result

    def _rule_to_dict(self, rule: Rule) -> Dict[str, Any]:
        """Convert Rule to dictionary."""
        out: Dict[str, Any] = {
            "action": rule.action,
            "options": rule.options,
            "override_confidence": rule.override_confidence,
        }

        # Only include non-None values for match and columns
        if rule.match is not None:
            out["match"] = rule.match
        if rule.columns is not None:
            out["columns"] = list(rule.columns)

        return out

    def _exception_to_dict(self, exception: PolicyException) -> Dict[str, Any]:
        """Convert Exception to dictionary."""
        return {
            "dataset": exception.dataset,
            "allow_types": exception.allow_types,
            "conditions": exception.conditions,
        }


@dataclass
class Finding:
    """
    A detected PII instance with metadata.

    Attributes:
        type: Type of PII detected (e.g., 'email', 'phone')
        value: The detected PII value
        span: Start and end positions in text (for string data)
        column: Column name where PII was found
        row_index: Row index where PII was found
        confidence: Confidence score (0.0 to 1.0)
        evidence: Explanation of why this was detected as PII
        transformed_value: Value after transformation (if applicable)
        action_taken: Transformation action applied
    """

    type: str
    value: str
    span: Tuple[int, int]
    column: str
    row_index: int
    confidence: float
    evidence: str
    transformed_value: Optional[str] = None
    action_taken: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate finding data."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")

        if self.span[0] > self.span[1]:
            raise ValueError("Invalid span: start must be <= end")


@dataclass
class ScanResult:
    """
    Results from scanning data for PII.

    Attributes:
        findings: List of detected PII instances
        coverage_score: Percentage of PII properly handled (0.0 to 1.0)
        scan_metadata: Additional metadata about the scan
        policy_hash: Hash of the policy used for scanning
        timestamp: When the scan was performed
        dataset_name: Name of the scanned dataset
        total_rows: Total number of rows scanned
        total_columns: Total number of columns scanned
    """

    findings: List[Finding]
    coverage_score: float
    scan_metadata: Dict[str, Any]
    policy_hash: str
    timestamp: datetime
    dataset_name: str = "unknown"
    total_rows: int = 0
    total_columns: int = 0

    def __post_init__(self) -> None:
        """Validate scan result data."""
        if not 0.0 <= self.coverage_score <= 1.0:
            raise ValueError("Coverage score must be between 0.0 and 1.0")

    def get_findings_by_type(self) -> Dict[str, List[Finding]]:
        """Group findings by PII type."""
        by_type: Dict[str, List[Finding]] = {}
        for finding in self.findings:
            by_type.setdefault(finding.type, []).append(finding)
        return by_type

    def get_findings_by_column(self) -> Dict[str, List[Finding]]:
        """Group findings by column."""
        by_column: Dict[str, List[Finding]] = {}
        for finding in self.findings:
            by_column.setdefault(finding.column, []).append(finding)
        return by_column

    def get_summary_stats(self) -> Dict[str, int]:
        """Get summary statistics about the findings."""
        by_type = self.get_findings_by_type()
        return {
            "total_findings": len(self.findings),
            "unique_types": len(by_type),
            "affected_columns": len(self.get_findings_by_column()),
            "high_confidence": len([f for f in self.findings if f.confidence >= 0.8]),
            "medium_confidence": len(
                [f for f in self.findings if 0.5 <= f.confidence < 0.8]
            ),
            "low_confidence": len([f for f in self.findings if f.confidence < 0.5]),
        }


@dataclass
class AuditReport:
    """
    Comprehensive audit report for compliance and governance.

    Attributes:
        job_name: Name of the job/process that generated this report
        timestamp: When the report was generated
        policy_hash: Hash of the policy used
        coverage_score: Overall PII coverage score
        residual_risk: Calculated residual risk score
        summary_stats: Summary statistics
        findings_by_type: Findings grouped by PII type
        performance_metrics: Performance and timing metrics
        samples: Sample transformed values for review
        scan_result: The underlying scan result
    """

    job_name: str
    timestamp: datetime
    policy_hash: str
    coverage_score: float
    residual_risk: float
    summary_stats: Dict[str, int]
    findings_by_type: Dict[str, List[Finding]]
    performance_metrics: Dict[str, float]
    samples: Dict[str, List[str]]
    scan_result: ScanResult
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate audit report data."""
        if not 0.0 <= self.coverage_score <= 1.0:
            raise ValueError("Coverage score must be between 0.0 and 1.0")

        if not 0.0 <= self.residual_risk <= 1.0:
            raise ValueError("Residual risk must be between 0.0 and 1.0")

    def get_coverage_by_type(self) -> Dict[str, float]:
        """Calculate coverage score by PII type."""
        coverage_by_type = {}
        for pii_type, findings in self.findings_by_type.items():
            protected = len([f for f in findings if f.action_taken])
            total = len(findings)
            coverage_by_type[pii_type] = protected / total if total > 0 else 1.0
        return coverage_by_type

    def get_risk_factors(self) -> Dict[str, float]:
        """Calculate risk factors contributing to residual risk."""
        total_findings = len(self.scan_result.findings)
        if total_findings == 0:
            return {"no_pii_detected": 0.0}

        unprotected = len([f for f in self.scan_result.findings if not f.action_taken])
        low_confidence = len(
            [f for f in self.scan_result.findings if f.confidence < 0.5]
        )

        return {
            "unprotected_ratio": unprotected / total_findings,
            "low_confidence_ratio": low_confidence / total_findings,
            "coverage_gap": 1.0 - self.coverage_score,
        }

    def passes_threshold(self, threshold: float) -> bool:
        """Check if coverage score meets the specified threshold."""
        return self.coverage_score >= threshold

    def model_dump(self) -> Dict[str, Any]:
        """Return a serializable dictionary representation of the report."""
        return asdict(self)

    @property
    def findings(self) -> List[Finding]:
        """Compatibility property to access findings directly from the report."""
        return self.scan_result.findings


@dataclass
class TransformationResult:
    """
    Result of a PII transformation operation.

    Attributes:
        original_value: The original PII value
        transformed_value: The transformed value (or None if failed)
        transformation_type: Type of transformation applied
        pii_type: Type of PII detected
        success: Whether the transformation was successful
        error_message: Error message if transformation failed
        metadata: Additional metadata about the transformation
        transform_data: For batch operations, the transform dataset
        audit_report: Associated audit report for the transformation
    """

    original_value: Optional[str]
    transformed_value: Optional[str]
    transformation_type: str
    success: bool
    pii_type: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    transform_data: Optional[Any] = None
    audit_report: Optional[AuditReport] = None

    def __post_init__(self) -> None:
        """Validate transformation result."""
        if not self.success and not self.error_message:
            self.error_message = "Transformation failed"
