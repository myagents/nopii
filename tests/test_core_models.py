"""
Tests for core models (Policy, Rule, Finding, etc.).
"""

import pytest
from datetime import datetime

from nopii.core.models import (
    Policy,
    Rule,
    Finding,
    ScanResult,
    AuditReport,
    TransformationResult,
)


class TestFinding:
    """Test Finding model."""

    def test_finding_creation(self):
        """Test basic finding creation."""
        finding = Finding(
            type="email",
            value="test@example.com",
            confidence=0.95,
            span=(0, 16),
            evidence="Contact test@example.com",
            column="email_field",
            row_index=1,
        )

        assert finding.type == "email"
        assert finding.value == "test@example.com"
        assert finding.confidence == 0.95
        assert finding.span == (0, 16)
        assert finding.evidence == "Contact test@example.com"
        assert finding.column == "email_field"
        assert finding.row_index == 1

    def test_finding_validation(self):
        """Test finding validation."""
        # Test invalid confidence
        with pytest.raises(ValueError, match="Confidence must be between 0.0 and 1.0"):
            Finding(
                type="email",
                value="test@example.com",
                confidence=1.5,
                span=(0, 16),
                evidence="Test evidence",
                column="email_field",
                row_index=1,
            )

        # Test invalid span
        with pytest.raises(ValueError, match="Invalid span: start must be <= end"):
            Finding(
                type="email",
                value="test@example.com",
                confidence=0.9,
                span=(16, 0),
                evidence="Test evidence",
                column="email_field",
                row_index=1,
            )


class TestRule:
    """Test Rule model."""

    def test_rule_creation(self):
        """Test basic rule creation."""
        rule = Rule(match="email", action="mask", override_confidence=0.8)

        assert rule.match == "email"
        assert rule.action == "mask"
        assert rule.override_confidence == 0.8
        assert rule.columns is None

    def test_rule_with_columns(self):
        """Test rule with specific columns."""
        rule = Rule(
            columns=["contact_email", "user_email"],
            action="hash",
            options={"algorithm": "sha256"},
        )

        assert rule.columns == ["contact_email", "user_email"]
        assert rule.action == "hash"
        assert rule.options["algorithm"] == "sha256"
        assert rule.match is None

    def test_rule_validation(self):
        """Test rule validation."""
        # Test rule without match or columns
        with pytest.raises(
            ValueError, match="Rule must specify either 'match' or 'columns'"
        ):
            Rule(action="mask")

        # Test invalid action
        with pytest.raises(ValueError, match="Invalid action"):
            Rule(match="email", action="invalid_action")

        # Test invalid confidence
        with pytest.raises(
            ValueError, match="override_confidence must be between 0.0 and 1.0"
        ):
            Rule(match="email", action="mask", override_confidence=1.5)


class TestPolicy:
    """Test Policy model."""

    def test_policy_creation(self):
        """Test basic policy creation."""
        policy = Policy(
            name="test_policy",
            version="1.0",
            description="Test policy for unit tests",
            default_action="mask",
        )

        assert policy.name == "test_policy"
        assert policy.version == "1.0"
        assert policy.description == "Test policy for unit tests"
        assert policy.default_action == "mask"
        assert policy.thresholds["min_confidence"] == 0.65  # Default value

    def test_policy_with_rules(self):
        """Test policy with rules."""
        rules = [Rule(match="email", action="hash"), Rule(match="phone", action="mask")]

        policy = Policy(
            name="multi_rule_policy",
            version="2.0",
            description="Policy with multiple rules",
            default_action="transform",
            rules=rules,
        )

        assert len(policy.rules) == 2
        assert policy.rules[0].match == "email"
        assert policy.rules[1].match == "phone"

    def test_policy_rule_lookup(self):
        """Test policy rule lookup methods."""
        rules = [
            Rule(match="email", action="hash"),
            Rule(columns=["phone_number"], action="mask"),
        ]

        policy = Policy(name="lookup_test_policy", rules=rules)

        # Test getting rule for type
        email_rule = policy.get_rule_for_type("email")
        assert email_rule is not None
        assert email_rule.action == "hash"

        # Test getting rule for column
        phone_rule = policy.get_rule_for_column("phone_number")
        assert phone_rule is not None
        assert phone_rule.action == "mask"

        # Test non-existent lookups
        assert policy.get_rule_for_type("ssn") is None
        assert policy.get_rule_for_column("unknown_column") is None


class TestScanResult:
    """Test ScanResult model."""

    def test_scan_result_creation(self, sample_findings):
        """Test scan result creation."""
        result = ScanResult(
            findings=sample_findings,
            coverage_score=0.85,
            scan_metadata={"source": "test.csv"},
            policy_hash="abc123",
            timestamp=datetime.now(),
            dataset_name="test_dataset",
            total_rows=100,
            total_columns=10,
        )

        assert len(result.findings) == len(sample_findings)
        assert result.total_rows == 100
        assert result.total_columns == 10
        assert result.coverage_score == 0.85
        assert result.dataset_name == "test_dataset"
        assert result.policy_hash == "abc123"

    def test_scan_result_statistics(self, sample_findings):
        """Test scan result statistics calculation."""
        result = ScanResult(
            findings=sample_findings,
            coverage_score=0.75,
            scan_metadata={"source": "test.csv"},
            policy_hash="def456",
            timestamp=datetime.now(),
            dataset_name="test_dataset",
            total_rows=3,
            total_columns=7,
        )

        stats = result.get_summary_stats()
        assert stats["total_findings"] == 3
        assert stats["unique_types"] == 3  # email, phone, ssn

        by_type = result.get_findings_by_type()
        assert "email" in by_type
        assert "phone" in by_type
        assert "ssn" in by_type
        assert len(by_type["email"]) == 1
        assert len(by_type["phone"]) == 1
        assert len(by_type["ssn"]) == 1

    def test_scan_result_validation(self, sample_findings):
        """Test scan result validation."""
        # Test invalid coverage score
        with pytest.raises(
            ValueError, match="Coverage score must be between 0.0 and 1.0"
        ):
            ScanResult(
                findings=sample_findings,
                coverage_score=1.5,  # Invalid
                scan_metadata={},
                policy_hash="test",
                timestamp=datetime.now(),
            )


class TestTransformationResult:
    """Test TransformationResult model."""

    def test_transformation_result_creation(self):
        """Test transformation result creation."""
        result = TransformationResult(
            original_value="test@example.com",
            transformed_value="****@example.com",
            transformation_type="mask",
            success=True,
            metadata={"mask_char": "*", "preserve_domain": True},
        )

        assert result.original_value == "test@example.com"
        assert result.transformed_value == "****@example.com"
        assert result.transformation_type == "mask"
        assert result.success is True
        assert result.metadata["mask_char"] == "*"
        assert result.metadata["preserve_domain"] is True

    def test_transformation_result_failure(self):
        """Test transformation result for failed transformation."""
        result = TransformationResult(
            original_value="invalid_data",
            transformed_value=None,
            transformation_type="hash",
            success=False,
            error_message="Invalid input format",
        )

        assert result.success is False
        assert result.transformed_value is None
        assert result.error_message == "Invalid input format"


class TestAuditReport:
    """Test AuditReport model."""

    def test_audit_report_creation(self, mock_scan_result):
        """Test audit report creation."""
        findings_by_type = {"email": [], "phone": []}
        summary_stats = {"total_findings": 0, "unique_types": 2}
        performance_metrics = {"scan_duration": 0.1, "transform_duration": 0.05}
        samples = {"masked": [], "hashed": []}

        report = AuditReport(
            job_name="test_job_123",
            timestamp=datetime.now(),
            policy_hash="abc123",
            coverage_score=0.85,
            residual_risk=0.1,  # Use float instead of RiskLevel
            summary_stats=summary_stats,
            findings_by_type=findings_by_type,
            performance_metrics=performance_metrics,
            samples=samples,
            scan_result=mock_scan_result,
        )

        assert report.job_name == "test_job_123"
        assert report.policy_hash == "abc123"
        assert report.coverage_score == 0.85
        assert report.residual_risk == 0.1
        assert report.summary_stats == summary_stats

    def test_audit_report_validation(self, mock_scan_result):
        """Test audit report validation."""
        findings_by_type = {"email": [], "phone": []}
        summary_stats = {"total_findings": 0, "unique_types": 2}
        performance_metrics = {"scan_duration": 0.1, "transform_duration": 0.05}
        samples = {"masked": [], "hashed": []}

        # Test invalid coverage score
        with pytest.raises(
            ValueError, match="Coverage score must be between 0.0 and 1.0"
        ):
            AuditReport(
                job_name="audit_test",
                timestamp=datetime.now(),
                policy_hash="policy123",
                coverage_score=1.5,  # Invalid
                residual_risk=0.3,
                summary_stats=summary_stats,
                findings_by_type=findings_by_type,
                performance_metrics=performance_metrics,
                samples=samples,
                scan_result=mock_scan_result,
            )

        # Test invalid residual risk
        with pytest.raises(
            ValueError, match="Residual risk must be between 0.0 and 1.0"
        ):
            AuditReport(
                job_name="audit_test",
                timestamp=datetime.now(),
                policy_hash="policy123",
                coverage_score=0.92,
                residual_risk=1.5,  # Invalid
                summary_stats=summary_stats,
                findings_by_type=findings_by_type,
                performance_metrics=performance_metrics,
                samples=samples,
                scan_result=mock_scan_result,
            )
