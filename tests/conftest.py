"""
Pytest configuration and shared fixtures.
"""

import pytest
import pandas as pd
import tempfile
from pathlib import Path

from nopii.core.models import Policy, Finding, ScanResult
from nopii.policy.loader import create_default_policy


@pytest.fixture
def sample_policy() -> Policy:
    """Create a sample policy for testing."""
    return create_default_policy()


@pytest.fixture
def custom_policy() -> Policy:
    """Create a custom policy with specific rules."""
    policy_dict = {
        "name": "test_policy",
        "version": "1.0",
        "description": "Test policy for unit tests",
        "default_action": "mask",
        "rules": [
            {
                "name": "email_rule",
                "pii_types": ["email"],
                "action": "hash",
                "confidence_threshold": 0.8,
                "enabled": True,
            },
            {
                "name": "phone_rule",
                "pii_types": ["phone"],
                "action": "mask",
                "confidence_threshold": 0.7,
                "enabled": True,
            },
        ],
        "exceptions": [
            {
                "name": "test_exception",
                "pattern": "test@example.com",
                "reason": "Test email for development",
            }
        ],
        "reporting": {
            "include_samples": False,
            "max_findings_per_type": 100,
            "output_format": "json",
        },
    }
    return Policy.from_dict(policy_dict)


@pytest.fixture
def sample_dataframe() -> pd.DataFrame:
    """Create a sample DataFrame with PII data."""
    return pd.DataFrame(
        {
            "name": ["John Doe", "Jane Smith", "Bob Johnson"],
            "email": ["john@example.com", "jane@test.org", "bob@company.net"],
            "phone": ["555-123-4567", "(555) 987-6543", "555.555.5555"],
            "ssn": ["123-45-6789", "987-65-4321", "555-44-3333"],
            "credit_card": [
                "4111-1111-1111-1111",
                "5555-5555-5555-4444",
                "3782-822463-10005",
            ],
            "age": [25, 30, 35],
            "city": ["New York", "Los Angeles", "Chicago"],
        }
    )


@pytest.fixture
def sample_text() -> str:
    """Create sample text with PII."""
    return """
    Contact John Doe at john@example.com or call (555) 123-4567.
    His SSN is 123-45-6789 and credit card is 4111-1111-1111-1111.
    Alternative contact: jane@test.org, phone 555-987-6543.
    """


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Create sample findings for testing."""
    return [
        Finding(
            type="email",
            value="john@example.com",
            confidence=0.95,
            span=(0, 15),
            evidence="Contact john@example.com",
            column="email",
            row_index=0,
        ),
        Finding(
            type="phone",
            value="555-123-4567",
            confidence=0.90,
            span=(20, 32),
            evidence="call 555-123-4567",
            column="phone",
            row_index=0,
        ),
        Finding(
            type="ssn",
            value="123-45-6789",
            confidence=0.98,
            span=(40, 51),
            evidence="SSN is 123-45-6789",
            column="ssn",
            row_index=0,
        ),
    ]


@pytest.fixture
def temp_directory():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def temp_csv_file(sample_dataframe, temp_directory):
    """Create a temporary CSV file with sample data."""
    csv_path = temp_directory / "test_data.csv"
    sample_dataframe.to_csv(csv_path, index=False)
    return csv_path


@pytest.fixture
def temp_json_file(sample_dataframe, temp_directory):
    """Create a temporary JSON file with sample data."""
    json_path = temp_directory / "test_data.json"
    sample_dataframe.to_json(json_path, orient="records", indent=2)
    return json_path


@pytest.fixture
def temp_policy_file(custom_policy, temp_directory):
    """Create a temporary policy file."""
    policy_path = temp_directory / "test_policy.yaml"
    custom_policy.save(policy_path)
    return policy_path


@pytest.fixture
def mock_scan_result(sample_findings) -> ScanResult:
    """Create a mock scan result."""
    from datetime import datetime

    return ScanResult(
        findings=sample_findings,
        coverage_score=0.85,
        scan_metadata={
            "file_path": "test_data.csv",
            "file_size": 1024,
            "timestamp": "2024-01-01T00:00:00Z",
        },
        policy_hash="test_policy_hash",
        timestamp=datetime.now(),
        dataset_name="test_dataset",
        total_rows=3,
        total_columns=7,
    )


@pytest.fixture(autouse=True)
def cleanup_temp_files():
    """Cleanup any temporary files created during tests."""
    yield
    # Cleanup logic if needed
    pass


# Test data constants
TEST_EMAIL_PATTERNS = [
    "test@example.com",
    "user.name@domain.co.uk",
    "firstname+lastname@company.org",
    "user123@test-domain.net",
]

TEST_PHONE_PATTERNS = [
    "555-123-4567",
    "(555) 987-6543",
    "555.555.5555",
    "+1-555-123-4567",
    "1-800-555-1234",
]

TEST_SSN_PATTERNS = ["123-45-6789", "987-65-4321", "555-44-3333"]

TEST_CREDIT_CARD_PATTERNS = [
    "4111-1111-1111-1111",  # Visa
    "5555-5555-5555-4444",  # Mastercard
    "3782-822463-10005",  # American Express
    "6011-1111-1111-1117",  # Discover
]

# Test configuration
TEST_CONFIG = {
    "confidence_threshold": 0.8,
    "max_findings": 1000,
    "include_samples": True,
    "output_formats": ["json", "csv", "html"],
    "test_timeout": 30,  # seconds
}
