"""
Tests for PII transformers.
"""

from typing import Any, Dict

from nopii.transforms.mask import MaskTransformer
from nopii.transforms.hash import HashTransformer
from nopii.transforms.tokenize import TokenizeTransformer
from nopii.transforms.redact import RedactTransformer
from nopii.transforms.nullify import NullifyTransformer
from nopii.transforms.registry import TransformRegistry
from nopii.core.models import TransformationResult


class TestMaskTransformer:
    """Test mask transformer."""

    def test_mask_basic(self):
        """Test basic masking."""
        transformer = MaskTransformer()
        result = transformer.transform("test@example.com", "email")

        assert result.success is True
        assert result.transformation_type == "mask"
        assert result.original_value == "test@example.com"
        # Should preserve some structure
        assert "@" in result.transformed_value
        assert "example.com" in result.transformed_value

    def test_mask_with_custom_char(self):
        """Test masking with custom character."""
        transformer = MaskTransformer(mask_char="X")
        result = transformer.transform("john@test.com", "email")

        assert result.success is True
        assert "X" in result.transformed_value
        assert "@" in result.transformed_value

    def test_mask_phone_number(self):
        """Test masking phone numbers."""
        transformer = MaskTransformer()
        result = transformer.transform("555-123-4567", "phone")

        assert result.success is True
        # Should preserve format structure
        assert "-" in result.transformed_value
        # Last 4 digits might be preserved
        assert "4567" in result.transformed_value

    def test_mask_ssn(self):
        """Test masking SSN."""
        transformer = MaskTransformer()
        result = transformer.transform("123-45-6789", "ssn")

        assert result.success is True
        # Should preserve format
        assert "-" in result.transformed_value
        # Last 4 digits typically preserved
        assert "6789" in result.transformed_value

    def test_mask_credit_card(self):
        """Test masking credit card."""
        transformer = MaskTransformer()
        result = transformer.transform("4111-1111-1111-1111", "credit_card")

        assert result.success is True
        # Should preserve format and last 4 digits
        assert "-" in result.transformed_value
        assert "1111" in result.transformed_value

    def test_mask_preserve_format(self):
        """Test that masking preserves format."""
        transformer = MaskTransformer(preserve_format=True)

        test_cases = [
            ("555-123-4567", "phone"),
            ("test@example.com", "email"),
            ("123-45-6789", "ssn"),
        ]

        for value, pii_type in test_cases:
            result = transformer.transform(value, pii_type)
            assert result.success is True
            # Original length should be preserved
            assert len(result.transformed_value) == len(value)


class TestHashTransformer:
    """Test hash transformer."""

    def test_hash_basic(self):
        """Test basic hashing."""
        transformer = HashTransformer()
        result = transformer.transform("test@example.com", "email")

        assert result.success is True
        assert result.transformation_type == "hash"
        assert result.original_value == "test@example.com"
        # Should be a hex string
        assert all(c in "0123456789abcdef" for c in result.transformed_value)

    def test_hash_consistency(self):
        """Test that hashing is consistent."""
        transformer = HashTransformer()
        value = "john@test.com"

        result1 = transformer.transform(value, "email")
        result2 = transformer.transform(value, "email")

        assert result1.transformed_value == result2.transformed_value

    def test_hash_different_values(self):
        """Test that different values produce different hashes."""
        transformer = HashTransformer()

        result1 = transformer.transform("test1@example.com", "email")
        result2 = transformer.transform("test2@example.com", "email")

        assert result1.transformed_value != result2.transformed_value

    def test_hash_with_salt(self):
        """Test hashing with salt."""
        transformer = HashTransformer(salt="custom_salt")
        result = transformer.transform("test@example.com", "email")

        assert result.success is True
        # Should be different from unsalted hash
        unsalted_transformer = HashTransformer()
        unsalted_result = unsalted_transformer.transform("test@example.com", "email")
        assert result.transformed_value != unsalted_result.transformed_value

    def test_hash_algorithm_selection(self):
        """Test different hash algorithms."""
        algorithms = ["sha256", "sha1", "md5"]
        value = "test@example.com"

        results = {}
        for algo in algorithms:
            transformer = HashTransformer(algorithm=algo)
            result = transformer.transform(value, "email")
            assert result.success is True
            results[algo] = result.transformed_value

        # All should be different
        assert len(set(results.values())) == len(algorithms)


class TestTokenizeTransformer:
    """Test tokenize transformer."""

    def test_tokenize_basic(self):
        """Test basic tokenization."""
        transformer = TokenizeTransformer()
        result = transformer.transform("test@example.com", "email")

        assert result.success is True
        assert result.transformation_type == "tokenize"
        assert result.original_value == "test@example.com"
        # Should be a token (UUID-like or similar)
        assert len(result.transformed_value) > 10

    def test_tokenize_consistency(self):
        """Test that tokenization is consistent for same value."""
        transformer = TokenizeTransformer()
        value = "john@test.com"

        result1 = transformer.transform(value, "email")
        result2 = transformer.transform(value, "email")

        # Should be consistent if using deterministic tokenization
        assert result1.transformed_value == result2.transformed_value

    def test_tokenize_different_values(self):
        """Test that different values get different tokens."""
        transformer = TokenizeTransformer()

        result1 = transformer.transform("test1@example.com", "email")
        result2 = transformer.transform("test2@example.com", "email")

        assert result1.transformed_value != result2.transformed_value

    def test_tokenize_preserve_format(self):
        """Test tokenization with format preservation."""
        transformer = TokenizeTransformer(preserve_format=True)
        result = transformer.transform("test@example.com", "email")

        assert result.success is True
        # Should still look like an email
        assert "@" in result.transformed_value
        assert "." in result.transformed_value

    def test_tokenize_phone_format(self):
        """Test tokenization preserving phone format."""
        transformer = TokenizeTransformer(preserve_format=True)
        result = transformer.transform("555-123-4567", "phone")

        assert result.success is True
        # Should preserve phone format
        assert "-" in result.transformed_value
        assert len(result.transformed_value) == len("555-123-4567")


class TestRedactTransformer:
    """Test redact transformer."""

    def test_transform_basic(self):
        """Test basic redaction."""
        transformer = RedactTransformer()
        result = transformer.transform("test@example.com", "email")

        assert result.success is True
        assert result.transformation_type == "redact"
        assert result.original_value == "test@example.com"
        assert result.transformed_value == "[transformed]"

    def test_transform_custom_placeholder(self):
        """Test redaction with custom placeholder."""
        transformer = RedactTransformer(placeholder="[EMAIL_REMOVED]")
        result = transformer.transform("john@test.com", "email")

        assert result.success is True
        assert result.transformed_value == "[EMAIL_REMOVED]"

    def test_transform_type_specific_placeholder(self):
        """Test redaction with type-specific placeholders."""
        transformer = RedactTransformer(
            placeholder="[transformed]",
            type_specific_placeholders={
                "email": "[EMAIL_transformed]",
                "phone": "[PHONE_transformed]",
                "ssn": "[SSN_transformed]",
            },
        )

        test_cases = [
            ("test@example.com", "email", "[EMAIL_transformed]"),
            ("555-123-4567", "phone", "[PHONE_transformed]"),
            ("123-45-6789", "ssn", "[SSN_transformed]"),
            ("unknown_type", "unknown", "[transformed]"),
        ]

        for value, pii_type, expected in test_cases:
            result = transformer.transform(value, pii_type)
            assert result.success is True
            assert result.transformed_value == expected

    def test_transform_preserve_length(self):
        """Test redaction with length preservation."""
        transformer = RedactTransformer(preserve_length=True)
        result = transformer.transform("test@example.com", "email")

        assert result.success is True
        # Should preserve original length
        assert len(result.transformed_value) == len("test@example.com")
        # Should be all redaction characters
        assert all(c == transformer.redaction_char for c in result.transformed_value)


class TestNullifyTransformer:
    """Test nullify transformer."""

    def test_nullify_basic(self):
        """Test basic nullification."""
        transformer = NullifyTransformer()
        result = transformer.transform("test@example.com", "email")

        assert result.success is True
        assert result.transformation_type == "nullify"
        assert result.original_value == "test@example.com"
        assert result.transformed_value is None

    def test_nullify_different_types(self):
        """Test nullification with different PII types."""
        transformer = NullifyTransformer()

        test_values = [
            ("test@example.com", "email"),
            ("555-123-4567", "phone"),
            ("123-45-6789", "ssn"),
            ("4111-1111-1111-1111", "credit_card"),
        ]

        for value, pii_type in test_values:
            result = transformer.transform(value, pii_type)
            assert result.success is True
            assert result.transformed_value is None

    def test_nullify_with_placeholder(self):
        """Test nullification with placeholder instead of None."""
        transformer = NullifyTransformer(use_placeholder=True, placeholder="NULL")
        result = transformer.transform("test@example.com", "email")

        assert result.success is True
        assert result.transformed_value == "NULL"


class TestTransformRegistry:
    """Test transform registry."""

    def test_registry_initialization(self):
        """Test that registry initializes with default transformers."""
        registry = TransformRegistry()

        # Check that default transformers are registered
        transformers = registry.list_transformers()
        assert "mask" in transformers
        assert "hash" in transformers
        assert "tokenize" in transformers
        assert "redact" in transformers
        assert "nullify" in transformers

    def test_registry_get_transformer(self):
        """Test getting transformers from registry."""
        registry = TransformRegistry()

        mask_transformer = registry.get_transformer("mask")
        assert mask_transformer is not None
        assert isinstance(mask_transformer, MaskTransformer)

        hash_transformer = registry.get_transformer("hash")
        assert hash_transformer is not None
        assert isinstance(hash_transformer, HashTransformer)

    def test_registry_get_nonexistent_transformer(self):
        """Test getting non-existent transformer."""
        registry = TransformRegistry()

        transformer = registry.get_transformer("nonexistent")
        assert transformer is None

    def test_registry_register_custom_transformer(self):
        """Test registering custom transformer."""
        registry = TransformRegistry()

        # Create a simple custom transformer
        class CustomTransformer:
            def transform(self, value: str, pii_type: str) -> TransformationResult:
                return TransformationResult(
                    original_value=value,
                    transformed_value=f"CUSTOM_{value}",
                    transformation_type="custom",
                    success=True,
                )

            def get_info(self) -> Dict[str, Any]:
                return {
                    "name": "custom",
                    "description": "Custom transformer for testing",
                    "supported_types": ["all"],
                }

            def is_reversible(self) -> bool:
                return False

        custom_transformer = CustomTransformer()
        registry.register("custom", custom_transformer)

        assert "custom" in registry.list_transformers()
        retrieved = registry.get_transformer("custom")
        assert retrieved is custom_transformer

    def test_registry_transform(self):
        """Test transforming with registry."""
        registry = TransformRegistry()

        # Test mask transformation
        result = registry.transform("test@example.com", "email", "mask")
        assert result.success is True
        assert result.transformation_type == "mask"

        # Test hash transformation
        result = registry.transform("test@example.com", "email", "hash")
        assert result.success is True
        assert result.transformation_type == "hash"

    def test_registry_transform_nonexistent(self):
        """Test transforming with non-existent transformer."""
        registry = TransformRegistry()

        result = registry.transform("test@example.com", "email", "nonexistent")
        assert result.success is False
        assert "not found" in result.error_message.lower()

    def test_registry_get_transformer_info(self):
        """Test getting transformer information."""
        registry = TransformRegistry()

        mask_info = registry.get_transformer_info("mask")
        assert mask_info is not None
        assert "name" in mask_info
        assert "description" in mask_info
        assert "supported_types" in mask_info

        # Test non-existent transformer
        nonexistent_info = registry.get_transformer_info("nonexistent")
        assert nonexistent_info is None

    def test_registry_batch_transform(self):
        """Test batch transformation."""
        registry = TransformRegistry()

        values = ["test1@example.com", "test2@example.com", "test3@example.com"]
        pii_types = ["email", "email", "email"]

        results = registry.batch_transform(values, pii_types, "mask")
        assert len(results) == 3
        assert all(r.success for r in results)
        assert all(r.transformation_type == "mask" for r in results)

    def test_registry_supported_transformations(self):
        """Test getting supported transformations for PII type."""
        registry = TransformRegistry()

        email_transformations = registry.get_supported_transformations("email")
        assert "mask" in email_transformations
        assert "hash" in email_transformations
        assert "redact" in email_transformations

        # All transformers should support all types by default
        phone_transformations = registry.get_supported_transformations("phone")
        assert len(phone_transformations) == len(registry.list_transformers())
