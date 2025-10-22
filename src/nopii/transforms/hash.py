"""Hash transformer for PII protection."""

import hashlib
from typing import Any, Dict
from .base import BaseTransformer
from ..core.models import TransformationResult


class HashTransformer(BaseTransformer):
    """Hash PII values for anonymization."""

    def __init__(self, salt: str = "", algorithm: str = "sha256"):
        super().__init__("hash", "Hash PII values")
        self.salt = salt
        self.algorithm = algorithm

    def transform(
        self, value: str, pii_type: str, options: Dict[str, Any] = None
    ) -> TransformationResult:
        """Hash the value using a cryptographic hash function."""
        try:
            if not options:
                options = {}

            # Use instance attributes as defaults, allow options to override
            algorithm = options.get("algorithm", self.algorithm)
            salt = options.get("salt", self.salt)
            include_prefix = options.get("include_prefix", False)

            # Combine value with salt
            salted_value = salt + value

            # Create hash
            if algorithm == "md5":
                hash_obj = hashlib.md5(salted_value.encode(), usedforsecurity=False)
            elif algorithm == "sha1":
                hash_obj = hashlib.sha1(salted_value.encode(), usedforsecurity=False)
            elif algorithm == "sha256":
                hash_obj = hashlib.sha256(salted_value.encode())
            else:
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")

            hash_value = hash_obj.hexdigest()

            if include_prefix:
                transformed_value = f"hash_{algorithm}_{hash_value[:8]}"
            else:
                transformed_value = hash_value

            return TransformationResult(
                original_value=value,
                transformed_value=transformed_value,
                transformation_type="hash",
                pii_type=pii_type,
                success=True,
                metadata={
                    "algorithm": algorithm,
                    "salt_used": bool(salt),
                    "include_prefix": include_prefix,
                    "hash_length": len(hash_value),
                },
            )
        except Exception as e:
            return TransformationResult(
                original_value=value,
                transformed_value=value,
                transformation_type="hash",
                pii_type=pii_type,
                success=False,
                error_message=str(e),
            )

    def is_reversible(self) -> bool:
        """Hashing is not reversible."""
        return False
