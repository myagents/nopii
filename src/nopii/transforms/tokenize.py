"""
Tokenize transformer for PII protection.
"""

from typing import Any, Dict, Optional
from .base import BaseTransformer
from ..core.models import TransformationResult


class TokenizeTransformer(BaseTransformer):
    """Replace PII with reversible tokens."""

    def __init__(
        self,
        preserve_format: bool = False,
        token_length: int = 8,
        token_prefix: str = "TOK",  # nosec B107 - This is a token prefix, not a password
    ):
        super().__init__("tokenize", "Replace PII with reversible tokens")
        self.preserve_format = preserve_format
        self.token_length = token_length
        self.token_prefix = token_prefix
        self._token_map: Dict[str, str] = {}
        self._reverse_map: Dict[str, str] = {}

    def transform(
        self, value: str, pii_type: str, options: Optional[Dict[str, Any]] = None
    ) -> TransformationResult:
        """Replace the value with a reversible token."""
        try:
            if not options:
                options = {}

            # Use instance attributes as defaults, allow options to override
            token_length = options.get("token_length", self.token_length)
            token_prefix = options.get("token_prefix", self.token_prefix)
            preserve_format = options.get("preserve_format", self.preserve_format)

            # Check if we already have a token for this value
            is_new_token = value not in self._token_map
            if value in self._token_map:
                token = self._token_map[value]
            else:
                # Generate a new token
                import secrets
                import string

                if preserve_format:
                    # Try to preserve the format of the original value
                    token = self._generate_format_preserving_token(value)
                else:
                    # Generate a simple alphanumeric token
                    random_part = "".join(
                        secrets.choice(string.ascii_uppercase + string.digits)
                        for _ in range(token_length)
                    )
                    token = f"{token_prefix}_{random_part}"

                # Store the mapping
                self._token_map[value] = token
                self._reverse_map[token] = value

            return TransformationResult(
                original_value=value,
                transformed_value=token,
                transformation_type="tokenize",
                pii_type=pii_type,
                success=True,
                metadata={
                    "token_length": len(token),
                    "token_prefix": token_prefix,
                    "preserve_format": preserve_format,
                    "is_new_token": is_new_token,
                },
            )
        except Exception as e:
            return TransformationResult(
                original_value=value,
                transformed_value=value,
                transformation_type="tokenize",
                pii_type=pii_type,
                success=False,
                error_message=str(e),
            )

    def _generate_format_preserving_token(self, value: str) -> str:
        """Generate a token that preserves the format of the original value."""
        import secrets
        import string

        token = ""  # nosec B105 - This is a token accumulator, not a password
        for char in value:
            if char.isalpha():
                token += secrets.choice(string.ascii_letters)
            elif char.isdigit():
                token += secrets.choice(string.digits)
            else:
                # Preserve non-alphanumeric characters (spaces, dashes, dots, etc.)
                token += char

        return token

    def is_reversible(self) -> bool:
        """Tokenization is reversible."""
        return True

    def get_token_map(self) -> Dict[str, str]:
        """Get the current token mapping."""
        return self._token_map.copy()

    def clear_token_map(self) -> None:
        """Clear the token mapping."""
        self._token_map.clear()
        self._reverse_map.clear()
