"""
Registry for managing PII transformers.
"""

from typing import Any, Dict, List, Optional, Union, Protocol, runtime_checkable


@runtime_checkable
class _TransformLike(Protocol):
    def transform(
        self, value: str, pii_type: str, options: Optional[Dict[str, Any]] = None
    ) -> Any: ...
    def get_info(self) -> Dict[str, Any]: ...
    def is_reversible(self) -> bool: ...


class TransformRegistry:
    """
    Registry for managing and accessing PII transformers.

    The registry allows registration of custom transformers and provides
    methods to retrieve transformers by name.
    """

    def __init__(self):
        """Initialize the transformer registry."""
        # Store any object that provides a .transform(...) method
        self._transformers: Dict[str, _TransformLike] = {}
        self._load_default_transformers()

    def register(
        self,
        name_or_transformer: Union[str, _TransformLike],
        transformer: Optional[_TransformLike] = None,
    ) -> None:
        """
        Register a transformer.

        Args:
            name_or_transformer: Either transformer instance or name string
            transformer: Transformer instance (when first arg is name)
        """
        if transformer is None:
            # Called with just transformer instance
            if not isinstance(name_or_transformer, _TransformLike):
                raise ValueError("Expected object with transform method")
            transformer_instance = name_or_transformer
            name = transformer_instance.__class__.__name__.lower().replace(
                "transformer", ""
            )
            self._transformers[name] = transformer_instance
        else:
            # Called with name and transformer
            if not isinstance(name_or_transformer, str):
                raise ValueError("Expected string name when transformer is provided")
            if not isinstance(transformer, _TransformLike):
                raise ValueError("Expected object with transform method")
            self._transformers[name_or_transformer] = transformer

    def unregister(self, name: str) -> bool:
        """
        Unregister a transformer by name.

        Args:
            name: Name of transformer to remove

        Returns:
            True if transformer was found and removed
        """
        if name in self._transformers:
            del self._transformers[name]
            return True
        return False

    def get_transformer(self, name: str) -> Optional[_TransformLike]:
        """
        Get a transformer by name.

        Args:
            name: Name of the transformer

        Returns:
            Transformer instance or None if not found
        """
        return self._transformers.get(name)

    def list_transformers(self) -> List[str]:
        """
        List all registered transformer names.

        Returns:
            List of transformer names
        """
        return list(self._transformers.keys())

    def get_all_transformers(self) -> List[_TransformLike]:
        """
        Get all registered transformers.

        Returns:
            List of all transformer instances
        """
        return list(self._transformers.values())

    def get_transformer_info(
        self, name: Optional[str] = None
    ) -> Union[Dict[str, Any], List[Dict[str, Any]], None]:
        """
        Get information about all registered transformers or a specific transformer.

        Args:
            name: Optional name of specific transformer to get info for

        Returns:
            Transformer info dict if name provided, list of dicts otherwise, or None if not found
        """
        if name:
            transformer = self.get_transformer(name)
            if transformer:
                info = transformer.get_info()
                # Add supported_types field if not present
                if "supported_types" not in info:
                    info["supported_types"] = [
                        "email",
                        "phone",
                        "ssn",
                        "credit_card",
                        "name",
                        "address",
                    ]
                return info
            return None
        return [transformer.get_info() for transformer in self._transformers.values()]

    def transform(
        self,
        value: str,
        pii_type: str,
        transformation_type: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Transform a value using the specified transformation type.

        Args:
            value: The value to transform
            pii_type: The type of PII (e.g., 'email', 'phone')
            transformation_type: The type of transformation to apply
            options: Optional transformation options

        Returns:
            TransformationResult object
        """
        transformer = self.get_transformer(transformation_type)
        if not transformer:
            from ..core.models import TransformationResult

            return TransformationResult(
                original_value=value,
                transformed_value=value,
                transformation_type=transformation_type,
                pii_type=pii_type,
                success=False,
                error_message=f"Transformer '{transformation_type}' not found",
            )

        return transformer.transform(value, pii_type, options)

    def batch_transform(
        self,
        values: List[str],
        pii_types: List[str],
        transformation_type: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> List[Any]:
        """
        Transform multiple values using the specified transformation type.

        Args:
            values: List of values to transform
            pii_types: List of PII types corresponding to each value
            transformation_type: The type of transformation to apply
            options: Optional transformation options

        Returns:
            List of TransformationResult objects
        """
        if len(values) != len(pii_types):
            raise ValueError("Values and PII types lists must have the same length")

        results = []
        for value, pii_type in zip(values, pii_types):
            result = self.transform(value, pii_type, transformation_type, options)
            results.append(result)

        return results

    def get_supported_transformations(
        self, pii_type: Optional[str] = None
    ) -> List[str]:
        """
        Get list of supported transformation types.

        Args:
            pii_type: Optional PII type to filter transformations for

        Returns:
            List of transformation type names
        """
        # For now, return all registered transformers
        # In the future, this could be filtered by PII type
        return list(self._transformers.keys())

    def _load_default_transformers(self) -> None:
        """Load the default set of transformers."""
        # Import and register default transformers
        from .hash import HashTransformer
        from .mask import MaskTransformer
        from .nullify import NullifyTransformer
        from .redact import RedactTransformer
        from .tokenize import TokenizeTransformer

        # Register all default transformers
        default_transformers = [
            RedactTransformer(),
            MaskTransformer(),
            HashTransformer(),
            TokenizeTransformer(),
            NullifyTransformer(),
        ]

        for transformer in default_transformers:
            self.register(transformer)
