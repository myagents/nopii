"""
Policy loading functionality for YAML configuration files.
"""

from pathlib import Path
from typing import Any, Dict, Union

import yaml

from ..core.models import Policy, Rule, PolicyException
from .validator import PolicyValidator


def load_policy(source: Union[str, Path, Dict[str, Any]]) -> Policy:
    """
    Load a policy from various sources.

    Args:
        source: Can be a file path, YAML string, or dictionary

    Returns:
        Policy instance

    Raises:
        ValueError: If policy is invalid
        FileNotFoundError: If file doesn't exist
    """
    if isinstance(source, dict):
        return load_policy_from_dict(source)
    elif isinstance(source, Path):
        if source.exists():
            return load_policy_from_file(source)
        raise FileNotFoundError(f"Policy file not found: {source}")
    elif isinstance(source, str):
        path = Path(source)
        if path.exists():
            return load_policy_from_file(path)
        # Try to parse as YAML string
        try:
            data = yaml.safe_load(source)
            return load_policy_from_dict(data)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML string: {e}")
    else:
        raise ValueError(f"Unsupported source type: {type(source)}")


def load_policy_from_file(file_path: Union[str, Path]) -> Policy:
    """
    Load a policy from a YAML file.

    Args:
        file_path: Path to the YAML policy file

    Returns:
        Policy instance

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If policy is invalid
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in policy file {path}: {e}")

    if not isinstance(data, dict):
        raise ValueError(f"Policy file must contain a YAML object, got {type(data)}")

    # Add file path to metadata
    data.setdefault("metadata", {})["source_file"] = str(path.absolute())

    return load_policy_from_dict(data)


def load_policy_from_dict(data: Dict[str, Any]) -> Policy:
    """
    Load a policy from a dictionary.

    Args:
        data: Policy configuration dictionary

    Returns:
        Policy instance

    Raises:
        ValueError: If policy is invalid
    """
    # Validate the raw dictionary before constructing models
    validator = PolicyValidator()
    result = validator.validate(data)
    if not result.is_valid:
        errors = "; ".join(result.errors)
        raise ValueError(f"Policy validation failed: {errors}")

    try:
        # Convert rules and exceptions to proper objects
        rules = []
        for rule_data in data.get("rules", []):
            rules.append(Rule(**rule_data))

        exceptions = []
        for exc_data in data.get("exceptions", []):
            exceptions.append(PolicyException(**exc_data))

        # Create Policy instance
        policy_data = data.copy()
        policy_data["rules"] = rules
        policy_data["exceptions"] = exceptions

        # Remove metadata as it's not part of the Policy model
        policy_data.pop("metadata", None)

        policy = Policy(**policy_data)

        return policy

    except (TypeError, ValueError, KeyError) as e:
        raise ValueError(f"Policy creation error: {e}")


def create_default_policy() -> Policy:
    """
    Create a default policy configuration.

    Returns:
        Default Policy instance
    """
    default_config = {
        "name": "default_policy",
        "version": "1",
        "locale_packs": ["generic"],
        "default_action": "mask",
        "thresholds": {
            "min_confidence": 0.65,
            "fail_on_untransform": False,
            "coverage_target": 0.85,
        },
        "reporting": {
            "formats": ["json"],
            "output_dir": "reports",
            "store_samples": 3,
            "include_trends": False,
        },
        "secrets": {
            "tokenization_key_env": "REDACT_PII_KEY",
            "namespace_env": "REDACT_PII_NS",
        },
        "rules": [
            {
                "action": "mask",
                "match": "email",
                "options": {"preserve_format": True, "mask_char": "*"},
            },
            {
                "action": "mask",
                "match": "phone",
                "options": {
                    "preserve_format": True,
                    "preserve_last": 4,
                    "mask_char": "*",
                },
            },
            {
                "action": "hash",
                "match": "ssn",
                "options": {"algorithm": "sha256", "include_prefix": True},
            },
        ],
        "exceptions": [],
    }

    return load_policy_from_dict(default_config)


def save_policy(policy: Policy, file_path: Union[str, Path]) -> None:
    """
    Save a policy to a YAML file.

    Args:
        policy: Policy instance to save
        file_path: Path where to save the policy
    """
    path = Path(file_path)

    # Convert policy to dictionary
    policy_dict = policy.model_dump(exclude={"policy_hash"})

    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write YAML file
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(
            policy_dict,
            f,
            default_flow_style=False,
            sort_keys=False,
            indent=2,
            allow_unicode=True,
        )


def validate_policy_file(file_path: Union[str, Path]) -> bool:
    """
    Validate a policy file without loading it.

    Args:
        file_path: Path to the policy file

    Returns:
        True if policy is valid
    """
    try:
        load_policy_from_file(file_path)
        return True
    except (FileNotFoundError, ValueError):
        return False


class PolicyLoader:
    """
    Policy loader class for loading policies from various sources.

    This class provides a convenient interface for loading policies
    from files, dictionaries, and other sources.
    """

    def __init__(self):
        """Initialize the policy loader."""
        self.validator = PolicyValidator()

    def load_from_file(self, file_path: Union[str, Path]) -> Policy:
        """
        Load a policy from a YAML file.

        Args:
            file_path: Path to the policy file

        Returns:
            Policy instance
        """
        return load_policy_from_file(file_path)

    def load_from_dict(self, data: Dict[str, Any]) -> Policy:
        """
        Load a policy from a dictionary.

        Args:
            data: Policy data as dictionary

        Returns:
            Policy instance
        """
        return load_policy_from_dict(data)

    def save_to_file(self, policy: Policy, file_path: Union[str, Path]) -> None:
        """
        Save a policy to a YAML file.

        Args:
            policy: Policy instance to save
            file_path: Path where to save the policy
        """
        save_policy(policy, file_path)

    def validate_file(self, file_path: Union[str, Path]) -> bool:
        """
        Validate a policy file.

        Args:
            file_path: Path to the policy file

        Returns:
            True if policy is valid
        """
        return validate_policy_file(file_path)
