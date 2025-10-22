"""
Policy validation functionality.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Set


@dataclass
class ValidationResult:
    """Result of policy validation."""

    is_valid: bool
    errors: List[str]
    warnings: List[str]


class PolicyValidator:
    """
    Validator for policy configuration files.

    Validates policy structure, rules, and configuration options.
    """

    def __init__(self):
        """Initialize the validator."""
        self.valid_actions = {
            "redact",
            "mask",
            "hash",
            "tokenize",
            "nullify",
        }
        self.valid_pii_types = {
            "email",
            "phone",
            "credit_card",
            "ssn",
            "ip_address",
            "url",
            "person_name",
            "address",
            "date_of_birth",
            "drivers_license",
        }

    def validate(self, policy_data: Dict[str, Any]) -> ValidationResult:
        """
        Validate a policy configuration.

        Args:
            policy_data: Policy configuration dictionary

        Returns:
            ValidationResult with validation status and any errors/warnings
        """
        errors = []
        warnings = []

        # Validate required fields
        required_fields = ["name", "version"]
        for field in required_fields:
            if field not in policy_data:
                errors.append(f"Missing required field: {field}")

        # Validate policy name
        if "name" in policy_data:
            if (
                not isinstance(policy_data["name"], str)
                or not policy_data["name"].strip()
            ):
                errors.append("Policy name must be a non-empty string")

        # Validate version
        if "version" in policy_data:
            if not isinstance(policy_data["version"], str):
                errors.append("Policy version must be a string")

        # Validate default action
        if "default_action" in policy_data:
            if policy_data["default_action"] not in self.valid_actions:
                errors.append(
                    f"Invalid default_action '{policy_data['default_action']}'. "
                    f"Must be one of: {', '.join(sorted(self.valid_actions))}"
                )

        # Validate rules
        if "rules" in policy_data:
            rule_errors = self._validate_rules(policy_data["rules"])
            errors.extend(rule_errors)

        # Validate exceptions
        if "exceptions" in policy_data:
            exception_errors = self._validate_exceptions(policy_data["exceptions"])
            errors.extend(exception_errors)

        # Validate reporting configuration
        if "reporting" in policy_data:
            reporting_errors = self._validate_reporting(policy_data["reporting"])
            errors.extend(reporting_errors)

        # Check for conflicting rules (rules with same match/columns)
        if "rules" in policy_data and isinstance(policy_data["rules"], list):
            self._check_rule_conflicts(policy_data["rules"], errors)

        # Generate warnings
        if "description" not in policy_data:
            warnings.append("Policy description is recommended for documentation")

        if "rules" not in policy_data or not policy_data["rules"]:
            warnings.append(
                "Policy has no rules defined - will use default action for all PII"
            )

        return ValidationResult(
            is_valid=len(errors) == 0, errors=errors, warnings=warnings
        )

    def _validate_rules(self, rules: Any) -> List[str]:
        """Validate policy rules."""
        errors = []

        if not isinstance(rules, list):
            errors.append("Rules must be a list")
            return errors

        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                errors.append(f"Rule {i} must be a dictionary")
                continue

            # Validate rule match or columns (our current model uses 'match' and 'columns')
            if "match" not in rule and "columns" not in rule:
                errors.append(f"Rule {i} must specify either 'match' or 'columns'")

            if "match" in rule:
                if rule["match"] not in self.valid_pii_types:
                    errors.append(
                        f"Rule {i} has invalid match type '{rule['match']}'. "
                        f"Must be one of: {', '.join(sorted(self.valid_pii_types))}"
                    )

            if "columns" in rule and rule["columns"] is not None:
                if not isinstance(rule["columns"], list):
                    errors.append(f"Rule {i} columns must be a list")
                elif not all(
                    isinstance(col, str) and col.strip() for col in rule["columns"]
                ):
                    errors.append(f"Rule {i} columns must be non-empty strings")

            # Validate action
            if "action" not in rule:
                errors.append(f"Rule {i} missing required field: action")
            elif rule["action"] not in self.valid_actions:
                errors.append(
                    f"Rule {i} has invalid action '{rule['action']}'. "
                    f"Must be one of: {', '.join(sorted(self.valid_actions))}"
                )

            # Validate options if present
            if "options" in rule:
                if not isinstance(rule["options"], dict):
                    errors.append(f"Rule {i} options must be a dictionary")
                else:
                    # If action is valid, validate options for that action
                    action = rule.get("action")
                    if action in self.valid_actions and isinstance(action, str):
                        opt_errors = self.validate_transformation_options(
                            action, rule["options"]
                        )
                        for e in opt_errors:
                            errors.append(f"Rule {i} options error: {e}")

            # Validate override_confidence if present
            if (
                "override_confidence" in rule
                and rule["override_confidence"] is not None
            ):
                conf = rule["override_confidence"]
                if not isinstance(conf, (int, float)) or not 0.0 <= conf <= 1.0:
                    errors.append(
                        f"Rule {i} override_confidence must be a number between 0.0 and 1.0"
                    )

        return errors

    def _validate_exceptions(self, exceptions: Any) -> List[str]:
        """Validate policy exceptions."""
        errors = []

        if not isinstance(exceptions, list):
            errors.append("Exceptions must be a list")
            return errors

        for i, exception in enumerate(exceptions):
            if not isinstance(exception, dict):
                errors.append(f"Exception {i} must be a dictionary")
                continue

            # Validate required exception fields (our model uses 'dataset' and 'allow_types')
            if "dataset" not in exception:
                errors.append(f"Exception {i} missing required field: dataset")

            if "allow_types" in exception:
                if not isinstance(exception["allow_types"], list):
                    errors.append(f"Exception {i} allow_types must be a list")
                else:
                    for pii_type in exception["allow_types"]:
                        if pii_type not in self.valid_pii_types:
                            errors.append(
                                f"Exception {i} has invalid allow_type '{pii_type}'. "
                                f"Must be one of: {', '.join(sorted(self.valid_pii_types))}"
                            )

            # Validate conditions if present
            if "conditions" in exception:
                if not isinstance(exception["conditions"], dict):
                    errors.append(f"Exception {i} conditions must be a dictionary")

        return errors

    def _validate_reporting(self, reporting: Any) -> List[str]:
        """Validate reporting configuration."""
        errors = []

        if not isinstance(reporting, dict):
            errors.append("Reporting configuration must be a dictionary")
            return errors

        # Validate store_samples
        if "store_samples" in reporting:
            if (
                not isinstance(reporting["store_samples"], int)
                or reporting["store_samples"] < 0
            ):
                errors.append("store_samples must be a non-negative integer")

        # Validate boolean flags
        boolean_fields = ["include_confidence", "include_context"]
        for field in boolean_fields:
            if field in reporting and not isinstance(reporting[field], bool):
                errors.append(f"{field} must be a boolean value")

        return errors

    def _check_rule_conflicts(self, rules: List[Any], errors: List[str]) -> None:
        """Check for conflicting rules."""
        seen_matches = set()
        seen_columns = set()

        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue

            # Check for duplicate match types
            if "match" in rule:
                if rule["match"] in seen_matches:
                    errors.append(f"Duplicate rule for PII type '{rule['match']}'")
                else:
                    seen_matches.add(rule["match"])

            # Check for duplicate column rules
            if "columns" in rule and isinstance(rule["columns"], list):
                for column in rule["columns"]:
                    if column in seen_columns:
                        errors.append(f"Duplicate rule for column '{column}'")
                    else:
                        seen_columns.add(column)

    def _find_duplicates(self, items: List[Any]) -> List[str]:
        """Find duplicate items in a list."""
        seen: Set[Any] = set()
        duplicates: Set[Any] = set()

        for item in items:
            if item is not None:
                if item in seen:
                    duplicates.add(item)
                else:
                    seen.add(item)

        return list(duplicates)

    def validate_transformation_options(
        self, action: str, options: Dict[str, Any]
    ) -> List[str]:
        """
        Validate transformation options for a specific action.

        Args:
            action: Transformation action name
            options: Options dictionary

        Returns:
            List of validation errors
        """
        errors = []

        if action == "mask":
            if "mask_char" in options and not isinstance(options["mask_char"], str):
                errors.append("mask_char must be a string")
            if "preserve_first" in options and not isinstance(
                options["preserve_first"], int
            ):
                errors.append("preserve_first must be an integer")
            if "preserve_last" in options and not isinstance(
                options["preserve_last"], int
            ):
                errors.append("preserve_last must be an integer")

        elif action == "hash":
            valid_algorithms = ["md5", "sha1", "sha256", "sha512"]
            if "algorithm" in options and options["algorithm"] not in valid_algorithms:
                errors.append(
                    f"hash algorithm must be one of: {', '.join(valid_algorithms)}"
                )
            if "max_length" in options and not isinstance(options["max_length"], int):
                errors.append("max_length must be an integer")

        elif action == "tokenize":
            if "deterministic" in options and not isinstance(
                options["deterministic"], bool
            ):
                errors.append("deterministic must be a boolean")
            if "token_length" in options and not isinstance(
                options["token_length"], int
            ):
                errors.append("token_length must be an integer")

        return errors
