"""
SDK wrapper for Policy management.
"""

from pathlib import Path
from typing import Dict, List, Optional, Union, Any

from ..core.models import Policy, Rule, PolicyException
from ..policy.loader import save_policy
from ..policy.validator import PolicyValidator


class SDKPolicy:
    """
    SDK wrapper for Policy management.

    Provides a simplified interface for policy operations.
    """

    def __init__(self, policy: Policy):
        """
        Initialize the SDK policy.

        Args:
            policy: Core Policy instance
        """
        self._policy = policy
        self._validator = PolicyValidator()

    @property
    def name(self) -> str:
        """Get policy name."""
        return self._policy.name

    @property
    def version(self) -> str:
        """Get policy version."""
        return self._policy.version

    @property
    def description(self) -> Optional[str]:
        """Get policy description."""
        return self._policy.description

    @property
    def default_action(self) -> str:
        """Get default action."""
        return self._policy.default_action

    def get_info(self) -> Dict[str, Any]:
        """
        Get comprehensive policy information.

        Returns:
            Dictionary with policy information
        """
        return {
            "name": self._policy.name,
            "version": self._policy.version,
            "description": self._policy.description,
            "default_action": self._policy.default_action,
            "rules_count": len(self._policy.rules),
            "exceptions_count": len(self._policy.exceptions),
            "policy_hash": self._policy.policy_hash,
            "reporting_config": self._policy.reporting,
        }

    def list_rules(self) -> List[Dict[str, Any]]:
        """List all rules with indices as ids."""
        return [
            {
                "id": idx,
                "match": rule.match,
                "columns": rule.columns,
                "action": rule.action,
                "options": rule.options,
                "override_confidence": rule.override_confidence,
            }
            for idx, rule in enumerate(self._policy.rules)
        ]

    def get_rule(self, rule_id: int) -> Optional[Dict[str, Any]]:
        """Get a single rule by index id."""
        if 0 <= rule_id < len(self._policy.rules):
            rule = self._policy.rules[rule_id]
            return {
                "id": rule_id,
                "match": rule.match,
                "columns": rule.columns,
                "action": rule.action,
                "options": rule.options,
                "override_confidence": rule.override_confidence,
            }
        return None

    def add_rule(self, rule_data: Dict[str, Any]) -> int:
        """Add a new rule (dict must match core Rule fields). Returns new rule id."""
        rule = Rule(**rule_data)
        self._policy.rules.append(rule)
        return len(self._policy.rules) - 1

    def remove_rule(self, rule_id: int) -> bool:
        """
        Remove a rule from the policy.

        Args:
            rule_name: Name of the rule to remove

        Returns:
            True if rule was removed, False if not found
        """
        if 0 <= rule_id < len(self._policy.rules):
            del self._policy.rules[rule_id]
            return True
        return False

    def update_rule(self, rule_id: int, **kwargs) -> bool:
        """
        Update an existing rule.

        Args:
            rule_name: Name of the rule to update
            **kwargs: Fields to update

        Returns:
            True if rule was updated, False if not found
        """
        if 0 <= rule_id < len(self._policy.rules):
            rule = self._policy.rules[rule_id]
            for key, value in kwargs.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            return True
        return False

    def list_exceptions(self) -> List[Dict[str, Any]]:
        """
        List all exceptions in the policy.

        Returns:
            List of exception information
        """
        return [
            {
                "dataset": exc.dataset,
                "allow_types": exc.allow_types,
                "conditions": exc.conditions,
            }
            for exc in self._policy.exceptions
        ]

    def add_exception(
        self,
        dataset: str,
        allow_types: List[str],
        conditions: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a new exception to the policy."""
        exception = PolicyException(
            dataset=dataset, allow_types=allow_types, conditions=conditions or {}
        )
        self._policy.exceptions.append(exception)

    def remove_exception(self, index: int) -> bool:
        """
        Remove an exception from the policy.

        Args:
            exception_name: Name of the exception to remove

        Returns:
            True if exception was removed, False if not found
        """
        if 0 <= index < len(self._policy.exceptions):
            del self._policy.exceptions[index]
            return True
        return False

    def set_default_action(self, action: str) -> None:
        """
        Set the default action for the policy.

        Args:
            action: Default action (redact, mask, hash, etc.)
        """
        self._policy.default_action = action

    def update_reporting_config(self, **kwargs) -> None:
        """
        Update reporting configuration.

        Args:
            **kwargs: Reporting configuration fields to update
        """
        for key, value in kwargs.items():
            if key in self._policy.reporting:
                self._policy.reporting[key] = value

    def validate(self) -> Dict[str, Any]:
        """
        Validate the current policy.

        Returns:
            Dictionary with validation results
        """
        policy_dict = self._policy.model_dump()
        result = self._validator.validate(policy_dict)

        return {
            "is_valid": result.is_valid,
            "errors": result.errors,
            "warnings": result.warnings,
        }

    def save(self, file_path: Union[str, Path]) -> None:
        """
        Save the policy to a file.

        Args:
            file_path: Path to save the policy file
        """
        save_policy(self._policy, file_path)

    def clone(self, new_name: Optional[str] = None) -> "SDKPolicy":
        """
        Create a copy of the current policy.

        Args:
            new_name: Optional new name for the cloned policy

        Returns:
            New SDKPolicy instance with copied policy
        """
        # Create a deep copy of the policy
        policy_dict = self._policy.model_dump()

        if new_name:
            policy_dict["name"] = new_name

        # Create new policy from dict
        from ..policy.loader import load_policy_from_dict

        new_policy = load_policy_from_dict(policy_dict)

        return SDKPolicy(new_policy)

    def get_applicable_rules(
        self,
        pii_type: Optional[str] = None,
        column: Optional[str] = None,
        dataset: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get rules that would apply to specific criteria.

        Args:
            pii_type: PII type to check
            column: Column name to check
            dataset: Dataset name to check (currently unused)

        Returns:
            List of applicable rules (preserving policy order)
        """
        applicable: List[Dict[str, Any]] = []

        for idx, rule in enumerate(self._policy.rules):
            match_ok = True
            if pii_type is not None and rule.match is not None:
                match_ok = rule.match == pii_type

            column_ok = True
            if column is not None and rule.columns is not None:
                column_ok = column in rule.columns

            # If both criteria provided and both are constrained, require both
            if pii_type is not None and column is not None:
                if rule.match is not None and rule.columns is not None:
                    if not (match_ok and column_ok):
                        continue
                else:
                    if rule.match is not None and not match_ok:
                        continue
                    if rule.columns is not None and not column_ok:
                        continue
            else:
                # Only enforce the provided constraints
                if pii_type is not None and rule.match is not None and not match_ok:
                    continue
                if column is not None and rule.columns is not None and not column_ok:
                    continue

            applicable.append(
                {
                    "id": idx,
                    "match": rule.match,
                    "columns": rule.columns,
                    "action": rule.action,
                    "options": rule.options,
                    "override_confidence": rule.override_confidence,
                }
            )

        return applicable

    def test_rule_matching(
        self, test_cases: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Test rule matching against test cases.

        Args:
            test_cases: List of test cases with 'type', 'column', 'dataset' keys

        Returns:
            List of test results
        """
        results = []

        for test_case in test_cases:
            applicable_rules = self.get_applicable_rules(
                pii_type=test_case.get("type"),
                column=test_case.get("column"),
                dataset=test_case.get("dataset"),
            )

            results.append(
                {
                    "test_case": test_case,
                    "matching_rules": applicable_rules,
                    "action_taken": applicable_rules[0]["action"]
                    if applicable_rules
                    else self._policy.default_action,
                    "rule_used": (
                        f"rule_index:{applicable_rules[0]['id']}"
                        if applicable_rules
                        else "default"
                    ),
                }
            )

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get policy statistics.

        Returns:
            Dictionary with policy statistics
        """
        action_counts: Dict[str, int] = {}
        type_counts: Dict[str, int] = {}
        for rule in self._policy.rules:
            action_counts[rule.action] = action_counts.get(rule.action, 0) + 1
            if rule.match:
                type_counts[rule.match] = type_counts.get(rule.match, 0) + 1
        return {
            "total_rules": len(self._policy.rules),
            "total_exceptions": len(self._policy.exceptions),
            "action_distribution": action_counts,
            "type_distribution": type_counts,
            "default_action": self._policy.default_action,
        }

    def __repr__(self) -> str:
        """String representation of the SDK policy."""
        return f"SDKPolicy(name='{self._policy.name}', rules={len(self._policy.rules)}, exceptions={len(self._policy.exceptions)})"
