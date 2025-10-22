"""
Tests for SDKPolicy CRUD operations and validation glue without pandas.
"""

from nopii.sdk.policy import SDKPolicy
from nopii.policy.loader import create_default_policy


def test_sdkpolicy_rule_crud_and_stats():
    base = create_default_policy()
    sdk = SDKPolicy(base)

    # Capture baseline rules from default policy (may include defaults)
    base_count = len(sdk.list_rules())

    # Add a rule
    rid = sdk.add_rule(
        {"match": "email", "action": "mask", "options": {"mask_char": "*"}}
    )
    assert isinstance(rid, int)
    rules = sdk.list_rules()
    assert len(rules) == base_count + 1
    assert rules[rid]["match"] == "email"

    # Update the rule
    assert sdk.update_rule(rid, action="hash") is True
    assert sdk.get_rule(rid)["action"] == "hash"

    # Add exception and list
    sdk.add_exception("dataset", ["email"])
    ex = sdk.list_exceptions()
    assert ex and ex[0]["dataset"] == "dataset"

    # Stats reflect baseline + one new rule, and one exception
    stats = sdk.get_statistics()
    assert stats["total_rules"] == base_count + 1
    assert stats["total_exceptions"] >= 1

    # Remove rule
    assert sdk.remove_rule(rid) is True
    assert len(sdk.list_rules()) == base_count


def test_sdkpolicy_validate_and_config():
    base = create_default_policy()
    sdk = SDKPolicy(base)

    # Update reporting config
    sdk.update_reporting_config(output_dir="out")
    assert sdk.get_info()["reporting_config"]["output_dir"] == "out"

    # Set default action
    sdk.set_default_action("redact")
    assert sdk.get_info()["default_action"] == "redact"

    # Validator runs on current policy model_dump
    res = sdk.validate()
    assert res["is_valid"] is True
