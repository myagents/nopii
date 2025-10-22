"""
Tests for PolicyValidator including per-action options validation.
"""

from nopii.policy.validator import PolicyValidator


def test_validator_valid_policy_minimal():
    v = PolicyValidator()
    policy = {
        "name": "p",
        "version": "1",
        "default_action": "mask",
        "rules": [
            {"match": "email", "action": "mask", "options": {"mask_char": "*"}},
        ],
        "exceptions": [],
    }
    res = v.validate(policy)
    assert res.is_valid
    assert not res.errors


def test_validator_invalid_options_for_action():
    v = PolicyValidator()
    # token_length should be int; give wrong type
    policy = {
        "name": "p",
        "version": "1",
        "rules": [
            {
                "match": "email",
                "action": "tokenize",
                "options": {"token_length": "bad"},
            },
        ],
    }
    res = v.validate(policy)
    assert not res.is_valid
    assert any("token_length must be an integer" in e for e in res.errors)


def test_validator_duplicate_rules_detection():
    v = PolicyValidator()
    policy = {
        "name": "p",
        "version": "1",
        "rules": [
            {"match": "email", "action": "mask"},
            {"match": "email", "action": "hash"},  # duplicate match
        ],
    }
    res = v.validate(policy)
    assert not res.is_valid
    assert any("Duplicate rule for PII type" in e for e in res.errors)
