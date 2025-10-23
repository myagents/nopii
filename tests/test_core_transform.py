import pandas as pd

from nopii.core.transform import Transform
from nopii.policy.loader import create_default_policy


def test_transform_dataframe_casts_numeric_phone_column_and_masks():
    policy = create_default_policy()
    t = Transform(policy)

    # Phone numbers as integers (numeric dtype), which should be detected and masked
    df = pd.DataFrame(
        {
            "phone": [5551234567, 5559876543],  # int64 column
            "email": ["john@example.com", "jane@test.org"],
        }
    )

    transformed, audit = t.transform_dataframe(df, dataset_name="df")

    # Column should have been cast to a string-friendly dtype
    dtype = transformed["phone"].dtype
    assert pd.api.types.is_string_dtype(dtype) or pd.api.types.is_object_dtype(dtype)

    # Values should be masked, preserving last 4 digits
    assert transformed.loc[0, "phone"].endswith("4567")
    assert transformed.loc[1, "phone"].endswith("6543")
    assert set(audit.findings_by_type.keys())  # has findings


def test_transform_text_with_report_produces_audit_and_samples():
    policy = create_default_policy()
    t = Transform(policy)

    text = "Contact john@example.com or 5551234567"
    transformed, audit = t.transform_text_with_report(text, dataset_name="text_ds")

    # Ensure text was transformed
    assert "john@example.com" not in transformed
    assert "5551234567" not in transformed

    # Audit report basic fields present
    assert audit.job_name.startswith("transform_")
    assert audit.performance_metrics.get("total_duration") is not None
    # Samples should not exceed configured limit
    for samples in audit.samples.values():
        assert len(samples) <= policy.reporting.get("store_samples", 3)


def test_transform_dict_replaces_value():
    policy = create_default_policy()
    t = Transform(policy)

    data = {"email": "user@example.com", "note": "no pii"}
    transformed, findings = t.transform_dict(data)

    assert transformed["email"] != "user@example.com"
    assert any(f.type == "email" for f in findings)
