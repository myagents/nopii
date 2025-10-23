import pandas as pd

from nopii.sdk.transform import SDKTransform
from nopii.sdk.scanner import SDKScanner
from nopii.policy.models import Policy, Rule
from nopii.core.models import Policy as CorePolicy, Rule as CoreRule


def test_sdk_transform_dataframe_and_text_and_dict():
    st = SDKTransform()

    df = pd.DataFrame({"email": ["alice@example.com"], "note": ["none"]})
    transformed, audit = st.transform_dataframe(df, dataset_name="ds", dry_run=True)
    assert list(transformed.columns) == ["email", "note"]
    assert audit.coverage_score >= 0.0

    text_out, findings = st.transform_text("contact bob@example.com")
    assert "bob@example.com" not in text_out
    assert any(f["type"] == "email" for f in findings)

    data_out, findings_dict = st.transform_dictionary({"email": "c@example.com"})
    assert data_out["email"] != "c@example.com"
    assert any(f["type"] == "email" for f in findings_dict)


def test_sdk_scanner_text_threshold_and_list_detectors():
    ss = SDKScanner()
    # High threshold should filter out low-confidence detections
    findings_hi = ss.scan_text("1111111111", confidence_threshold=0.99)
    assert findings_hi == []

    # Detectors list should not be empty
    dets = ss.list_detectors()
    assert isinstance(dets, list) and len(dets) > 0
    info = ss.get_detector_info(dets[0]["name"])  # roundtrip info
    assert "description" in info


def test_policy_models_reexports():
    # Ensure policy.models re-exports core models
    assert Policy is CorePolicy
    assert Rule is CoreRule
