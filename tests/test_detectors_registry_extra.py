"""
Additional tests for DetectorRegistry helpers.
"""

from nopii.detectors.registry import DetectorRegistry


def test_registry_get_detectors_by_type_and_configure():
    reg = DetectorRegistry()
    emails = reg.get_detectors_by_type("email")
    assert emails and all(d.pii_type == "email" for d in emails)

    # configure no-op returns True when detector validates
    assert reg.configure_detector("email", {}) is True
