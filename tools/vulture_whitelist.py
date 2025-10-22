"""
Whitelist file for vulture: marks public API and CLI entrypoints as used.
This file is not executed; vulture parses it to infer usage.
"""

# CLI commands
from nopii.cli.commands import policy as _policy

_policy.create_policy
_policy.validate_policy
_policy.inspect_policy
_policy.test_policy

# CLI utilities that may be wired by future options
from nopii.cli import utils as _cli_utils

_cli_utils.save_scan_results
_cli_utils.validate_file_path
_cli_utils.validate_output_dir
_cli_utils.confirm_large_file_operation
_cli_utils.setup_logging
_cli_utils.print_summary

# Core models analytics helpers
from nopii.core.models import RiskLevel as _RiskLevel
from nopii.core.models import AuditReport as _AuditReport

_RiskLevel
_AuditReport.get_coverage_by_type
_AuditReport.get_risk_factors
_AuditReport.passes_threshold

# Policy loader convenience API
from nopii.policy.loader import PolicyLoader as _PolicyLoader

_PolicyLoader
_PolicyLoader.load_from_file
_PolicyLoader.load_from_dict
_PolicyLoader.save_to_file
_PolicyLoader.validate_file

# Policy validator helpers
from nopii.policy.validator import PolicyValidator as _PolicyValidator

_PolicyValidator._find_duplicates
_PolicyValidator.validate_transformation_options

# Registries admin operations
from nopii.detectors.registry import DetectorRegistry as _DetReg
from nopii.transforms.registry import TransformRegistry as _TransReg

_DetReg.unregister
_DetReg.get_detector_info
_DetReg.configure_detector
_TransReg.unregister
_TransReg.get_all_transformers
_TransReg.get_transformer_info
_TransReg.batch_transform
_TransReg.get_supported_transformations

# Reporting calculator extras
from nopii.reporting.coverage import CoverageCalculator as _CovCalc

_CovCalc.calculate_data_quality_metrics

# SDK public surface
from nopii.sdk.client import NoPIIClient as _Client
from nopii.sdk.transform import SDKTRANSFORM as _SDKTRANSFORM
from nopii.sdk.policy import SDKPolicy as _SDKPolicy
from nopii.sdk.scanner import SDKScanner as _SDKScanner

_Client.current_policy
_Client.update_policy
_Client.generate_report
_Client.quick_scan
_Client.quick_transform
_Client.get_policy_info
_Client.validate_policy

_SDKTRANSFORM.preview_transform
_SDKTRANSFORM.get_transformer_info
_SDKTRANSFORM.test_transformer
_SDKTRANSFORM.calculate_transform_stats

_SDKPolicy.list_rules
_SDKPolicy.get_rule
_SDKPolicy.add_rule
_SDKPolicy.remove_rule
_SDKPolicy.update_rule
_SDKPolicy.list_exceptions
_SDKPolicy.add_exception
_SDKPolicy.remove_exception
_SDKPolicy.set_default_action
_SDKPolicy.update_reporting_config
_SDKPolicy.save
_SDKPolicy.clone
_SDKPolicy.test_rule_matching
_SDKPolicy.get_statistics

_SDKScanner.scan_dictionary
_SDKScanner.get_coverage_score
_SDKScanner.get_detector_info
_SDKScanner.test_detector
_SDKScanner.analyze_findings
