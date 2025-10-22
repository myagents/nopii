"""
SDK wrapper for the TRANSFORM class.
"""

from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple

try:
    import pandas as pd
except Exception:  # pragma: no cover
    pd = None

from ..core.transform import Transform
from ..policy.loader import create_default_policy
from ..core.models import AuditReport


class SDKTransform:
    """
    SDK wrapper for the Transform class.

    Provides a simplified interface for PII transformation operations.
    """

    def __init__(self, transform: Optional[Transform] = None):
        """
        Initialize the SDK transform.

        Args:
            transform: Core TRANSFORM instance
        """
        self._transform = transform or Transform(create_default_policy())

    def transform_dataframe(
        self,
        df: pd.DataFrame,
        dataset_name: Optional[str] = None,
        dry_run: bool = False,
    ) -> Tuple[pd.DataFrame, AuditReport]:
        """
        No PII from a pandas DataFrame.

        Args:
            df: DataFrame to transform
            dataset_name: Optional name for the dataset
            dry_run: If True, don't modify data but show what would be transform

        Returns:
            Tuple of (transform_dataframe, audit_report)
        """
        return self._transform.transform_dataframe(
            df, dataset_name or "dataframe", dry_run=dry_run
        )

    def transform_text(
        self, text: str, dry_run: bool = False
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """
        No PII from text.

        Args:
            text: Text to transform
            dry_run: If True, don't modify text but show what would be transform

        Returns:
            Tuple of (transform_text, findings_list)
        """
        transform_text, findings = self._transform.transform_text(text, dry_run=dry_run)

        # Convert findings to dictionaries for easier SDK usage
        findings_dict = [
            {
                "type": f.type,
                "original_value": f.value,
                "transformed_value": f.transformed_value,
                "confidence": f.confidence,
                "start_pos": f.span[0],
                "end_pos": f.span[1],
                "action_taken": f.action_taken,
                "column": "text",
                "row_index": 0,
                "evidence": f.evidence,
            }
            for f in findings
        ]

        return transform_text, findings_dict

    def transform_file(
        self,
        input_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
        dry_run: bool = False,
        backup: bool = True,
    ) -> AuditReport:
        """
        No PII from a file.

        Args:
            input_path: Path to input file
            output_path: Path to output file (defaults to input_path)
            dry_run: If True, don't modify file but show what would be transform
            backup: If True, create backup of original file

        Returns:
            AuditReport with transformation details
        """
        input_path = Path(input_path)

        if not input_path.exists():
            raise FileNotFoundError(f"File not found: {input_path}")

        if output_path is None:
            output_path = input_path
        else:
            output_path = Path(output_path)

        # Create backup if requested
        if backup and not dry_run:
            backup_path = input_path.with_suffix(input_path.suffix + ".backup")
            import shutil

            shutil.copy2(input_path, backup_path)

        # Load and transform file based on extension
        if input_path.suffix.lower() == ".csv":
            if pd is None:
                raise RuntimeError(
                    "pandas is required to process CSV files. Install pandas."
                )
            df = pd.read_csv(input_path)
            transform_df, audit_report = self.transform_dataframe(
                df, input_path.stem, dry_run
            )

            if not dry_run:
                transform_df.to_csv(output_path, index=False)

            return audit_report

        elif input_path.suffix.lower() == ".json":
            if pd is None:
                raise RuntimeError(
                    "pandas is required to process JSON files. Install pandas."
                )
            df = pd.read_json(input_path)
            transform_df, audit_report = self.transform_dataframe(
                df, input_path.stem, dry_run
            )

            if not dry_run:
                transform_df.to_json(output_path, orient="records", indent=2)

            return audit_report

        elif input_path.suffix.lower() == ".parquet":
            if pd is None:
                raise RuntimeError(
                    "pandas is required to process Parquet files. Install pandas."
                )
            df = pd.read_parquet(input_path)
            transform_df, audit_report = self.transform_dataframe(
                df, input_path.stem, dry_run
            )

            if not dry_run:
                transform_df.to_parquet(output_path, index=False)

            return audit_report

        elif input_path.suffix.lower() in [".txt", ".md"]:
            with open(input_path, "r", encoding="utf-8") as f:
                text = f.read()
            transform_text, audit_report = self._transform.transform_text_with_report(
                text,
                dataset_name=input_path.stem,
                job_name=f"transform_{input_path.stem}",
                dry_run=dry_run,
            )
            if not dry_run:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(transform_text)
            return audit_report

        else:
            raise ValueError(f"Unsupported file format: {input_path.suffix}")

    def transform_dictionary(
        self, data: Dict[str, Any], dry_run: bool = False
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        No PII from a dictionary.

        Args:
            data: Dictionary to transform
            dry_run: If True, don't modify data but show what would be transform

        Returns:
            Tuple of (transform_dictionary, findings_list)
        """
        transform_dict, findings = self._transform.transform_dict(data, dry_run=dry_run)

        # Convert findings to dictionaries for easier SDK usage
        findings_dict = [
            {
                "type": f.type,
                "original_value": f.value,
                "transformed_value": f.transformed_value,
                "confidence": f.confidence,
                "key": f.column,
                "action_taken": f.action_taken,
                "evidence": f.evidence,
            }
            for f in findings
        ]

        return transform_dict, findings_dict

    def preview_transformation(
        self, data: Union[pd.DataFrame, str, Dict[str, Any]], max_samples: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Preview what would be transformed without actually modifying the data.

        Args:
            data: Data to preview transformation for
            max_samples: Maximum number of samples to return

        Returns:
            List of transformation previews
        """
        if isinstance(data, pd.DataFrame):
            _, audit_report = self.transform_dataframe(data, dry_run=True)
            findings = audit_report.findings[:max_samples]

            return [
                {
                    "type": f.type,
                    "column": f.column,
                    "row_index": f.row_index,
                    "original_value": f.value,
                    "transformed_value": f.transformed_value,
                    "action": f.action_taken,
                    "confidence": f.confidence,
                }
                for f in findings
            ]

        elif isinstance(data, str):
            _, text_findings = self.transform_text(data, dry_run=True)

            return text_findings[:max_samples]

        elif isinstance(data, dict):
            _, dict_findings = self.transform_dictionary(data, dry_run=True)

            return dict_findings[:max_samples]

        else:
            raise ValueError(f"Unsupported data type: {type(data)}")

    def list_transformers(self) -> List[Dict[str, Any]]:
        """
        List available transformers.

        Returns:
            List of transformer information
        """
        registry = self._transform.transform_registry
        names = registry.list_transformers()
        out: List[Dict[str, Any]] = []
        for name in names:
            t = registry.get_transformer(name)
            if not t:
                continue
            info = t.get_info()
            out.append(
                {
                    "name": name,
                    "description": info.get("description", ""),
                    "reversible": t.is_reversible(),
                }
            )
        return out

    def get_transformer_info(self, transformer_name: str) -> Dict[str, Any]:
        """
        Get information about a specific transformer.

        Args:
            transformer_name: Name of the transformer

        Returns:
            Dictionary with transformer information
        """
        transformer = self._transform.transform_registry.get_transformer(
            transformer_name
        )
        if not transformer:
            raise ValueError(f"Transformer not found: {transformer_name}")

        return transformer.get_info()

    def test_transformer(
        self,
        transformer_name: str,
        test_data: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Test a specific transformer against sample data.

        Args:
            transformer_name: Name of the transformer to test
            test_data: Sample data to transform
            options: Optional transformer options

        Returns:
            Transformed data
        """
        result = self._transform.transform_registry.transform(
            test_data, "unknown", transformer_name, options or {}
        )
        if not result.success:
            raise ValueError(result.error_message or "Transformation failed")
        return result.transformed_value or test_data

    def calculate_transformation_stats(
        self, audit_report: AuditReport
    ) -> Dict[str, Any]:
        """
        Calculate transformation statistics from an audit report.

        Args:
            audit_report: Audit report to analyze

        Returns:
            Dictionary with transformation statistics
        """
        if not audit_report.findings:
            return {
                "total_findings": 0,
                "transform_count": 0,
                "redaction_rate": 0.0,
                "skipped_count": 0,
                "skip_rate": 0.0,
                "action_distribution": {},
            }

        total_findings = len(audit_report.findings)
        transform_count = len(
            [
                f
                for f in audit_report.findings
                if f.action_taken and f.action_taken != "skip"
            ]
        )
        skipped_count = len(
            [
                f
                for f in audit_report.findings
                if not f.action_taken or f.action_taken == "skip"
            ]
        )

        # Action distribution
        action_distribution: Dict[str, int] = {}
        for finding in audit_report.findings:
            action = finding.action_taken or "none"
            action_distribution[action] = action_distribution.get(action, 0) + 1

        return {
            "total_findings": total_findings,
            "transform_count": transform_count,
            "redaction_rate": round((transform_count / total_findings) * 100, 1),
            "skipped_count": skipped_count,
            "skip_rate": round((skipped_count / total_findings) * 100, 1),
            "action_distribution": action_distribution,
            "coverage_score": round(audit_report.coverage_score * 100, 1),
            "residual_risk": round(audit_report.residual_risk * 100, 1),
        }

    def __repr__(self) -> str:
        """String representation of the SDK transform."""
        return f"SDKTRANSFORM(transformers={len(self._transform.transform_registry.list_transformers())})"
