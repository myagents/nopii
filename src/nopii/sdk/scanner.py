"""
SDK wrapper for the Scanner class.
"""

from pathlib import Path
from typing import Dict, List, Optional, Union, Any

try:  # optional pandas
    import pandas as pd
except Exception:  # pragma: no cover
    pd = None

from ..core.scanner import Scanner
from ..policy.loader import create_default_policy
from ..core.models import ScanResult, Finding


class SDKScanner:
    """
    SDK wrapper for the Scanner class.

    Provides a simplified interface for PII scanning operations.
    """

    def __init__(self, scanner: Optional[Scanner] = None):
        """
        Initialize the SDK scanner.

        Args:
            scanner: Core Scanner instance
        """
        self._scanner = scanner or Scanner(create_default_policy())

    def scan_dataframe(
        self,
        df: pd.DataFrame,
        dataset_name: Optional[str] = None,
        confidence_threshold: float = 0.5,
    ) -> ScanResult:
        """
        Scan a pandas DataFrame for PII.

        Args:
            df: DataFrame to scan
            dataset_name: Optional name for the dataset
            confidence_threshold: Minimum confidence threshold for findings

        Returns:
            ScanResult with detected PII
        """
        result = self._scanner.scan_dataframe(df, dataset_name or "dataframe")

        # Filter by confidence threshold
        if confidence_threshold > 0:
            result.findings = [
                f for f in result.findings if f.confidence >= confidence_threshold
            ]

        return result

    def scan_text(
        self, text: str, confidence_threshold: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Scan text for PII.

        Args:
            text: Text to scan
            confidence_threshold: Minimum confidence threshold for findings

        Returns:
            List of findings as dictionaries
        """
        findings = self._scanner.scan_text(text)

        # Filter by confidence threshold
        if confidence_threshold > 0:
            findings = [f for f in findings if f.confidence >= confidence_threshold]

        # Convert to dictionaries for easier SDK usage
        return [
            {
                "type": f.type,
                "value": f.value,
                "confidence": f.confidence,
                "start_pos": f.span[0],
                "end_pos": f.span[1],
                "column": "text",
                "row_index": 0,
                "evidence": f.evidence,
            }
            for f in findings
        ]

    def scan_file(
        self, file_path: Union[str, Path], confidence_threshold: float = 0.5
    ) -> ScanResult:
        """
        Scan a file for PII.

        Args:
            file_path: Path to file to scan
            confidence_threshold: Minimum confidence threshold for findings

        Returns:
            ScanResult with detected PII
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Load file based on extension
        if file_path.suffix.lower() == ".csv":
            # Use core streaming scanner to avoid loading entire file
            return self._scanner.scan_file(file_path, confidence_threshold)
        elif file_path.suffix.lower() == ".json":
            if pd is None:
                raise RuntimeError(
                    "pandas is required to scan JSON files. Install pandas."
                )
            df = pd.read_json(file_path)
            return self.scan_dataframe(df, file_path.stem, confidence_threshold)
        elif file_path.suffix.lower() == ".parquet":
            if pd is None:
                raise RuntimeError(
                    "pandas is required to scan Parquet files. Install pandas."
                )
            df = pd.read_parquet(file_path)
            return self.scan_dataframe(df, file_path.stem, confidence_threshold)
        elif file_path.suffix.lower() in [".txt", ".md"]:
            # Use core streaming scanner for text files (line-by-line)
            return self._scanner.scan_file(file_path, confidence_threshold)
        else:
            raise ValueError(f"Unsupported file format: {file_path.suffix}")

    def scan_dictionary(
        self, data: Dict[str, Any], confidence_threshold: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Scan a dictionary for PII.

        Args:
            data: Dictionary to scan
            confidence_threshold: Minimum confidence threshold for findings

        Returns:
            List of findings as dictionaries
        """
        findings = self._scanner.scan_dict(data)

        # Filter by confidence threshold
        if confidence_threshold > 0:
            findings = [f for f in findings if f.confidence >= confidence_threshold]

        # Convert to dictionaries for easier SDK usage
        return [
            {
                "type": f.type,
                "value": f.value,
                "confidence": f.confidence,
                "key": f.column,
                "row_index": f.row_index,
                "span": f.span,
            }
            for f in findings
        ]

    def get_coverage_score(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Calculate detection coverage metrics for a scan result."""
        from ..reporting.coverage import CoverageCalculator

        calc = CoverageCalculator()
        # We don't know total cells here; let calculator derive available metrics
        return calc.calculate_detection_coverage(scan_result)

    def list_detectors(self) -> List[Dict[str, Any]]:
        """
        List available PII detectors.

        Returns:
            List of detector information
        """
        registry = self._scanner.detector_registry
        names = registry.list_detectors()
        out: List[Dict[str, Any]] = []
        for name in names:
            det = registry.get_detector(name)
            if not det:
                continue
            info = det.get_info()
            out.append(
                {
                    "name": info.get("name", name),
                    "pii_type": info.get("pii_type", name),
                    "description": info.get("description", ""),
                }
            )
        return out

    def get_detector_info(self, detector_name: str) -> Dict[str, Any]:
        """
        Get information about a specific detector.

        Args:
            detector_name: Name of the detector

        Returns:
            Dictionary with detector information
        """
        detector = self._scanner.detector_registry.get_detector(detector_name)
        if not detector:
            raise ValueError(f"Detector not found: {detector_name}")

        return detector.get_info()

    def test_detector(
        self, detector_name: str, test_data: Union[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """
        Test a specific detector against sample data.

        Args:
            detector_name: Name of the detector to test
            test_data: Sample data to test

        Returns:
            List of findings from the detector
        """
        detector = self._scanner.detector_registry.get_detector(detector_name)
        if not detector:
            raise ValueError(f"Detector not found: {detector_name}")

        inputs = [test_data] if isinstance(test_data, str) else list(test_data)
        results: List[Dict[str, Any]] = []
        for s in inputs:
            matches = detector.detect(s)
            results.append(
                {
                    "input": s,
                    "detected": bool(matches),
                    "matches": matches,
                }
            )
        return results

    def analyze_findings(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Analyze a list of findings and provide statistics.

        Args:
            findings: List of findings to analyze

        Returns:
            Dictionary with analysis results
        """
        if not findings:
            return {
                "total_findings": 0,
                "unique_types": 0,
                "average_confidence": 0.0,
                "high_confidence_count": 0,
                "type_distribution": {},
            }

        # Calculate statistics
        total_findings = len(findings)
        unique_types = len(set(f.type for f in findings))
        average_confidence = sum(f.confidence for f in findings) / total_findings
        high_confidence_count = len([f for f in findings if f.confidence >= 0.8])

        # Type distribution
        type_distribution: Dict[str, int] = {}
        for finding in findings:
            type_distribution[finding.type] = type_distribution.get(finding.type, 0) + 1

        return {
            "total_findings": total_findings,
            "unique_types": unique_types,
            "average_confidence": round(average_confidence, 3),
            "high_confidence_count": high_confidence_count,
            "high_confidence_percentage": round(
                (high_confidence_count / total_findings) * 100, 1
            ),
            "type_distribution": type_distribution,
            "most_common_type": max(type_distribution.items(), key=lambda x: x[1])[0]
            if type_distribution
            else None,
        }

    def __repr__(self) -> str:
        """String representation of the SDK scanner."""
        return f"SDKScanner(detectors={len(self._scanner.detector_registry.list_detectors())})"
