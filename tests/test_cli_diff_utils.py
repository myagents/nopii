"""
Unit tests for diff helpers without requiring pandas DataFrame.
We provide a small DummyDF that mimics minimal DataFrame API used by the helpers.
"""

from pathlib import Path
from typing import List, Dict, Any

from nopii.cli.commands.diff import (
    calculate_differences,
    check_data_type_preservation,
    save_diff_results,
)


class DummyColumn:
    def __init__(self, name: str, values: List[Any], dtype: str = "object"):
        self.name = name
        self._values = values
        self.dtype = dtype


class DummyDF:
    def __init__(self, data: List[Dict[str, Any]]):
        self._data = data
        self.columns = list(data[0].keys()) if data else []
        self.index = list(range(len(data)))
        self.size = len(data) * len(self.columns)

    def __len__(self):
        return len(self._data)

    def _get_value(self, idx, column):
        # Simulate DataFrame cell access
        return self._data[idx][column]

    # Allow bracket access used in check_data_type_preservation for dtype
    def __getitem__(self, column: str) -> DummyColumn:
        values = [row[column] for row in self._data]
        # Infer very rough dtype string
        dtype = "int64" if all(isinstance(v, int) for v in values) else "object"
        return DummyColumn(column, values, dtype=dtype)


def _adapt_df_accessors(df: DummyDF):
    """Provide attributes to mimic pandas .loc for two-key indexing.

    We monkey-patch an attribute 'loc' that supports df.loc[idx, column] form.
    """

    class _Loc:
        def __init__(self, outer: DummyDF):
            self._outer = outer

        def __getitem__(self, key):
            idx, column = key
            return self._outer._get_value(idx, column)

    df.loc = _Loc(df)  # type: ignore[attr-defined]
    return df


def test_calculate_differences_counts():
    original = _adapt_df_accessors(
        DummyDF(
            [
                {"name": "Alice", "email": "a@example.com"},
                {"name": "Bob", "email": "b@example.com"},
            ]
        )
    )
    transform = _adapt_df_accessors(
        DummyDF(
            [
                {"name": "Alice", "email": "a@example.com"},
                {"name": "Bob", "email": "b@ex.co"},  # changed
            ]
        )
    )

    diff = calculate_differences(original, transform, include_details=True)
    assert diff["total_rows"] == 2
    assert diff["total_columns"] == 2
    assert diff["changed_cells"] == 1
    assert diff["change_rate"] == 1 / 4
    assert diff["column_changes"]["email"] == 1
    assert diff["detailed_changes"][0]["column"] == "email"


def test_check_data_type_preservation_detects_change():
    original = _adapt_df_accessors(
        DummyDF(
            [
                {"id": 1, "val": "x"},
                {"id": 2, "val": "y"},
            ]
        )
    )
    # Change type of 'id' to string
    transform = _adapt_df_accessors(
        DummyDF(
            [
                {"id": "1", "val": "x"},
                {"id": "2", "val": "y"},
            ]
        )
    )
    changes = check_data_type_preservation(original, transform)
    assert "id" in changes
    assert changes["id"]["original"] == "int64"
    assert changes["id"]["transform"] == "object"


def test_save_diff_results_json_and_table(tmp_path: Path):
    diff = {
        "total_rows": 2,
        "total_columns": 2,
        "total_cells": 4,
        "changed_cells": 1,
        "change_rate": 0.25,
        "column_changes": {"email": 1},
        "detailed_changes": [
            {"row": 1, "column": "email", "original": "a", "transform": "b"}
        ],
    }

    # JSON
    out_json = tmp_path / "diff.json"
    save_diff_results(diff, out_json, "json")
    assert out_json.exists()
    assert '"changed_cells": 1' in out_json.read_text(encoding="utf-8")

    # Table
    out_txt = tmp_path / "diff.txt"
    save_diff_results(diff, out_txt, "table")
    txt = out_txt.read_text(encoding="utf-8")
    assert "TRANSFORM Diff Summary" in txt
    assert "Changed Cells: 1" in txt
