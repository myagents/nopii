# NoPII

A Python package for detecting, transforming, and auditing Personally Identifiable Information (PII) in your data. Supports multiple data sources including CSV, JSON, Parquet, and pandas DataFrames with policy-driven configuration.

## Features

### 🔍 **PII Detection**

- **Built-in Detectors**: Identifies email addresses, phone numbers, credit cards, SSNs, IP addresses, names, addresses, and dates of birth
- **Confidence Scoring**: Each detection includes a confidence score (0-100%) with configurable thresholds to balance precision and recall
- **Custom Pattern Support**: Create your own detectors using regex patterns or implement the BaseDetector interface for complex logic
- **Multi-language Support**: Localized detection patterns for different regions and formats (US phone numbers, international emails, etc.)

### 🛡️ **Transformation Strategies**

- **Masking**: Replace characters with asterisks or custom symbols while preserving format (e.g., `john@example.com` → `****@example.com`)
- **Redacting**: Replace entire PII values with placeholder text (e.g., `john@example.com` → `[REDACTED]`)
- **Hashing**: One-way cryptographic transformation using SHA-256 or other algorithms, with optional salt for security
- **Tokenization**: Replace with reversible tokens for data analysis while maintaining referential integrity across datasets
- **Nullification**: Replace with null/empty values for complete data removal

### 📊 **Data Processing**

- **Pandas DataFrames**: Process tabular data with vectorized operations for performance, supporting column-wise scanning and transformation
- **File Formats**: Direct support for CSV, JSON, Parquet, and Excel files with streaming for large datasets
- **Text & Dictionaries**: Scan and transform plain text strings and Python dictionaries for flexible data handling
- **Memory Efficient**: Streaming processing for large files to avoid loading entire datasets into memory

### 📋 **Policy Management**

- **YAML Configuration**: Human-readable policy files defining detection rules, transformation actions, and confidence thresholds
- **Rule-based System**: Match PII types (email, phone, ssn) to specific actions (mask, redact, hash) with customizable options
- **Exception Handling**: Define patterns to skip (e.g., company email domains, test data) with regex-based exclusions
- **Policy Validation**: Built-in validation ensures policy syntax is correct and transformation options are compatible

### 🔧 **CLI & SDK**

- **Command Line Interface**: Five main commands (scan, transform, report, diff, policy) for file processing and policy management
- **Python SDK**: High-level NoPIIClient for quick operations and low-level Scanner/Transform classes for fine-grained control
- **Audit Reporting**: JSON audit trails with HTML/Markdown report generation including coverage metrics and PII type breakdowns
- **Coverage Scoring**: Quantitative metrics showing percentage of data scanned and residual risk assessment

## Installation

```bash
pip install nopii
```

The base installation includes core PII detection and transformation capabilities for text files, JSON, and basic CSV processing.

### Optional Dependencies

Install optional extras for extended functionality:

```bash
# Pandas support for DataFrame operations and advanced tabular file formats
# Enables: Excel files, Parquet, advanced CSV operations, column-wise processing
pip install "nopii[pandas]"

# HTML reporting with styled templates and interactive elements
# Enables: Rich HTML reports, charts, detailed PII breakdowns, export options
pip install "nopii[report-html]"

# Install all optional dependencies
pip install "nopii[pandas,report-html]"
```

## Quick Start

### CLI Usage

The CLI provides five main commands for different PII processing workflows:

```bash
# Scan: Detect PII without modifying data
# Outputs findings with confidence scores and locations
nopii scan data.csv --format json --output scan_results.json

# Transform: Remove or mask PII from files
# Creates cleaned data + audit trail of what was changed
nopii transform data.csv transformed_data.csv --audit-report audit.json

# Report: Generate human-readable reports from audit data
# Convert JSON audit logs into HTML/Markdown with charts and summaries
nopii report audit.json --format html --output report.html

# Diff: Compare original vs transformed files
# Shows exactly what PII was detected and how it was changed
nopii diff original.csv transformed.csv

# Policy: Manage detection and transformation rules
# Validate YAML policies or create new ones
nopii policy validate my_policy.yaml

# Create a new policy file
nopii policy create new_policy.yaml --default-action redact
```

# Note: the CLI is also available as 'no-pii' (alias)

# nopii scan data.csv --format json

````

Exit codes:

- `0` when no PII is detected
- `1` when PII is found
- Non‑zero on errors

### Python SDK / Core

The SDK provides two levels of access: low-level core classes for fine-grained control and a high-level client for quick operations.

#### Core Classes (Low-level API)

Use Scanner and Transform classes directly when you need precise control over detection and transformation:

```python
from nopii.core.scanner import Scanner
from nopii.core.transform import Transform
from nopii.policy.loader import create_default_policy, load_policy

# Load policy (default or custom YAML)
policy = create_default_policy()  # or load_policy("policy.yaml")

# Scanner: Detect PII without modifying data
# Returns list of Finding objects with location, confidence, and PII type
scanner = Scanner(policy)
findings = scanner.scan_text("Contact john@example.com or 555-123-4567")
print(f"Found {len(findings)} findings")

# Transform: Apply policy actions (mask, redact, hash) to PII
# Returns tuple of (cleaned_text, findings_list)
transformer = Transform(policy)
transformed_text, findings = transformer.transform_text("Contact john@example.com or 555-123-4567")
print(f"Transformed: {transformed_text}")

# DataFrame operations (requires pandas extra)
import pandas as pd
df = pd.DataFrame({"email": ["john@example.com"], "phone": ["555-123-4567"]})

# Scan entire DataFrame, get detailed results per column
scan_result = scanner.scan_dataframe(df, dataset_name="contacts")

# Transform DataFrame, get cleaned data + comprehensive audit report
df_transformed, audit_report = transformer.transform_dataframe(df, dataset_name="contacts")
print(f"Coverage: {audit_report.coverage_score:.1%}, Risk: {audit_report.residual_risk}")
````

#### High-Level Client (Quick Operations)

Use NoPIIClient for simple, one-line operations with sensible defaults:

```python
from nopii.sdk import NoPIIClient

client = NoPIIClient()

# Scan text
findings = client.scanner.scan_text("Contact john@example.com")
print(f"Found {len(findings)} PII items")

# Transform text
result = client.transform_text("Contact john@example.com")
print(result)  # "Contact ****@example.com"
```

### DataFrame Processing

```python
import pandas as pd
from nopii.core.scanner import Scanner
from nopii.core.transform import Transform
from nopii.policy.loader import create_default_policy

policy = create_default_policy()
df = pd.read_csv("data.csv")

scanner = Scanner(policy)
transformer = Transform(policy)

# Load and process data
df = pd.read_csv("customer_data.csv")
scan_result = scanner.scan_dataframe(df, dataset_name="customers")
transformed_df, audit = transformer.transform_dataframe(df, dataset_name="customers")

# Review results
print(f"Processed {len(df)} rows, coverage: {audit.coverage_score:.1%}")
print(f"PII types found: {[f.pii_type for f in scan_result.findings]}")
print(f"Columns affected: {len(audit.column_reports)}")
```

### Performance & Streaming

NoPII is designed for efficient processing of large datasets:

**Memory-Efficient Streaming:**

- CLI and SDK automatically stream `.csv` and `.txt/.md` files to avoid loading entire files into memory
- Processes files line-by-line or in configurable chunks (default: 1000 rows)
- Suitable for multi-GB files on standard hardware

**In-Memory Operations:**

- JSON/Parquet files and DataFrame operations require pandas and load data into memory
- Recommended for files under 1GB or when you need full DataFrame functionality
- For very large JSON, consider line-delimited JSON (JSONL) and chunked processing.
- Coverage metrics for streaming scans are computed without a full DataFrame, using policy rules and detected items.

## Policy Configuration (YAML)

```yaml
name: my_policy
default_action: mask
thresholds:
  min_confidence: 0.7
rules:
  - match: email
    action: mask
    options:
      mask_char: "*"
  - match: phone
    action: redact
  - match: ssn
    action: hash
    options:
      algorithm: sha256
exceptions: []
```

### Rule Options Validation

Policy rule `options` are validated based on the rule `action`:

- mask
  - `mask_char`: string
  - `preserve_first`: integer
  - `preserve_last`: integer
- hash
  - `algorithm`: one of `md5`, `sha1`, `sha256`, `sha512`
  - `max_length`: integer
- tokenize
  - `deterministic`: boolean
  - `token_length`: integer

Invalid or mismatched types will be reported by `PolicyValidator` as errors when loading/validating a policy.

## Performance

- Streams large CSV/text files to avoid memory issues
- Processes multi-GB files efficiently
- DataFrame operations require pandas (in-memory)

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.
