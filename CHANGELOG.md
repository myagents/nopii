# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-10-22

### Added

#### Core Features

- **PII Detection Engine**: Comprehensive detection for emails, phone numbers, credit cards, SSNs, and more
- **Transformation Engine**: Multiple strategies including masking, hashing, tokenization, redaction, and nullification
- **Policy Management System**: YAML-based configuration with rule validation and exception handling
- **Coverage Scoring**: Measure detection effectiveness and policy coverage
- **Audit Reporting**: Detailed reports on PII findings and transformations

#### Streaming

- **Streaming Scan**: CSV and text files are scanned in a streaming fashion (line/row-by-row) to handle large inputs without loading them entirely into memory. CLI and SDK prefer streaming for these formats.

#### CLI Interface

- `nopii scan` - Scan files for PII with configurable output formats
- `nopii transform` - Transform PII from files with various strategies
- `nopii report` - Generate comprehensive coverage and audit reports
- `nopii diff` - Compare files to identify differences after transformation
- `nopii policy` - Validate and manage policy configurations

#### Python SDK

- **Scanner Class**: Programmatic PII detection with confidence scoring
- **TRANSFORM Class**: Text transformation with multiple strategies
- **Policy Class**: Dynamic policy loading and validation
- **Finding Models**: Structured representation of PII detection results

#### Data Integration

- **Pandas Integration**: DataFrame operations for scanning and transformation (optional extra)

#### Core Features

- **Custom Detectors**: Extensible detector framework for custom PII types
- **Multiple Transformations**: Mask, hash, redact, tokenize, and nullify strategies
- **Policy Management**: YAML-based configuration with rules and exceptions
- **Comprehensive Reporting**: HTML, Markdown, and JSON report generation
- **Validation**: Comprehensive input validation and error handling

### Technical Implementation

#### Architecture

- Modular design with clear separation of concerns
- Plugin-based detector system for extensibility
- Policy-driven configuration with YAML support
- Type-safe implementation with comprehensive type hints

#### Performance

- Pragmatic defaults suitable for small to medium datasets

#### Quality Assurance

- Test suite with coverage configuration
- Type checking with mypy
- Code formatting with ruff
- Security scanning with bandit
- Pre-commit hooks for code quality

#### Dependencies

- **Core**: click, pyyaml, pydantic, jinja2, rich, typing-extensions
- **Optional Extras**:
  - `pandas`: pandas, numpy
  - `report-html`: plotly, kaleido, weasyprint
- **Development**: pytest, pytest-cov, ruff, mypy, pre-commit, bandit, vulture, twine, pip-audit

### Documentation

- Comprehensive README with quick start guide
- API documentation with examples
- Policy configuration guide
- Integration tutorials for each supported framework
- Performance optimization guide

### Security

- Secure handling of sensitive data during processing
- No logging of actual PII content
- Configurable audit trail with privacy controls
- Support for cryptographic hashing with salt

### Compatibility

- Python 3.12+ support
- Cross-platform compatibility (Windows, macOS, Linux)
- Backward compatibility for policy configurations

## [Unreleased]

### Planned Features

- **Machine Learning Detectors**: AI-powered PII detection for improved accuracy
- **Real-time Streaming**: Kafka and other streaming platform integrations
- **Cloud Storage**: Direct integration with S3, GCS, and Azure Blob Storage
- **Data Lineage**: Track PII transformations across data pipelines
- **Web UI**: Browser-based interface for policy management and monitoring
- **Enterprise Features**: Role-based access control and centralized policy management

### Known Issues

- Large ZIP archives may require significant memory for processing
- PySpark integration requires Spark 3.0+ for optimal performance
- Some regex patterns may have performance implications on very large texts

### Migration Notes

- This is the initial release, no migration required
- Future versions will maintain backward compatibility for policy files
- API changes will follow semantic versioning guidelines

---

## Release Process

### Version Numbering

- **Major** (X.0.0): Breaking changes to public API
- **Minor** (0.X.0): New features, backward compatible
- **Patch** (0.0.X): Bug fixes, backward compatible

### Release Checklist

- [ ] Update version in `pyproject.toml`
- [ ] Update CHANGELOG.md with release notes
- [ ] Run full test suite
- [ ] Update documentation
- [ ] Create GitHub release
- [ ] Publish to PyPI

### Support Policy

- **Current Release**: Full support with bug fixes and security updates
- **Previous Minor**: Security updates only
- **Older Versions**: Community support only

## Planned Features

The following features are planned for future releases:

### Data Integration (Planned)

- **Polars Integration**: High-performance operations with lazy evaluation support
- **PySpark Integration**: Distributed processing for big data workloads
- **SQLAlchemy Integration**: Direct database table scanning and redaction
- **HTTPX Integration**: API request/response processing with audit trails

### Streaming Support (Planned)

- **File Streamer**: Process large files that don't fit in memory
- **Chunk Processor**: Parallel processing with adaptive worker management
- **Memory Manager**: Automatic memory monitoring and optimization
- **Progress Tracker**: Real-time progress reporting with multiple operation support
- **Compression Support**: Handle gzip, bzip2, lzma, zip, and tar files

### Advanced Features (Planned)

- **Localization Support**: Region-specific detection patterns (US, EU, AU)
- **Async Support**: Asynchronous processing for high-throughput scenarios
- **Caching**: Intelligent caching for improved performance

---

For detailed information about each release, see the [GitHub Releases](https://github.com/ay-mich/nopii/releases) page.
