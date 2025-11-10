# TVM Reporter

A comprehensive Python tool for processing Microsoft Defender for Endpoint Threat & Vulnerability Management (TVM) export CSVs and generating structured vulnerability reporting.

## Overview

TVM Reporter ingests four TVM export CSV files and produces:
- Structured CSV reports for remediation planning
- Executive summary PDF
- Risk prioritization analysis
- Device and CVE correlation reports
- Trend analysis (when event data is available)

## Features

- **Automated Schema Normalization**: Handles various TVM export column formats
- **Intelligent Severity Bucketing**: Derives severity from CVSS scores or text
- **Flexible Owner Assignment**: Pattern-based routing for remediation ownership
- **Comprehensive Metrics**: Top CVEs, products, recommendations, and device hotlists
- **Exception Tracking**: Identifies CVEs without recommendations and EOL software
- **Daily Trend Analysis**: Tracks vulnerability trends over time (when events data provided)
- **Configurable SLAs**: Define remediation timelines per severity level

## Project Structure

```
tvm-reporter/
├── app.py                      # Main CLI entry point
├── src/
│   ├── __init__.py            # Package initialization
│   ├── ingest.py              # CSV loading
│   ├── normalize.py           # Schema normalization
│   ├── validate.py            # Data validation
│   ├── model.py               # Data model construction
│   ├── metrics.py             # Metrics computation
│   ├── reports.py             # CSV and PDF generation
│   └── utils.py               # Utility functions
├── config/
│   ├── config.yaml            # Main configuration
│   └── owners.yaml            # Owner assignment rules
├── input/                     # Place input CSV files here
├── output/
│   ├── reports/               # Generated reports (dated folders)
│   └── logs/                  # Execution and validation logs
└── requirements.txt           # Python dependencies
```

## Installation

1. **Clone or download this project**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation**:
   ```bash
   python app.py --help
   ```

## Usage

### Basic Usage

```bash
python app.py \
  --vulns input/vulnerabilities.csv \
  --recs input/recommendations.csv \
  --software input/software_inventory.csv
```

### With Events (for Trend Analysis)

```bash
python app.py \
  --vulns input/vulnerabilities.csv \
  --recs input/recommendations.csv \
  --software input/software_inventory.csv \
  --events input/events.csv
```

### With Custom Configuration

```bash
python app.py \
  --vulns input/vulnerabilities.csv \
  --recs input/recommendations.csv \
  --software input/software_inventory.csv \
  --config config/config.yaml \
  --owners config/owners.yaml \
  --out output
```

### Optional Flags

- `--profile`: Enable profile mode (samples data for quick analysis)
- `--strict`: Enable strict validation (exit on validation errors)
- `--since YYYY-MM-DD`: Only include vulnerabilities detected after specified date

### Example with All Options

```bash
python app.py \
  --vulns input/vulnerabilities.csv \
  --recs input/recommendations.csv \
  --software input/software_inventory.csv \
  --events input/events.csv \
  --config config/config.yaml \
  --owners config/owners.yaml \
  --out output \
  --since 2024-01-01 \
  --strict
```

## Input Requirements

### Required CSV Files

1. **Vulnerabilities** (`--vulns`)
   - Must contain: device information, CVE ID, severity, CVSS, software details
   - Optional: recommendation ID, exposure score, dates

2. **Recommendations** (`--recs`)
   - Must contain: recommendation ID, title
   - Optional: category, severity, affected devices, exposure reduction

3. **Software Inventory** (`--software`)
   - Must contain: device information, product, vendor
   - Optional: version, install date, EOL flag

### Optional CSV Files

4. **Events** (`--events`)
   - For daily trend analysis
   - Must contain: event time, device name
   - Optional: severity, recommendation ID, CVE

## Output Reports

All reports are generated in dated folders: `output/reports/YYYY-MM-DD/`

### CSV Reports

1. **Remediation_Plan.csv**
   - Critical and High severity vulnerabilities
   - Owner assignments
   - SLA days per severity

2. **CVE_By_Device.csv**
   - Devices grouped with their CVEs
   - Severity counts per device

3. **Device_By_CVE.csv**
   - CVEs grouped with affected devices
   - Device counts and product details

4. **Software_Risk_Priorities.csv**
   - Software risk scoring
   - Aggregated vulnerability counts
   - EOL status

5. **Datasets_Profile.csv**
   - Summary statistics
   - Total counts and severity distribution

### PDF Report

**Executive_Snapshot.pdf**
- Summary metrics
- Top 10 CVEs by device impact
- Top 10 products with Critical/High CVEs
- Top recommendations
- Device hotlist
- Exception summary
- Trend analysis (if events provided)

## Configuration

### config/config.yaml

Key configuration sections:

```yaml
report:
  top_n: 10  # Number of items in top lists

sla_days:
  critical: 7
  high: 30
  medium: 90
  low: 180

severity_scoring:
  critical_threshold: 9.0
  high_threshold: 7.0
  medium_threshold: 4.0

exposure_buckets:
  very_high: 80
  high: 60
  medium: 30
  low: 1
```

### config/owners.yaml

Define owner assignment rules:

```yaml
default_owner: "Security Team"

patterns:
  - product_pattern: "windows"
    vendor_pattern: "microsoft"
    owner: "Windows Infrastructure Team"

  - product_pattern: "apache"
    vendor_pattern: ""
    owner: "Web Infrastructure Team"
```

## Column Normalization

TVM Reporter automatically normalizes various column header formats:

- Converts to lowercase
- Removes punctuation
- Collapses whitespace to underscores
- Maps known aliases to canonical names

### Supported Aliases Examples

- `deviceid`, `machineid` → `device_id`
- `cveid`, `vulnerability_id` → `cve`
- `severity_level`, `risk_level` → `severity`
- `product_name`, `productname` → `product`

## Data Model

### Fact Tables

1. **VulnDevice** - Vulnerabilities joined with software and recommendations
2. **SoftwareDevice** - Software inventory with vulnerability counts

### Dimension Tables

1. **Rec** - Recommendations dimension

### Linkage

- Vulnerabilities ↔ Software: device_key + software_key
- Vulnerabilities ↔ Recommendations: recommendation_id or product/vendor fallback
- Events ↔ Vulnerabilities: CVE or recommendation_id

## Validation

The tool performs comprehensive validation:

- Required column checks
- Duplicate detection and removal
- Data quality assessment
- Null value reporting

Validation logs are written to: `output/logs/validation_TIMESTAMP.csv`

### Strict Mode

Use `--strict` flag to exit with error code if validation fails.

## Logging

Execution logs are written to: `output/logs/tvm_reporter_TIMESTAMP.log`

Log levels:
- INFO: Standard execution flow
- WARNING: Missing optional data or quality issues
- ERROR: Critical failures

Configure log level in `config/config.yaml`:

```yaml
logging:
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR
```

## Troubleshooting

### Common Issues

1. **Missing columns error**
   - Check that your CSV headers match expected formats
   - Review column alias mappings in normalize.py
   - Add custom mappings in config.yaml

2. **PDF generation fails**
   - Ensure reportlab is installed: `pip install reportlab`
   - Check output directory permissions

3. **Date parsing warnings**
   - Dates should be in standard formats (YYYY-MM-DD, MM/DD/YYYY, etc.)
   - Invalid dates are logged but don't stop execution

4. **Memory issues with large datasets**
   - Use `--profile` flag for sampling
   - Process data in chunks externally before import

## Performance

- Typical execution time: 30-60 seconds for 100K vulnerability records
- Memory usage: ~500MB-1GB for standard datasets
- Use `--profile` mode for quick analysis of large datasets

## Requirements

- Python 3.7+
- pandas
- PyYAML
- reportlab (for PDF generation)

## License

This project is provided as-is for internal security operations use.

## Support

For issues, questions, or feature requests, contact the Security Operations team.

## Version History

- **1.0.0** - Initial release
  - Core TVM export processing
  - CSV and PDF report generation
  - Owner assignment and SLA tracking
  - Trend analysis support
