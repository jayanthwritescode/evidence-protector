# Evidence Protector

A Python tool for analyzing log file integrity, detecting time gaps, malformed entries, and potential evidence tampering.

## Features

- **Time Gap Detection**: Identifies significant gaps between log entries (200s, 600s, 1500s thresholds)
- **Malformed Entry Detection**: Flags entries with missing timestamps, garbled text, or invalid format
- **Duplicate Detection**: Finds duplicate log entries using hash comparison
- **File Integrity**: Calculates SHA-256 checksums for verification
- **Configurable Analysis**: Customizable thresholds and detection rules
- **Comprehensive Reporting**: JSON reports with detailed findings

## Project Structure

```
evidence-protector/
├── integrity_check.py    # Main analysis script
├── config.json          # Configuration settings
├── sample.log           # Sample log file with test data
└── README.md           # This documentation
```

## Log Format

The tool expects logs in the following format:
```
YYMMDD HHMMSS PID LEVEL COMPONENT: MESSAGE
```

Example:
```
081109 203615 148 INFO Authentication: User login successful for admin
```

## Installation

No external dependencies required. Uses Python 3 standard library only.

```bash
# Make the script executable
chmod +x integrity_check.py
```

## Usage

### Basic Usage

```bash
# Analyze the sample log file
python3 integrity_check.py sample.log

# Or make it executable and run directly
./integrity_check.py sample.log
```

### Advanced Usage

```bash
# Use custom configuration
python3 integrity_check.py -c custom_config.json sample.log

# Save report to specific file
python3 integrity_check.py -o my_report.json sample.log

# Verbose output
python3 integrity_check.py -v sample.log
```

### Command Line Options

- `log_file`: Path to the log file to analyze (default: sample.log)
- `-c, --config`: Path to configuration file (default: config.json)
- `-o, --output`: Output report file (default: integrity_report.json)
- `-v, --verbose`: Enable verbose output

## Configuration

The `config.json` file allows customization of:

```json
{
  "log_file": "sample.log",
  "timestamp_format": "YYMMDD HHMMSS",
  "time_gap_thresholds": {
    "warning": 60,
    "critical": 300,
    "severe": 1200
  },
  "integrity_checks": {
    "detect_gaps": true,
    "detect_malformed": true,
    "detect_duplicates": true,
    "validate_timestamps": true
  },
  "output": {
    "verbose": false,
    "save_report": true,
    "report_file": "integrity_report.json"
  },
  "security": {
    "calculate_checksum": true,
    "backup_original": true
  }
}
```

### Time Gap Thresholds

- **Warning**: Gaps exceeding 60 seconds
- **Critical**: Gaps exceeding 300 seconds (5 minutes)
- **Severe**: Gaps exceeding 1200 seconds (20 minutes)

## Sample Log Analysis

The included `sample.log` contains:
- 30 realistic log entries
- 3 deliberate time gaps (200s, 600s, 1500s)
- 2 malformed entries for testing error handling

Run the analysis to see how the tool detects these issues:

```bash
python3 integrity_check.py sample.log
```

Expected output will show:
- Time gaps detected at the specified intervals
- Malformed entries flagged with appropriate error messages
- Summary statistics and file integrity information

## Output

The tool generates:

1. **Console Summary**: Human-readable summary of findings
2. **JSON Report**: Detailed analysis report saved to file (default: `integrity_report.json`)

### Report Structure

```json
{
  "analysis_timestamp": "2026-03-28T...",
  "log_file": "sample.log",
  "file_checksum": "sha256_hash...",
  "total_lines": 32,
  "valid_entries": 30,
  "malformed_entries": 2,
  "issues": {
    "time_gaps": [...],
    "duplicates": [...],
    "malformed_entries": [...]
  },
  "summary": {
    "critical_issues": 2,
    "warnings": 1,
    "malformed_count": 2
  }
}
```

## Error Handling

The tool gracefully handles:
- Missing or invalid timestamps
- Malformed log structure
- File encoding issues
- Configuration errors
- Missing log files

## Security Features

- **Checksum Verification**: SHA-256 hashes for file integrity
- **Non-destructive**: Read-only analysis, no modification of original logs
- **Encoding Support**: Handles UTF-8 and Latin-1 encoded files

## Use Cases

- **Digital Forensics**: Verify log file integrity in investigations
- **Security Auditing**: Detect potential log tampering or gaps
- **System Monitoring**: Identify unusual logging patterns
- **Compliance**: Ensure continuous logging for regulatory requirements

## License

This project is provided as-is for educational and forensic analysis purposes.

## Contributing

Feel free to submit issues or enhancement requests for additional log formats or analysis features.
