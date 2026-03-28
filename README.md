# Evidence Protector

Modular log integrity checker for forensic analysis.

## Installation

No installation required. Uses Python standard library only.

```bash
# Make executable (optional)
chmod +x integrity_check.py
```

## Usage Examples

### Basic Analysis
```bash
python integrity_check.py --file sample.log --threshold 60
```

### With Export
```bash
python integrity_check.py --file sample.log --threshold 60 --export json
# Creates: gaps_report.json with metadata and gap details

python integrity_check.py --file sample.log --threshold 60 --export csv  
# Creates: gaps_report.csv with columns: start, end, duration_seconds, severity
```

### With Configuration
```bash
python integrity_check.py --file sample.log --config config.json
# Uses config.json settings (threshold, export, severity_multipliers)
```

### With Visual Timeline
```bash
python integrity_check.py --file sample.log --visual
# Shows ASCII timeline visualization of gaps
```

### Combined Options
```bash
python integrity_check.py --file sample.log --threshold 30 --export csv --visual
# Custom threshold, CSV export, and timeline visualization
```

## Command Line Options

- `--file`: Path to log file (required)
- `--threshold`: Time gap threshold in seconds (default: 60)
- `--export`: Export format - csv or json (optional)
- `--visual`: Show ASCII timeline visualization (flag)
- `--config`: Configuration file path (default: config.json)

## Configuration File

```json
{
  "threshold": 60,
  "export": "json",
  "severity_multipliers": {
    "low": 5,
    "medium": 20
  }
}
```

CLI arguments override configuration file values.

## Log Format

Expected format: `YYMMDD HHMMSS PID LEVEL COMPONENT: MESSAGE`

Example: `081109 203615 148 INFO Authentication: User login successful`

## Architecture Note

### 5-Layer Modular Design

1. **InputLayer**: CLI argument parsing and configuration loading
2. **ParsingLayer**: Memory-efficient line-by-line log parsing
3. **DetectionEngine**: Time gap detection and severity classification
4. **ReportingLayer**: Forensic reports and data export
5. **ErrorHandling**: Centralized error management

### Data Flow
```
file -> parser -> detector -> reporter -> stdout/file
```

### Error Handling Strategy
- **Skip-and-count**: Malformed lines are silently counted, never crash
- **Graceful degradation**: Missing config files use defaults
- **Encoding fallback**: UTF-8 → Latin-1 on decode errors
- **Never aborts**: Continues analysis despite individual line failures

## Design Rationale

### Why Line-by-Line Processing?
**Memory efficiency** for large log files. Forensic logs can be gigabytes; loading entire files into memory is impractical in field environments.

### Why Standard Library Only?
**Zero dependencies**. Forensic environments are typically locked down systems without internet access or package managers. Standard library ensures maximum compatibility.

### Tradeoffs and Limitations
- **Assumes chronological order**: Processes timestamps sequentially. Out-of-order logs may produce inaccurate gap detection.
- **Single timestamp format**: Only supports `%y%m%d %H%M%S` format for consistency.
- **Memory tradeoff for visual mode**: Visual timeline collects all timestamps in memory to provide accurate gap positioning. This trades memory for timeline accuracy. Non-visual mode maintains true streaming behavior.

### User Value
**Actionable output for analysts under time pressure**. Clear forensic reports with:
- Immediate gap detection with severity classification
- Multiple export formats for integration with other tools
- Visual timeline for quick assessment
- Silent error handling that doesn't interrupt workflow

## Output Formats

### Console Report
```
================================================================================
LOG INTEGRITY FORENSIC REPORT
================================================================================
File Scanned: sample.log
Threshold Used: 60 seconds

TIME GAPS DETECTED:
--------------------------------------------------------------------------------
Start Time           End Time             Duration (s)    Severity      
--------------------------------------------------------------------------------
2008-11-09 20:36:32  2008-11-09 20:39:12  160             LOW           
2008-11-09 20:39:20  2008-11-09 20:51:12  712             MEDIUM        
2008-11-09 20:51:24  2008-11-09 22:50:24  7140            HIGH          

================================================================================
SUMMARY:
  Total Gaps Detected: 3
  Total Malformed Lines: 2
  File Scanned: sample.log
  Threshold Used: 60 seconds
================================================================================
```

### Visual Timeline
```
TIMELINE VISUALIZATION:
--------------------------------------------------------------------------------
20:36:15 [[M---[H-------------------------------------------------------------] 22:50:44
Gap markers: [GAP:MEDIUM] [GAP:HIGH]
--------------------------------------------------------------------------------
```

### CSV Export
```csv
start,end,duration_seconds,severity
2008-11-09 20:36:32,2008-11-09 20:39:12,160,LOW
2008-11-09 20:39:20,2008-11-09 20:51:12,712,MEDIUM
2008-11-09 20:51:24,2008-11-09 22:50:24,7140,HIGH
```

### JSON Export
```json
{
  "metadata": {
    "file": "sample.log",
    "threshold": 60,
    "total_gaps": 3,
    "malformed_lines": 2
  },
  "gaps": [
    {
      "start": "2008-11-09 20:36:32",
      "end": "2008-11-09 20:39:12", 
      "duration_seconds": 160,
      "severity": "LOW"
    }
  ]
}
```

## Severity Classification

Based on threshold multiples:
- **LOW**: threshold to 5× threshold
- **MEDIUM**: 5× to 20× threshold
- **HIGH**: beyond 20× threshold

Configurable via `severity_multipliers` in config.json.

## Use Cases

- **Digital Forensics**: Verify log file integrity in investigations
- **Security Auditing**: Detect potential log tampering or gaps
- **System Monitoring**: Identify unusual logging patterns
- **Compliance**: Ensure continuous logging for regulatory requirements
- **Incident Response**: Quick assessment of log completeness during breaches
