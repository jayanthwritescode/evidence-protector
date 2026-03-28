#!/usr/bin/env python3
"""
Evidence Protector - Log Integrity Checker
Analyzes log files for time gaps, malformed entries, and integrity issues.
"""

import json
import re
import hashlib
import os
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import argparse


class LogIntegrityChecker:
    def __init__(self, config_file: str = "config.json"):
        """Initialize the integrity checker with configuration."""
        self.config = self.load_config(config_file)
        self.issues = []
        self.valid_entries = []
        self.malformed_entries = []
        
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Configuration file {config_file} not found!")
            return {}
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in configuration file: {e}")
            return {}
    
    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp string according to configured format."""
        try:
            # Handle YYMMDD HHMMSS format
            if len(timestamp_str) == 13 and timestamp_str[6] == ' ':
                date_part = timestamp_str[:6]
                time_part = timestamp_str[7:]
                
                # Convert YY to 4-digit year (assuming 2000s)
                year = 2000 + int(date_part[:2])
                month = int(date_part[2:4])
                day = int(date_part[4:6])
                
                hour = int(time_part[:2])
                minute = int(time_part[2:4])
                second = int(time_part[4:6])
                
                return datetime(year, month, day, hour, minute, second)
            else:
                return None
        except (ValueError, IndexError):
            return None
    
    def parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse a single log line and extract components."""
        line = line.strip()
        if not line:
            return None
            
        # Expected format: YYMMDD HHMMSS PID LEVEL COMPONENT: MESSAGE
        pattern = r'^(\d{6} \d{6})\s+(\d+)\s+(\w+)\s+([^:]+):\s+(.*)$'
        match = re.match(pattern, line)
        
        if match:
            timestamp_str, pid, level, component, message = match.groups()
            timestamp = self.parse_timestamp(timestamp_str)
            
            if timestamp:
                return {
                    'timestamp': timestamp,
                    'timestamp_str': timestamp_str,
                    'pid': pid,
                    'level': level,
                    'component': component,
                    'message': message,
                    'raw_line': line
                }
            else:
                self.malformed_entries.append({
                    'line': line,
                    'issue': 'Invalid timestamp format'
                })
                return None
        else:
            # Check for specific malformed patterns
            if not re.match(r'^\d{6} \d{6}', line):
                self.malformed_entries.append({
                    'line': line,
                    'issue': 'Missing or invalid timestamp'
                })
            else:
                self.malformed_entries.append({
                    'line': line,
                    'issue': 'Malformed log structure'
                })
            return None
    
    def detect_time_gaps(self) -> List[Dict]:
        """Detect significant time gaps between consecutive log entries."""
        gaps = []
        thresholds = self.config.get('time_gap_thresholds', {
            'warning': 60, 'critical': 300, 'severe': 1200
        })
        
        for i in range(1, len(self.valid_entries)):
            prev_time = self.valid_entries[i-1]['timestamp']
            curr_time = self.valid_entries[i]['timestamp']
            gap_seconds = (curr_time - prev_time).total_seconds()
            
            if gap_seconds > thresholds['warning']:
                severity = 'warning'
                if gap_seconds > thresholds['severe']:
                    severity = 'severe'
                elif gap_seconds > thresholds['critical']:
                    severity = 'critical'
                
                gaps.append({
                    'from_line': i,
                    'to_line': i + 1,
                    'gap_seconds': gap_seconds,
                    'severity': severity,
                    'from_timestamp': prev_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'to_timestamp': curr_time.strftime('%Y-%m-%d %H:%M:%S')
                })
        
        return gaps
    
    def detect_duplicates(self) -> List[Dict]:
        """Detect duplicate log entries."""
        seen_lines = set()
        duplicates = []
        
        for i, entry in enumerate(self.valid_entries):
            line_hash = hashlib.md5(entry['raw_line'].encode()).hexdigest()
            if line_hash in seen_lines:
                duplicates.append({
                    'line_number': i + 1,
                    'duplicate_line': entry['raw_line'],
                    'hash': line_hash
                })
            else:
                seen_lines.add(line_hash)
        
        return duplicates
    
    def calculate_file_checksum(self, filepath: str) -> str:
        """Calculate SHA-256 checksum of the log file."""
        hash_sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except FileNotFoundError:
            return ""
    
    def analyze_log_file(self, filepath: str) -> Dict:
        """Perform comprehensive analysis of the log file."""
        if not os.path.exists(filepath):
            return {'error': f'Log file {filepath} not found'}
        
        # Read and parse log file
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except UnicodeDecodeError:
            with open(filepath, 'r', encoding='latin-1') as f:
                lines = f.readlines()
        
        # Parse each line
        for line_num, line in enumerate(lines, 1):
            parsed = self.parse_log_line(line)
            if parsed:
                parsed['line_number'] = line_num
                self.valid_entries.append(parsed)
        
        # Perform integrity checks
        time_gaps = self.detect_time_gaps() if self.config.get('integrity_checks', {}).get('detect_gaps', True) else []
        duplicates = self.detect_duplicates() if self.config.get('integrity_checks', {}).get('detect_duplicates', True) else []
        
        # Calculate file checksum
        checksum = self.calculate_file_checksum(filepath) if self.config.get('security', {}).get('calculate_checksum', True) else ""
        
        # Generate report
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'log_file': filepath,
            'file_checksum': checksum,
            'total_lines': len(lines),
            'valid_entries': len(self.valid_entries),
            'malformed_entries': len(self.malformed_entries),
            'issues': {
                'time_gaps': time_gaps,
                'duplicates': duplicates,
                'malformed_entries': self.malformed_entries
            },
            'summary': {
                'critical_issues': len([g for g in time_gaps if g['severity'] in ['critical', 'severe']]),
                'warnings': len([g for g in time_gaps if g['severity'] == 'warning']) + len(duplicates),
                'malformed_count': len(self.malformed_entries)
            }
        }
        
        return report
    
    def save_report(self, report: Dict, output_file: str = None):
        """Save analysis report to JSON file."""
        if output_file is None:
            output_file = self.config.get('output', {}).get('report_file', 'integrity_report.json')
        
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"Report saved to {output_file}")
        except Exception as e:
            print(f"Error saving report: {e}")
    
    def print_summary(self, report: Dict):
        """Print a summary of the analysis results."""
        print("\n" + "="*60)
        print("LOG INTEGRITY ANALYSIS SUMMARY")
        print("="*60)
        print(f"Log file: {report['log_file']}")
        print(f"Total lines: {report['total_lines']}")
        print(f"Valid entries: {report['valid_entries']}")
        print(f"Malformed entries: {report['malformed_entries']}")
        
        if report['file_checksum']:
            print(f"File checksum: {report['file_checksum'][:16]}...")
        
        summary = report['summary']
        print(f"\nCritical issues: {summary['critical_issues']}")
        print(f"Warnings: {summary['warnings']}")
        print(f"Malformed lines: {summary['malformed_count']}")
        
        # Show time gaps
        if report['issues']['time_gaps']:
            print(f"\nTime gaps detected ({len(report['issues']['time_gaps'])}):")
            for gap in report['issues']['time_gaps']:
                print(f"  {gap['severity'].upper()}: {gap['gap_seconds']:.0f}s gap "
                      f"between line {gap['from_line']} and {gap['to_line']}")
        
        # Show malformed entries
        if report['issues']['malformed_entries']:
            print(f"\nMalformed entries ({len(report['issues']['malformed_entries'])}):")
            for i, entry in enumerate(report['issues']['malformed_entries'][:5]):
                print(f"  - {entry['issue']}: {entry['line'][:50]}...")
            if len(report['issues']['malformed_entries']) > 5:
                print(f"  ... and {len(report['issues']['malformed_entries']) - 5} more")
        
        print("="*60)


def main():
    parser = argparse.ArgumentParser(description='Log Integrity Checker')
    parser.add_argument('log_file', nargs='?', default='sample.log', 
                       help='Path to the log file to analyze')
    parser.add_argument('-c', '--config', default='config.json',
                       help='Path to configuration file')
    parser.add_argument('-o', '--output', help='Output report file')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    checker = LogIntegrityChecker(args.config)
    report = checker.analyze_log_file(args.log_file)
    
    if 'error' in report:
        print(f"Error: {report['error']}")
        return 1
    
    checker.print_summary(report)
    
    if args.config and checker.config.get('output', {}).get('save_report', True):
        checker.save_report(report, args.output)
    
    return 0


if __name__ == "__main__":
    exit(main())
