#!/usr/bin/env python3
"""
Evidence Protector - Modular Log Integrity Checker
Layered architecture for forensic log analysis.
"""

import argparse
import csv
import json
import sys
from datetime import datetime
from typing import Iterator, Optional, Dict, List


class InputLayer:
    """Handles command line arguments and configuration loading."""
    
    def __init__(self):
        self.args = self._parse_arguments()
        self.config = self._load_config()
        
    def _parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(
            description='Modular Log Integrity Checker',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument('--file', required=True, 
                          help='Path to the log file to analyze')
        parser.add_argument('--threshold', type=int, default=60,
                          help='Time gap threshold in seconds (default: 60)')
        parser.add_argument('--export', choices=['csv', 'json'],
                          help='Export format: csv or json')
        parser.add_argument('--config', 
                          help='Path to configuration file (default: config.json)')
        return parser.parse_args()
    
    def _load_config(self) -> Dict:
        """Load configuration from JSON file if provided."""
        config_file = self.args.config or 'config.json'
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Override defaults with command line args
                if self.args.threshold != 60:
                    config['threshold'] = self.args.threshold
                if self.args.export:
                    config['export'] = self.args.export
                return config
        except FileNotFoundError:
            # Config file is optional
            config = {'threshold': self.args.threshold}
            if self.args.export:
                config['export'] = self.args.export
            return config
        except json.JSONDecodeError as e:
            print(f"Warning: Invalid JSON in config file: {e}", file=sys.stderr)
            config = {'threshold': self.args.threshold}
            if self.args.export:
                config['export'] = self.args.export
            return config
    
    def get_file_path(self) -> str:
        """Get the log file path."""
        return self.args.file
    
    def get_threshold(self) -> int:
        """Get the time gap threshold."""
        return self.config.get('threshold', self.args.threshold)
    
    def get_export_format(self) -> Optional[str]:
        """Get the export format."""
        return self.config.get('export')
    
    def get_severity_multipliers(self) -> Dict[str, int]:
        """Get severity multipliers from config."""
        return self.config.get('severity_multipliers', {'low': 5, 'medium': 20})


class ParsingLayer:
    """Handles memory-efficient line-by-line log parsing."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.malformed_count = 0
        
    def parse_timestamp(self, line: str) -> Optional[datetime]:
        """Extract timestamp from log line using %y%m%d %H%M%S format."""
        try:
            # Get first two space-separated tokens
            tokens = line.strip().split(None, 2)
            if len(tokens) < 2:
                return None
            
            timestamp_str = f"{tokens[0]} {tokens[1]}"
            # Parse using %y%m%d %H%M%S format
            return datetime.strptime(timestamp_str, "%y%m%d %H%M%S")
        except (ValueError, IndexError):
            return None
    
    def iter_timestamps(self) -> Iterator[datetime]:
        """Iterate over valid timestamps from the log file."""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    timestamp = self.parse_timestamp(line)
                    if timestamp:
                        yield timestamp
                    else:
                        self.malformed_count += 1
                        # Silent skip - count only
        except FileNotFoundError:
            print(f"Error: File not found: {self.file_path}", file=sys.stderr)
            raise
        except UnicodeDecodeError:
            # Try with different encoding
            try:
                with open(self.file_path, 'r', encoding='latin-1') as f:
                    for line_num, line in enumerate(f, 1):
                        timestamp = self.parse_timestamp(line)
                        if timestamp:
                            yield timestamp
                        else:
                            self.malformed_count += 1
            except Exception as e:
                print(f"Error reading file: {e}", file=sys.stderr)
                raise
        except Exception as e:
            print(f"Unexpected error parsing file: {e}", file=sys.stderr)
            raise
    
    def get_malformed_count(self) -> int:
        """Get the count of malformed lines."""
        return self.malformed_count


class DetectionEngine:
    """Detects time gaps and classifies severity."""
    
    def __init__(self, threshold: int, severity_multipliers: Dict[str, int] = None):
        self.threshold = threshold
        self.multipliers = severity_multipliers or {'low': 5, 'medium': 20}
        
    def classify_severity(self, gap_seconds: int) -> str:
        """Classify gap severity based on threshold multiples."""
        if gap_seconds <= self.threshold:
            return "LOW"
        elif gap_seconds <= self.multipliers['low'] * self.threshold:
            return "LOW"
        elif gap_seconds <= self.multipliers['medium'] * self.threshold:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def detect_gaps(self, timestamps: Iterator[datetime]) -> List[Dict]:
        """Detect time gaps between consecutive timestamps."""
        gaps = []
        prev_timestamp = None
        
        for timestamp in timestamps:
            if prev_timestamp is not None:
                gap_seconds = int((timestamp - prev_timestamp).total_seconds())
                if gap_seconds > self.threshold:
                    gap_info = {
                        'start': prev_timestamp,
                        'end': timestamp,
                        'duration': gap_seconds,
                        'severity': self.classify_severity(gap_seconds)
                    }
                    gaps.append(gap_info)
            prev_timestamp = timestamp
            
        return gaps


class ReportingLayer:
    """Generates clean forensic reports and exports data."""
    
    @staticmethod
    def print_report(gaps: List[Dict], malformed_count: int, 
                     file_path: str, threshold: int):
        """Print forensic report to stdout."""
        print("=" * 80)
        print("LOG INTEGRITY FORENSIC REPORT")
        print("=" * 80)
        print(f"File Scanned: {file_path}")
        print(f"Threshold Used: {threshold} seconds")
        print()
        
        if not gaps:
            print("No time gaps detected.")
        else:
            print("TIME GAPS DETECTED:")
            print("-" * 80)
            print(f"{'Start Time':<20} {'End Time':<20} {'Duration (s)':<15} {'Severity':<10}")
            print("-" * 80)
            
            for gap in gaps:
                start_str = gap['start'].strftime("%Y-%m-%d %H:%M:%S")
                end_str = gap['end'].strftime("%Y-%m-%d %H:%M:%S")
                print(f"{start_str:<20} {end_str:<20} {gap['duration']:<15} {gap['severity']:<10}")
        
        print()
        print("=" * 80)
        print("SUMMARY:")
        print(f"  Total Gaps Detected: {len(gaps)}")
        print(f"  Total Malformed Lines: {malformed_count}")
        print(f"  File Scanned: {file_path}")
        print(f"  Threshold Used: {threshold} seconds")
        print("=" * 80)
    
    @staticmethod
    def export_csv(gaps: List[Dict], filename: str = "gaps_report.csv"):
        """Export gaps to CSV format."""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['start', 'end', 'duration_seconds', 'severity']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for gap in gaps:
                    writer.writerow({
                        'start': gap['start'].strftime("%Y-%m-%d %H:%M:%S"),
                        'end': gap['end'].strftime("%Y-%m-%d %H:%M:%S"),
                        'duration_seconds': gap['duration'],
                        'severity': gap['severity']
                    })
            print(f"CSV report exported to: {filename}", file=sys.stderr)
        except Exception as e:
            print(f"Error exporting CSV: {e}", file=sys.stderr)
    
    @staticmethod
    def export_json(gaps: List[Dict], metadata: Dict, filename: str = "gaps_report.json"):
        """Export gaps to JSON format with metadata."""
        try:
            report_data = {
                'metadata': metadata,
                'gaps': []
            }
            
            for gap in gaps:
                gap_data = {
                    'start': gap['start'].strftime("%Y-%m-%d %H:%M:%S"),
                    'end': gap['end'].strftime("%Y-%m-%d %H:%M:%S"),
                    'duration_seconds': gap['duration'],
                    'severity': gap['severity']
                }
                report_data['gaps'].append(gap_data)
            
            with open(filename, 'w', encoding='utf-8') as jsonfile:
                json.dump(report_data, jsonfile, indent=2)
            print(f"JSON report exported to: {filename}", file=sys.stderr)
        except Exception as e:
            print(f"Error exporting JSON: {e}", file=sys.stderr)


class ErrorHandling:
    """Centralized error handling."""
    
    @staticmethod
    def handle_file_not_found(file_path: str):
        """Handle file not found errors."""
        print(f"FATAL: Log file not found: {file_path}", file=sys.stderr)
        sys.exit(1)
    
    @staticmethod
    def handle_parsing_error(error: Exception, file_path: str):
        """Handle parsing errors."""
        print(f"FATAL: Error parsing file {file_path}: {error}", file=sys.stderr)
        sys.exit(1)
    
    @staticmethod
    def handle_config_error(error: Exception):
        """Handle configuration errors."""
        print(f"WARNING: Configuration error: {error}", file=sys.stderr)


def main():
    """Main execution function."""
    try:
        # Layer 1: Input
        input_layer = InputLayer()
        file_path = input_layer.get_file_path()
        threshold = input_layer.get_threshold()
        export_format = input_layer.get_export_format()
        severity_multipliers = input_layer.get_severity_multipliers()
        
        # Layer 2: Parsing
        parsing_layer = ParsingLayer(file_path)
        
        # Layer 3: Detection
        detection_engine = DetectionEngine(threshold, severity_multipliers)
        timestamps = parsing_layer.iter_timestamps()
        gaps = detection_engine.detect_gaps(timestamps)
        
        # Layer 4: Reporting
        ReportingLayer.print_report(
            gaps=gaps,
            malformed_count=parsing_layer.get_malformed_count(),
            file_path=file_path,
            threshold=threshold
        )
        
        # Export if requested
        if export_format:
            metadata = {
                'file': file_path,
                'threshold': threshold,
                'total_gaps': len(gaps),
                'malformed_lines': parsing_layer.get_malformed_count()
            }
            
            if export_format == 'csv':
                ReportingLayer.export_csv(gaps)
            elif export_format == 'json':
                ReportingLayer.export_json(gaps, metadata)
        
    except FileNotFoundError as e:
        ErrorHandling.handle_file_not_found(file_path)
    except Exception as e:
        ErrorHandling.handle_parsing_error(e, file_path if 'file_path' in locals() else "unknown")


if __name__ == "__main__":
    main()
