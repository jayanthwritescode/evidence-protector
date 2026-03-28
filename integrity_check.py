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
        parser.add_argument('--visual', action='store_true',
                          help='Show ASCII timeline visualization')
        parser.add_argument('--quiet', action='store_true',
                          help='Suppress output except summary insights')
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
    
    def get_safe_windows(self) -> List[Dict]:
        """Get safe windows from config."""
        return self.config.get('safe_windows', [])
    
    def get_visual(self) -> bool:
        """Get visual timeline flag."""
        return self.args.visual
    
    def get_quiet(self) -> bool:
        """Get quiet mode flag."""
        return self.args.quiet


class ParsingLayer:
    """Handles memory-efficient line-by-line log parsing."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.malformed_count = 0
        
    def parse_timestamp(self, line: str) -> Optional[datetime]:
        """Extract timestamp from log line using auto-detection."""
        try:
            # Get tokens from line
            tokens = line.strip().split(None, 2)
            if len(tokens) < 2:
                return None
            
            # Try different timestamp formats
            formats_to_try = [
                # Legacy: 081109 203615 (first two tokens)
                (f"{tokens[0]} {tokens[1]}", "%y%m%d %H%M%S"),
                # ISO 8601: 2024-01-15T20:36:17 (first token)
                (tokens[0], "%Y-%m-%dT%H:%M:%S"),
                # ISO with space: 2024-01-15 20:36:17 (first two tokens)
                (f"{tokens[0]} {tokens[1]}", "%Y-%m-%d %H:%M:%S"),
            ]
            
            for timestamp_str, fmt in formats_to_try:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            
            return None
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
    
    def __init__(self, threshold: int, severity_multipliers: Dict[str, int] = None, safe_windows: List[Dict] = None):
        self.threshold = threshold
        self.multipliers = severity_multipliers or {'low': 5, 'medium': 20}
        self.safe_windows = safe_windows or []
        
    def parse_safe_window_time(self, time_str: str) -> Optional[datetime.time]:
        """Parse time string from safe window config."""
        try:
            return datetime.strptime(time_str, "%H:%M:%S").time()
        except ValueError:
            return None
    
    def is_in_safe_window(self, timestamp: datetime) -> bool:
        """Check if timestamp falls within any safe window."""
        time_only = timestamp.time()
        
        for window in self.safe_windows:
            start_time = self.parse_safe_window_time(window.get('start', ''))
            end_time = self.parse_safe_window_time(window.get('end', ''))
            
            if start_time and end_time:
                if start_time <= end_time:
                    # Normal window (same day)
                    if start_time <= time_only <= end_time:
                        return True
                else:
                    # Overnight window (e.g., 22:00 to 02:00)
                    if time_only >= start_time or time_only <= end_time:
                        return True
        
        return False
    
    def is_gap_in_safe_window(self, gap_start: datetime, gap_end: datetime) -> bool:
        """Check if entire gap falls within a single safe window."""
        for window in self.safe_windows:
            start_time = self.parse_safe_window_time(window.get('start', ''))
            end_time = self.parse_safe_window_time(window.get('end', ''))
            
            if start_time and end_time:
                # Check if both gap start and end times are within this window
                start_in_window = self.is_time_in_window(gap_start.time(), start_time, end_time)
                end_in_window = self.is_time_in_window(gap_end.time(), start_time, end_time)
                
                if start_in_window and end_in_window:
                    return True
        
        return False
    
    def is_time_in_window(self, time_to_check: datetime.time, window_start: datetime.time, window_end: datetime.time) -> bool:
        """Check if a time falls within a window (handles overnight windows)."""
        if window_start <= window_end:
            # Normal window (same day)
            return window_start <= time_to_check <= window_end
        else:
            # Overnight window (e.g., 22:00 to 02:00)
            return time_to_check >= window_start or time_to_check <= window_end
        
    def classify_severity(self, gap_seconds: int) -> str:
        """Classify gap severity based on threshold multiples."""
        if gap_seconds <= self.multipliers['low'] * self.threshold:
            return "LOW"
        elif gap_seconds <= self.multipliers['medium'] * self.threshold:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def detect_gaps(self, timestamps: Iterator[datetime]) -> List[Dict]:
        """Detect time gaps between consecutive timestamps."""
        gaps = []
        prev_timestamp = None
        suppressed_count = 0
        
        for timestamp in timestamps:
            if prev_timestamp is not None:
                gap_seconds = int((timestamp - prev_timestamp).total_seconds())
                if gap_seconds > self.threshold:
                    # Check if gap is in safe window
                    if self.safe_windows and self.is_gap_in_safe_window(prev_timestamp, timestamp):
                        suppressed_count += 1
                    else:
                        gap_info = {
                            'start': prev_timestamp,
                            'end': timestamp,
                            'duration': gap_seconds,
                            'severity': self.classify_severity(gap_seconds)
                        }
                        gaps.append(gap_info)
            prev_timestamp = timestamp
        
        # Add suppressed count to first gap for reporting
        if gaps and suppressed_count > 0:
            gaps[0]['suppressed_gaps'] = suppressed_count
            
        return gaps


class ReportingLayer:
    """Generates clean forensic reports and exports data."""
    
    @staticmethod
    def print_summary_insights(gaps: List[Dict], file_path: str, threshold: int):
        """Print analyst-focused summary insights."""
        if not gaps:
            print(f"✓ Clean: No gaps detected in {file_path}")
            return
        
        # Check for suppressed gaps
        suppressed_count = 0
        if gaps and 'suppressed_gaps' in gaps[0]:
            suppressed_count = gaps[0]['suppressed_gaps']
            del gaps[0]['suppressed_gaps']  # Clean up the data
        
        # Find most suspicious gap (longest duration)
        most_suspicious = max(gaps, key=lambda g: g['duration'])
        
        # Format time window
        start_time = most_suspicious['start'].strftime("%H:%M")
        end_time = most_suspicious['end'].strftime("%H:%M")
        duration = most_suspicious['duration']
        severity = most_suspicious['severity']
        
        print(f"⚠ Most suspicious window: {start_time}-{end_time} ({severity}, {duration}s). "
              f"Recommend investigating user activity in this period.")
        
        # Additional context for multiple gaps
        total_gap_time = sum(gap['duration'] for gap in gaps)
        if len(gaps) > 1:
            print(f"⚠ Found {len(gaps)} gaps totaling {total_gap_time}s of missing activity")
        
        # Safe windows suppression info
        if suppressed_count > 0:
            print(f"ℹ Suppressed {suppressed_count} gaps falling within scheduled maintenance windows")
    
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
    
    @staticmethod
    def print_timeline(gaps: List[Dict], start_time: datetime, end_time: datetime):
        """Print ASCII timeline visualization of gaps."""
        timeline_width = 60
        total_seconds = int((end_time - start_time).total_seconds())
        
        if total_seconds == 0:
            print("Timeline: Insufficient data for visualization")
            return
        
        # Create timeline character array
        timeline = ['-'] * timeline_width
        
        # Track gap positions for inline labels
        gap_positions = []
        
        # Mark gaps on timeline
        for gap in gaps:
            gap_start_offset = int((gap['start'] - start_time).total_seconds())
            gap_end_offset = int((gap['end'] - start_time).total_seconds())
            
            # Convert to timeline positions
            start_pos = int((gap_start_offset * timeline_width) / total_seconds)
            end_pos = int((gap_end_offset * timeline_width) / total_seconds)
            
            # Ensure positions are within bounds
            start_pos = max(0, min(start_pos, timeline_width - 1))
            end_pos = max(0, min(end_pos, timeline_width - 1))
            
            # Create inline label with duration
            duration_str = f"GAP:{gap['severity']} {gap['duration']}s"
            
            # Try to fit the label in the gap
            available_space = end_pos - start_pos - 2  # Account for brackets
            
            if available_space >= len(duration_str):
                # Full label fits
                timeline[start_pos] = '['
                for i, char in enumerate(duration_str):
                    if start_pos + 1 + i < timeline_width:
                        timeline[start_pos + 1 + i] = char
                if end_pos < timeline_width:
                    timeline[end_pos] = ']'
                gap_positions.append((start_pos, duration_str))
            elif available_space >= 8:  # Minimum for "GAP:X Ys"
                # Shortened label
                short_label = f"G:{gap['severity'][0]} {gap['duration']}s"
                timeline[start_pos] = '['
                for i, char in enumerate(short_label):
                    if start_pos + 1 + i < timeline_width:
                        timeline[start_pos + 1 + i] = char
                if end_pos < timeline_width:
                    timeline[end_pos] = ']'
                gap_positions.append((start_pos, short_label))
            else:
                # Just mark with severity letter
                timeline[start_pos] = '['
                if start_pos + 1 < timeline_width:
                    timeline[start_pos + 1] = gap['severity'][0]  # L, M, H
                if end_pos > start_pos + 2 and end_pos < timeline_width:
                    timeline[end_pos] = ']'
                gap_positions.append((start_pos, gap['severity'][0]))
        
        # Format timestamps
        start_str = start_time.strftime("%H:%M:%S")
        end_str = end_time.strftime("%H:%M:%S")
        
        # Build timeline string
        timeline_str = ''.join(timeline)
        
        # Print timeline
        print("\nTIMELINE VISUALIZATION:")
        print("-" * 80)
        print(f"{start_str} {timeline_str} {end_str}")
        
        # Print gap annotations for any that might be unclear
        annotations = []
        for pos, label in gap_positions:
            if isinstance(label, str) and len(label) > 3:  # Only annotate complex labels
                annotations.append(label)
        
        if annotations:
            print("Gap markers:", " ".join(annotations))
        
        print("-" * 80)


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
        visual_flag = input_layer.get_visual()
        quiet_flag = input_layer.get_quiet()
        severity_multipliers = input_layer.get_severity_multipliers()
        safe_windows = input_layer.get_safe_windows()
        
        # Layer 2: Parsing
        parsing_layer = ParsingLayer(file_path)
        
        # Collect all timestamps for both detection and timeline
        all_timestamps = []
        timestamps_iter = parsing_layer.iter_timestamps()
        for ts in timestamps_iter:
            all_timestamps.append(ts)
        
        # Layer 3: Detection
        detection_engine = DetectionEngine(threshold, severity_multipliers, safe_windows)
        gaps = detection_engine.detect_gaps(iter(all_timestamps))
        
        # Get start and end times for timeline
        if all_timestamps:
            start_time = all_timestamps[0]
            end_time = all_timestamps[-1]
        else:
            start_time = end_time = None
        
        # Layer 4: Reporting
        if not quiet_flag:
            ReportingLayer.print_report(
                gaps=gaps,
                malformed_count=parsing_layer.get_malformed_count(),
                file_path=file_path,
                threshold=threshold
            )
        
        # Visual timeline if requested and not quiet
        if visual_flag and not quiet_flag and start_time and end_time:
            ReportingLayer.print_timeline(gaps, start_time, end_time)
        
        # Always print summary insights (even in quiet mode)
        ReportingLayer.print_summary_insights(gaps, file_path, threshold)
        
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
        
        # Exit code: 1 if gaps found, 0 if clean
        return 1 if gaps else 0
        
    except FileNotFoundError as e:
        ErrorHandling.handle_file_not_found(file_path)
    except Exception as e:
        ErrorHandling.handle_parsing_error(e, file_path if 'file_path' in locals() else "unknown")


if __name__ == "__main__":
    exit(main())
