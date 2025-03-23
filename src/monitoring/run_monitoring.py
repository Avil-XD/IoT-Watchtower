#!/usr/bin/env python3
import sys
import time
import os
from pathlib import Path
from datetime import datetime
import logging
from typing import Dict, Any

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from data.event_collector import EventCollector
from ml.attack_detector import AttackDetector

class ConsoleMonitor:
    def __init__(self):
        """Initialize the console-based monitoring system."""
        self._setup_logging()
        self.event_collector = EventCollector()
        self.attack_detector = AttackDetector()

    def _setup_logging(self):
        """Configure monitoring-specific logging."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"monitoring_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("Monitoring")

    def clear_screen(self):
        """Clear the console screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_header(self):
        """Print monitoring dashboard header."""
        print("=" * 80)
        print("IoT Security Monitoring Dashboard")
        print(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)

    def print_stats(self, stats: Dict[str, Any]):
        """Print current monitoring statistics."""
        print("\nAlert Statistics:")
        print(f"Total Alerts: {stats['total_alerts']}")
        
        if stats['severity_distribution']:
            print("\nSeverity Distribution:")
            for severity, count in stats['severity_distribution'].items():
                print(f"  {severity.upper()}: {count}")
        
        if stats['attack_types']:
            print("\nAttack Types:")
            for attack_type, count in stats['attack_types'].items():
                print(f"  {attack_type}: {count}")
        
        if stats['recent_alerts']:
            print("\nRecent Alerts:")
            for alert in stats['recent_alerts']:
                print(f"\n  Time: {alert['timestamp']}")
                print(f"  Type: {alert['details'].get('attack_type', 'Unknown')}")
                print(f"  Severity: {alert['severity']}")
                print(f"  Confidence: {alert['confidence']:.2f}")

    def run_monitoring(self, refresh_interval: float = 1.0):
        """Run the monitoring dashboard with real-time updates."""
        self.logger.info("Starting IoT security monitoring system...")
        print("\nPress Ctrl+C to stop monitoring...")
        time.sleep(2)  # Give time to read the message

        try:
            while True:
                # Simulate getting current network status
                network_status = {
                    "metrics": {
                        "total_bandwidth": 1500.0,  # kbps
                        "latency": 25.0,           # ms
                        "packet_loss_rate": 0.01,  # 1%
                        "error_rate": 0.005        # 0.5%
                    },
                    "devices": [
                        {
                            "id": "camera_01",
                            "type": "SmartCamera",
                            "status": "active",
                            "metrics": {
                                "cpu_usage": 45.5,
                                "memory_usage": 60.2,
                                "bandwidth_usage": 750.0,
                                "packet_count": 1000,
                                "error_count": 5
                            }
                        },
                        {
                            "id": "lock_01",
                            "type": "SmartLock",
                            "status": "active",
                            "metrics": {
                                "cpu_usage": 15.5,
                                "memory_usage": 30.2,
                                "bandwidth_usage": 50.0,
                                "packet_count": 100,
                                "error_count": 0
                            }
                        }
                    ]
                }

                # Detect potential attacks
                detection_result = self.attack_detector.detect(network_status)
                
                # Store alert if attack detected
                if detection_result["is_attack"]:
                    self.event_collector.collect_event(
                        event_type="security_alert",
                        data={
                            "attack_type": detection_result["detected_type"],
                            "network_status": network_status
                        },
                        severity=detection_result["severity"],
                        confidence=detection_result["confidence"],
                        anomaly_score=detection_result["anomaly_score"]
                    )
                
                # Update console display
                self.clear_screen()
                self.print_header()
                stats = self.event_collector.get_alert_stats()
                self.print_stats(stats)
                
                time.sleep(refresh_interval)

        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
            print("\nMonitoring stopped. Check logs for full history.")
        except Exception as e:
            self.logger.error(f"Monitoring failed: {str(e)}")
            raise

def main():
    """Start the monitoring system."""
    monitor = ConsoleMonitor()
    monitor.run_monitoring()

if __name__ == "__main__":
    main()