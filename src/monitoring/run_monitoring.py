import logging
from datetime import datetime
from pathlib import Path
import threading
import time
import json
from typing import Dict, Any
import os
from event_collector import EventCollector

class ConsoleMonitor:
    def __init__(self):
        """Initialize the console-based monitoring system."""
        self._setup_logging()
        self.event_collector = EventCollector()
        self.is_running = False
        
        # Display settings
        self.refresh_rate = 2  # seconds
        self.alert_colors = {
            "high": "\033[91m",    # Red
            "medium": "\033[93m",  # Yellow
            "low": "\033[94m",     # Blue
            "reset": "\033[0m"     # Reset
        }

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
        self.logger = logging.getLogger("SecurityMonitoring")

    def _clear_screen(self):
        """Clear console screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def _print_header(self):
        """Print monitoring dashboard header."""
        self._clear_screen()
        print("=" * 80)
        print("IoT Security Monitoring Dashboard")
        print(f"Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)

    def _print_alert(self, alert: Dict[str, Any]):
        """Print formatted alert information."""
        severity = alert.get("severity", "low")
        color = self.alert_colors.get(severity, "")
        reset = self.alert_colors["reset"]
        
        print(f"\n{color}[{severity.upper()} Priority Alert]{reset}")
        print(f"Type: {alert['attack_type']}")
        print(f"Confidence: {alert['confidence']:.3f}")
        print(f"Anomaly Score: {alert.get('anomaly_score', 'N/A')}")
        print(f"Affected Devices: {len(alert['affected_devices'])}")
        print("-" * 40)

    def _update_display(self):
        """Update console display with current monitoring information."""
        while self.is_running:
            try:
                # Get current statistics
                stats = self.event_collector.get_alert_statistics()
                recent_alerts = self.event_collector.get_recent_alerts(minutes=5)
                
                # Update display
                self._print_header()
                
                # Print alert statistics
                print("\nAlert Statistics (Last 60 minutes):")
                print(f"Total Alerts: {stats['total_alerts']}")
                print("\nBy Severity:")
                for severity, count in stats["by_severity"].items():
                    color = self.alert_colors.get(severity, "")
                    reset = self.alert_colors["reset"]
                    print(f"{color}{severity.title()}: {count}{reset}")
                
                print("\nBy Attack Type:")
                for attack_type, count in stats["by_type"].items():
                    print(f"{attack_type}: {count}")
                
                print(f"\nAffected Devices: {len(stats['affected_devices'])}")
                
                # Print recent alerts
                if recent_alerts:
                    print("\nRecent Alerts (Last 5 minutes):")
                    for alert in recent_alerts[-5:]:  # Show last 5 alerts
                        self._print_alert(alert)
                
                time.sleep(self.refresh_rate)
                
            except Exception as e:
                self.logger.error(f"Display update error: {str(e)}")
                time.sleep(self.refresh_rate)

    def handle_alert(self, alert: Dict[str, Any]):
        """Handle new alerts from event collector."""
        try:
            severity = alert.get("severity", "low")
            self.logger.warning(
                f"\n{self.alert_colors[severity]}New Alert Detected!"
                f"\nType: {alert['attack_type']}"
                f"\nSeverity: {severity.upper()}"
                f"\nConfidence: {alert['confidence']:.3f}"
                f"\nAffected Devices: {len(alert['affected_devices'])}"
                f"{self.alert_colors['reset']}"
            )
        except Exception as e:
            self.logger.error(f"Alert handling error: {str(e)}")

    def start(self):
        """Start the monitoring system."""
        try:
            self.is_running = True
            self.logger.info("Starting security monitoring system...")

            # Register alert handler
            self.event_collector.add_alert_handler(self.handle_alert)
            
            # Start event collector
            self.event_collector.start()

            # Start display update thread
            display_thread = threading.Thread(target=self._update_display)
            display_thread.daemon = True
            display_thread.start()

            # Keep main thread running
            while self.is_running:
                try:
                    time.sleep(1)
                except KeyboardInterrupt:
                    break

        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {str(e)}")
            self.stop()
            raise
        finally:
            if self.is_running:
                self.stop()

    def stop(self):
        """Stop the monitoring system."""
        self.is_running = False
        self.event_collector.stop()
        self.logger.info("Security monitoring system stopped")

if __name__ == "__main__":
    monitor = ConsoleMonitor()
    try:
        monitor.start()
    except KeyboardInterrupt:
        print("\nReceived shutdown signal")
    finally:
        monitor.stop()