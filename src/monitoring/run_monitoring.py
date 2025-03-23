import logging
from datetime import datetime
from pathlib import Path
import threading
from dashboard import MonitoringDashboard
from event_collector import EventCollector

class SecurityMonitoring:
    def __init__(self):
        """Initialize the security monitoring system."""
        self._setup_logging()
        self.dashboard = MonitoringDashboard()
        self.event_collector = EventCollector(es_host="localhost", es_port=9200)
        self.is_running = False

    def _setup_logging(self):
        """Configure monitoring-specific logging."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"dashboard_runner_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("SecurityMonitoring")

    def update_dashboard(self):
        """Update dashboard with latest events from Elasticsearch."""
        while self.is_running:
            try:
                # Get recent attacks from Elasticsearch
                recent_attacks = self.event_collector.get_recent_attacks(minutes=60)
                
                # Update dashboard data
                for attack in recent_attacks:
                    # Convert Elasticsearch document to dashboard format
                    network_status = {
                        "metrics": attack.get("metrics", {}),
                        "devices": []
                    }
                    
                    # Extract device metrics
                    for key, value in attack.items():
                        if key.startswith("device_"):
                            device_id = key.replace("device_", "")
                            network_status["devices"].append({
                                "id": device_id,
                                "metrics": value
                            })
                    
                    # Update dashboard with attack data
                    # Enhanced detection result with severity and patterns
                    detection_result = {
                        "detected_type": attack.get("attack_type"),
                        "confidence": attack.get("confidence"),
                        "is_attack": True,
                        "severity": attack.get("severity"),
                        "anomaly_score": attack.get("anomaly_score", 0),
                        "alert_triggered": attack.get("alert_triggered", False)
                    }

                    # Get attack patterns if available
                    if "attack_patterns" in attack:
                        detection_result["attack_patterns"] = attack["attack_patterns"]
                    
                    # Get severity distribution if available
                    if "severity_distribution" in attack:
                        detection_result["severity_distribution"] = attack["severity_distribution"]

                    # Update dashboard with enhanced attack data
                    self.dashboard.update_data(network_status, detection_result)

                    # Log high severity alerts
                    if detection_result["alert_triggered"] and detection_result["severity"] == "high":
                        self.logger.warning(
                            f"High severity {detection_result['detected_type']} attack detected! "
                            f"Anomaly score: {detection_result['anomaly_score']:.3f}"
                        )
                
            except Exception as e:
                self.logger.error(f"Error updating dashboard: {str(e)}")
            
            import time
            time.sleep(5)  # Update every 5 seconds

    def start(self):
        """Start the monitoring system."""
        try:
            self.is_running = True
            self.logger.info("Starting security monitoring system...")

            # Start dashboard update thread
            update_thread = threading.Thread(target=self.update_dashboard)
            update_thread.daemon = True
            update_thread.start()

            # Start dashboard server
            self.dashboard.run(host="localhost", port=8050, debug=False)

        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {str(e)}")
            self.stop()
            raise

    def stop(self):
        """Stop the monitoring system."""
        self.is_running = False
        self.logger.info("Security monitoring system stopped")

if __name__ == "__main__":
    monitoring = SecurityMonitoring()
    
    try:
        monitoring.start()
    except KeyboardInterrupt:
        print("\nReceived shutdown signal")
        monitoring.stop()
    except Exception as e:
        print(f"\nError during monitoring: {str(e)}")
        monitoring.stop()
        raise