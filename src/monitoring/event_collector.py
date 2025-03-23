import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import json
import time
import threading
from queue import Queue

class EventCollector:
    def __init__(self):
        """Initialize event collector with local monitoring."""
        self._setup_logging()
        self._setup_storage()
        self.event_queue = Queue()
        self.alerts_queue = Queue()
        self.is_running = False
        self.alert_handlers = []

    def _setup_logging(self):
        """Configure event collector logging."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"event_collector_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("EventCollector")

    def _setup_storage(self):
        """Setup local storage for events and alerts."""
        self.data_dir = Path("data/events")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Files for current events
        self.events_file = self.data_dir / "current_events.jsonl"
        self.alerts_file = self.data_dir / "current_alerts.jsonl"
        
        if not self.events_file.exists():
            self.events_file.touch()
        if not self.alerts_file.exists():
            self.alerts_file.touch()

    def start(self):
        """Start event collection and alert monitoring."""
        self.is_running = True
        
        # Start event processing thread
        self.event_thread = threading.Thread(target=self._process_events)
        self.event_thread.daemon = True
        self.event_thread.start()
        
        # Start alert processing thread
        self.alert_thread = threading.Thread(target=self._process_alerts)
        self.alert_thread.daemon = True
        self.alert_thread.start()
        
        self.logger.info("Event collector started")

    def stop(self):
        """Stop event collection."""
        self.is_running = False
        self.logger.info("Event collector stopped")

    def add_alert_handler(self, handler):
        """Add a callback function for real-time alerts."""
        self.alert_handlers.append(handler)

    def record_event(self, event_type: str, details: Dict[str, Any]):
        """Queue an event for processing."""
        event = {
            "@timestamp": datetime.now().isoformat(),
            "type": event_type,
            **details
        }
        self.event_queue.put(event)

    def record_attack_detection(self, detection_result: Dict[str, Any], network_status: Dict[str, Any]):
        """Record attack detection event with enhanced monitoring."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": detection_result["detected_type"],
            "severity": detection_result.get("severity"),
            "confidence": detection_result["confidence"],
            "anomaly_score": detection_result.get("anomaly_score", 0),
            "alert_triggered": detection_result.get("alert_triggered", False),
            "consecutive_alerts": detection_result.get("consecutive_alerts", 0),
            "network_metrics": {
                "total_bandwidth": network_status["metrics"]["total_bandwidth"],
                "error_rate": network_status["metrics"]["error_rate"],
                "packet_loss_rate": network_status["metrics"]["packet_loss_rate"],
                "latency": network_status["metrics"]["latency"]
            },
            "affected_devices": []
        }

        # Add device-specific information
        for device in network_status["devices"]:
            if device["status"] != "normal":
                event["affected_devices"].append({
                    "id": device["id"],
                    "type": device["type"],
                    "status": device["status"],
                    "metrics": {
                        "cpu_usage": device["metrics"]["cpu_usage"],
                        "memory_usage": device["metrics"]["memory_usage"],
                        "bandwidth_usage": device["metrics"]["bandwidth_usage"],
                        "error_count": device["metrics"]["error_count"]
                    }
                })

        # Queue event and potential alert
        self.event_queue.put(event)
        
        if detection_result.get("alert_triggered", False):
            self.alerts_queue.put(event)

    def _process_events(self):
        """Process events from queue and save to file."""
        while self.is_running:
            try:
                if not self.event_queue.empty():
                    event = self.event_queue.get()
                    
                    # Save to events file
                    with self.events_file.open('a') as f:
                        f.write(json.dumps(event) + '\n')
                    
                    # Rotate file if too large
                    if self.events_file.stat().st_size > 10_000_000:  # 10MB
                        self._rotate_file(self.events_file, "events")
                        
                    self.event_queue.task_done()
                
                time.sleep(0.1)  # Prevent CPU thrashing
                
            except Exception as e:
                self.logger.error(f"Error processing event: {str(e)}")

    def _process_alerts(self):
        """Process alerts from queue and notify handlers."""
        while self.is_running:
            try:
                if not self.alerts_queue.empty():
                    alert = self.alerts_queue.get()
                    
                    # Save to alerts file
                    with self.alerts_file.open('a') as f:
                        f.write(json.dumps(alert) + '\n')
                    
                    # Notify alert handlers
                    for handler in self.alert_handlers:
                        try:
                            handler(alert)
                        except Exception as e:
                            self.logger.error(f"Error in alert handler: {str(e)}")
                    
                    # Print high severity alerts
                    if alert.get("severity") == "high":
                        self.logger.warning(
                            f"\nHIGH SEVERITY ALERT!"
                            f"\nAttack Type: {alert['attack_type']}"
                            f"\nConfidence: {alert['confidence']:.3f}"
                            f"\nAffected Devices: {len(alert['affected_devices'])}"
                        )
                    
                    self.alerts_queue.task_done()
                
                time.sleep(0.1)  # Prevent CPU thrashing
                
            except Exception as e:
                self.logger.error(f"Error processing alert: {str(e)}")

    def _rotate_file(self, file_path: Path, prefix: str):
        """Rotate log file when it gets too large."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_path = self.data_dir / f"{prefix}_{timestamp}.jsonl"
        file_path.rename(new_path)
        file_path.touch()
        self.logger.info(f"Rotated {prefix} file to {new_path}")

    def get_recent_alerts(self, minutes: int = 60) -> List[Dict]:
        """Get recent alerts within the specified time window."""
        cutoff_time = datetime.now().timestamp() - (minutes * 60)
        recent_alerts = []

        # Check current alerts file
        with self.alerts_file.open('r') as f:
            for line in f:
                if line.strip():
                    alert = json.loads(line)
                    if datetime.fromisoformat(alert["timestamp"]).timestamp() > cutoff_time:
                        recent_alerts.append(alert)

        # Check rotated alert files
        for file_path in self.data_dir.glob("alerts_*.jsonl"):
            if file_path.stat().st_mtime > cutoff_time:
                with file_path.open('r') as f:
                    for line in f:
                        if line.strip():
                            alert = json.loads(line)
                            if datetime.fromisoformat(alert["timestamp"]).timestamp() > cutoff_time:
                                recent_alerts.append(alert)

        # Sort by timestamp
        recent_alerts.sort(key=lambda x: x["timestamp"])
        return recent_alerts

    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get statistics about recent alerts."""
        recent_alerts = self.get_recent_alerts(minutes=60)
        
        stats = {
            "total_alerts": len(recent_alerts),
            "by_severity": {"high": 0, "medium": 0, "low": 0},
            "by_type": {},
            "affected_devices": set(),
            "latest_alert": None if not recent_alerts else recent_alerts[-1]
        }
        
        for alert in recent_alerts:
            # Count by severity
            severity = alert.get("severity")
            if severity:
                stats["by_severity"][severity] += 1
            
            # Count by attack type
            attack_type = alert["attack_type"]
            stats["by_type"][attack_type] = stats["by_type"].get(attack_type, 0) + 1
            
            # Track affected devices
            for device in alert["affected_devices"]:
                stats["affected_devices"].add(device["id"])
        
        stats["affected_devices"] = list(stats["affected_devices"])
        return stats