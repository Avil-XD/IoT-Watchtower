import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

class EventCollector:
    def __init__(self):
        """Initialize event collector with local file storage."""
        self._setup_logging()
        
        # Setup storage paths
        self.base_dir = Path("data")
        self.events_dir = self.base_dir / "events"
        self.alerts_file = self.events_dir / "current_alerts.jsonl"
        self.events_file = self.events_dir / "current_events.jsonl"
        
        # Create directories
        self.events_dir.mkdir(parents=True, exist_ok=True)
        
        # Create empty files if they don't exist
        self.alerts_file.touch()
        self.events_file.touch()

    def _setup_logging(self):
        """Configure logging for the event collector."""
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

    def _store_event(self, event: Dict[str, Any], is_alert: bool = False):
        """Store event in appropriate file."""
        try:
            target_file = self.alerts_file if is_alert else self.events_file
            with open(target_file, 'a') as f:
                f.write(json.dumps(event) + '\n')
            self.logger.debug(f"Event stored: {event['event_type']}")
        except Exception as e:
            self.logger.error(f"Failed to store event: {str(e)}")
            raise

    def collect_event(self, event_type: str, data: Dict[str, Any],
                     source: Optional[str] = None, target: Optional[str] = None,
                     severity: Optional[str] = None, confidence: Optional[float] = None,
                     anomaly_score: Optional[float] = None):
        """Collect and store an event with enhanced metadata."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "source": source,
            "target": target,
            "severity": severity,
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "alert_triggered": bool(severity and severity != "normal"),
            "consecutive_alerts": data.get("consecutive_alerts", 0),
            "details": data
        }
        
        # Store as alert if it's a security event with severity
        is_alert = event_type == "security_alert" and severity is not None
        self._store_event(event, is_alert)
        
        # Log alerts immediately
        if is_alert:
            self.logger.warning(
                f"\nALERT: {severity.upper()} severity attack detected!"
                f"\nType: {data.get('attack_type', 'Unknown')}"
                f"\nConfidence: {confidence:.2f}"
                f"\nSource: {source or 'Unknown'}"
                f"\nTarget: {target or 'Unknown'}"
            )

    def get_events(self, event_type: Optional[str] = None,
                   start_time: Optional[str] = None,
                   end_time: Optional[str] = None,
                   size: int = 100) -> list:
        """Retrieve events from local file storage."""
        events = []
        try:
            if self.events_file.exists():
                with open(self.events_file, 'r') as f:
                    for line in f:
                        event = json.loads(line)
                        if event_type and event["event_type"] != event_type:
                            continue
                        if start_time and event["timestamp"] < start_time:
                            continue
                        if end_time and event["timestamp"] > end_time:
                            continue
                        events.append(event)
        except Exception as e:
            self.logger.error(f"Failed to read events from file: {str(e)}")
        
        # Sort by timestamp descending and limit size
        events.sort(key=lambda x: x["timestamp"], reverse=True)
        return events[:size]

    def get_alert_stats(self) -> Dict[str, Any]:
        """Get real-time statistics about alerts."""
        alerts = []
        try:
            if self.alerts_file.exists():
                with open(self.alerts_file, 'r') as f:
                    alerts = [json.loads(line) for line in f]
        except Exception as e:
            self.logger.error(f"Failed to read alerts: {str(e)}")
            return {
                "total_alerts": 0,
                "severity_distribution": {},
                "attack_types": {},
                "recent_alerts": []
            }

        if not alerts:
            return {
                "total_alerts": 0,
                "severity_distribution": {},
                "attack_types": {},
                "recent_alerts": []
            }

        # Calculate statistics
        severity_dist = {}
        attack_types = {}
        for alert in alerts:
            severity = alert.get("severity", "unknown")
            attack_type = alert.get("details", {}).get("attack_type", "unknown")
            
            severity_dist[severity] = severity_dist.get(severity, 0) + 1
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

        # Sort alerts by timestamp descending
        alerts.sort(key=lambda x: x["timestamp"], reverse=True)

        return {
            "total_alerts": len(alerts),
            "severity_distribution": severity_dist,
            "attack_types": attack_types,
            "recent_alerts": alerts[:5]  # Last 5 alerts
        }