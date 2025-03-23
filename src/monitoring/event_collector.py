import logging
from datetime import datetime
from pathlib import Path
from elasticsearch import Elasticsearch
from typing import Dict, Any

class EventCollector:
    def __init__(self, es_host: str = "localhost", es_port: int = 9200):
        """Initialize event collector with Elasticsearch connection."""
        self._setup_logging()
        self.es = Elasticsearch([f"http://{es_host}:{es_port}"])
        self._create_index_if_not_exists()

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

    def _create_index_if_not_exists(self):
        """Create Elasticsearch index with proper mappings if it doesn't exist."""
        index_name = "iot-attacks"
        if not self.es.indices.exists(index=index_name):
            mappings = {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "type": {"type": "keyword"},
                        "attack_type": {"type": "keyword"},
                        "target": {"type": "keyword"},
                        "confidence": {"type": "float"},
                        "blocked": {"type": "boolean"},
                        "metrics": {
                            "properties": {
                                "cpu_usage": {"type": "float"},
                                "memory_usage": {"type": "float"},
                                "bandwidth_usage": {"type": "float"},
                                "error_count": {"type": "integer"},
                                "packet_count": {"type": "integer"}
                            }
                        }
                    }
                }
            }
            self.es.indices.create(index=index_name, body=mappings)
            self.logger.info(f"Created Elasticsearch index: {index_name}")

    def record_event(self, event_type: str, details: Dict[str, Any]):
        """Record an event to Elasticsearch."""
        document = {
            "@timestamp": datetime.now().isoformat(),
            "type": event_type,
            **details
        }

        try:
            self.es.index(index="iot-attacks", body=document)
            self.logger.info(f"Recorded {event_type} event: {details.get('attack_type', 'N/A')}")
        except Exception as e:
            self.logger.error(f"Failed to record event: {str(e)}")

    def record_attack_detection(self, detection_result: Dict[str, Any], network_status: Dict[str, Any]):
        """Record attack detection event with network status."""
        event = {
            "attack_type": detection_result["prediction"],
            "confidence": detection_result["confidence"],
            "blocked": detection_result["confidence"] > 0.8,  # Auto-block high confidence attacks
            "metrics": {
                "total_bandwidth": network_status["metrics"]["total_bandwidth"],
                "error_rate": network_status["metrics"]["error_rate"],
                "packet_loss_rate": network_status["metrics"]["packet_loss_rate"],
                "latency": network_status["metrics"]["latency"]
            }
        }

        # Add device-specific metrics
        for device in network_status["devices"]:
            device_metrics = device["metrics"]
            event[f"device_{device['id']}"] = {
                "cpu_usage": device_metrics["cpu_usage"],
                "memory_usage": device_metrics["memory_usage"],
                "bandwidth_usage": device_metrics["bandwidth_usage"],
                "error_count": device_metrics["error_count"],
                "packet_count": device_metrics["packet_count"]
            }

        self.record_event("attack_detection", event)

    def get_recent_attacks(self, minutes: int = 60) -> list:
        """Get recent attack events from Elasticsearch."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"type": "attack_detection"}},
                        {"range": {
                            "@timestamp": {
                                "gte": f"now-{minutes}m",
                                "lte": "now"
                            }
                        }}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }

        try:
            results = self.es.search(index="iot-attacks", body=query)
            return [hit["_source"] for hit in results["hits"]["hits"]]
        except Exception as e:
            self.logger.error(f"Failed to fetch recent attacks: {str(e)}")
            return []