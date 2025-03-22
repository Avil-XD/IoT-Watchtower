import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import json
import requests
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError

class EventCollector:
    def __init__(self, es_host: str = "localhost", es_port: int = 9200):
        """Initialize event collector with Elasticsearch connection."""
        self._setup_logging()
        self.es_host = es_host
        self.es_port = es_port
        self.es = None
        self.fallback_file = Path("logs/events_backup.jsonl")
        self.connect_elasticsearch()

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

    def connect_elasticsearch(self):
        """Establish connection to Elasticsearch."""
        try:
            self.es = Elasticsearch([{
                'host': self.es_host,
                'port': self.es_port,
                'scheme': 'http'
            }])
            
            if not self.es.ping():
                raise ConnectionError("Failed to connect to Elasticsearch")
                
            self.setup_indices()
            self.logger.info("Successfully connected to Elasticsearch")
            
        except Exception as e:
            self.logger.warning(f"Failed to connect to Elasticsearch: {str(e)}")
            self.logger.info("Events will be stored in local file")
            self.es = None

    def setup_indices(self):
        """Create and configure Elasticsearch indices."""
        if not self.es:
            return

        # Load index mappings
        try:
            with open("src/config/elasticsearch_mappings.json", 'r') as f:
                mappings = json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load index mappings: {str(e)}")
            return

        indices = ['iot-events', 'iot-attacks', 'iot-metrics']
        
        for index in indices:
            if not self.es.indices.exists(index=index):
                try:
                    self.es.indices.create(
                        index=index,
                        body=mappings,
                        ignore=400
                    )
                    self.logger.info(f"Created index: {index}")
                except Exception as e:
                    self.logger.error(f"Failed to create index {index}: {str(e)}")

    def collect_event(self, event_type: str, data: Dict[str, Any], 
                     source: Optional[str] = None, target: Optional[str] = None):
        """Collect and store an event."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "source": source,
            "target": target,
            "details": data
        }

        if self.es:
            try:
                # Determine index based on event type
                if event_type.startswith('attack'):
                    index = 'iot-attacks'
                elif event_type.startswith('metric'):
                    index = 'iot-metrics'
                else:
                    index = 'iot-events'

                self.es.index(
                    index=index,
                    body=event,
                    refresh=True
                )
                self.logger.debug(f"Event stored in Elasticsearch: {event_type}")
                
            except Exception as e:
                self.logger.error(f"Failed to store event in Elasticsearch: {str(e)}")
                self._store_local_backup(event)
        else:
            self._store_local_backup(event)

    def _store_local_backup(self, event: Dict[str, Any]):
        """Store event in local backup file."""
        try:
            self.fallback_file.parent.mkdir(exist_ok=True)
            with open(self.fallback_file, 'a') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to store event in backup file: {str(e)}")

    def get_events(self, event_type: Optional[str] = None, 
                  start_time: Optional[str] = None,
                  end_time: Optional[str] = None,
                  size: int = 100) -> list:
        """Retrieve events from storage."""
        if not self.es:
            return self._get_local_events(event_type)

        query = {"query": {"bool": {"must": []}}}
        
        if event_type:
            query["query"]["bool"]["must"].append(
                {"match": {"event_type": event_type}}
            )
            
        if start_time or end_time:
            range_query = {"range": {"timestamp": {}}}
            if start_time:
                range_query["range"]["timestamp"]["gte"] = start_time
            if end_time:
                range_query["range"]["timestamp"]["lte"] = end_time
            query["query"]["bool"]["must"].append(range_query)

        try:
            result = self.es.search(
                body=query,
                size=size,
                sort={"timestamp": "desc"}
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve events from Elasticsearch: {str(e)}")
            return self._get_local_events(event_type)

    def _get_local_events(self, event_type: Optional[str] = None) -> list:
        """Retrieve events from local backup file."""
        events = []
        try:
            if self.fallback_file.exists():
                with open(self.fallback_file, 'r') as f:
                    for line in f:
                        event = json.loads(line)
                        if not event_type or event["event_type"] == event_type:
                            events.append(event)
        except Exception as e:
            self.logger.error(f"Failed to read events from backup file: {str(e)}")
        
        return events

    def clear_local_backup(self):
        """Clear the local backup file after successful upload to Elasticsearch."""
        try:
            if self.fallback_file.exists():
                self.fallback_file.unlink()
                self.logger.info("Local backup file cleared")
        except Exception as e:
            self.logger.error(f"Failed to clear backup file: {str(e)}")

    def upload_backup_to_elasticsearch(self):
        """Upload events from backup file to Elasticsearch."""
        if not self.es or not self.fallback_file.exists():
            return

        try:
            with open(self.fallback_file, 'r') as f:
                for line in f:
                    event = json.loads(line)
                    self.collect_event(
                        event["event_type"],
                        event["details"],
                        event.get("source"),
                        event.get("target")
                    )
            
            self.clear_local_backup()
            
        except Exception as e:
            self.logger.error(f"Failed to upload backup to Elasticsearch: {str(e)}")

if __name__ == "__main__":
    # Test event collector
    collector = EventCollector()
    
    test_event = {
        "cpu_usage": 75.5,
        "memory_usage": 60.2,
        "bandwidth_usage": 45.8,
        "error_count": 2
    }
    
    collector.collect_event(
        event_type="device_metrics",
        data=test_event,
        source="device_001"
    )