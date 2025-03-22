# Setting Up the Monitoring Infrastructure

## Prerequisites

1. Install Docker and Docker Compose:
   - Windows: Download and install Docker Desktop from https://www.docker.com/products/docker-desktop
   - Linux: Follow instructions at https://docs.docker.com/engine/install/
   - MacOS: Download and install Docker Desktop from https://www.docker.com/products/docker-desktop

## Starting the Monitoring Stack

1. Start the Elasticsearch and Grafana containers:
```bash
docker-compose up -d
```

2. Wait for services to initialize (about 1-2 minutes)

3. Access Grafana:
   - Open browser: http://localhost:3000
   - Login credentials:
     - Username: admin
     - Password: iotsecurity

4. Configure Elasticsearch data source in Grafana:
   - Go to Configuration > Data Sources
   - Click "Add data source"
   - Select "Elasticsearch"
   - Set URL to: http://elasticsearch:9200
   - Click "Save & Test"

## Monitoring Dashboard

The IoT Security Dashboard will be automatically loaded and includes:
- Network Error Rate monitoring
- Device CPU Usage heatmap
- Network Bandwidth Usage trends
- Recent Attack Events table
- Attack Origin Map
- Attack Type Distribution

## Elasticsearch Indices

The system uses the following indices:
- iot-events: Device and network events
- iot-attacks: Attack detection and classification results
- iot-metrics: Performance and health metrics

## Troubleshooting

1. If Elasticsearch fails to start:
```bash
# Check container logs
docker logs iot_elasticsearch

# Adjust virtual memory settings (Linux):
sudo sysctl -w vm.max_map_count=262144
```

2. If Grafana dashboard doesn't load:
```bash
# Restart Grafana container
docker restart iot_grafana

# Check dashboard provisioning
docker exec iot_grafana ls /etc/grafana/provisioning/dashboards
```

3. If data isn't showing up:
```bash
# Check Elasticsearch indices
curl http://localhost:9200/_cat/indices

# Verify index mappings
curl http://localhost:9200/iot-events/_mapping
```

## Maintenance

1. Backup Elasticsearch data:
```bash
# Create snapshot repository
curl -X PUT "localhost:9200/_snapshot/backup?pretty" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/usr/share/elasticsearch/backups"
  }
}'

# Create snapshot
curl -X PUT "localhost:9200/_snapshot/backup/snapshot_1?wait_for_completion=true"
```

2. Clean up old data:
```bash
# Delete indices older than 30 days
curl -X POST "localhost:9200/iot-events-*,-iot-events-current/_delete_by_query" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "timestamp": {
        "lt": "now-30d"
      }
    }
  }
}'
```

## Stopping the Monitoring Stack

To stop all services:
```bash
docker-compose down
```

To stop and remove all data:
```bash
docker-compose down -v