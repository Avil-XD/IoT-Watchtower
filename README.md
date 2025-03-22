# IoT Security Simulation Project

A comprehensive IoT network security simulation with attack detection and monitoring capabilities.

## Features

- IoT network simulation with multiple device types
- Real-time network metrics and device monitoring
- Attack simulation (Botnet, DDoS, MitM)
- Machine learning-based attack detection
- Elasticsearch and Grafana integration for visualization
- Docker-based monitoring infrastructure

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/iot-security-simulation.git
cd iot-security-simulation
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install Docker and Docker Compose for monitoring infrastructure:
- [Docker Installation Guide](https://docs.docker.com/get-docker/)
- [Docker Compose Installation Guide](https://docs.docker.com/compose/install/)

## Usage

### Running the IoT Network Simulation

1. Start the base simulation:
```bash
python src/main.py
```

2. Run an attack test:
```bash
python src/test_attack.py
```

### Setting Up Monitoring

1. Start the monitoring stack:
```bash
docker-compose up -d
```

2. Access Grafana:
- Open http://localhost:3000 in your browser
- Login with admin/iotsecurity
- The IoT Security Dashboard will be automatically loaded

For detailed monitoring setup instructions, see [monitoring_setup.md](monitoring_setup.md).

### Training the Attack Classifier

1. Collect training data:
```bash
python src/ml/collect_training_data.py
```

This will:
- Run the network simulation
- Collect normal behavior data
- Simulate various attacks
- Store all data in Elasticsearch
- Train an initial model

2. Monitor training progress in Grafana:
- Open the "ML Training" dashboard
- View data collection metrics
- Monitor model performance

## Project Structure

```
src/
├── config/               # Configuration files
├── data/                # Data collection and storage
├── ml/                  # Machine learning components
├── monitoring/          # Monitoring setup
├── simulation/          # IoT network simulation
└── test/                # Test scripts
```

## Machine Learning Components

### Data Collection

The system collects the following metrics for ML training:
- Network-level metrics (bandwidth, latency, error rates)
- Device-level metrics (CPU, memory, packet counts)
- Attack events and patterns
- Security-related events

### Model Training

The attack classifier uses:
- Random Forest algorithm
- Feature scaling and preprocessing
- Cross-validation for model evaluation
- Real-time prediction capabilities

### Model Deployment

Trained models are:
- Automatically saved with timestamps
- Version controlled
- Hot-reloadable
- Monitored for performance

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Elasticsearch for data storage
- Grafana for visualization
- Scikit-learn for machine learning
- Docker for containerization