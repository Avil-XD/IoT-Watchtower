"""
IoT Attack Detection System
==========================

A simplified system for simulating and detecting IoT network attacks using machine learning.

Project Structure:
src/
├── simulation/          # Attack simulation
│   ├── network.py          # IoT network simulation
│   └── attack_simulator.py # Attack generation and execution
│
├── ml/                 # Machine Learning
│   ├── attack_classifier.py    # ML model implementation
│   ├── attack_detector.py      # Real-time attack detection
│   ├── collect_training_data.py# Training data collection
│   └── train_model.py         # Model training script
│
├── monitoring/         # Event monitoring
│   ├── event_collector.py     # Event logging and storage
│   └── run_monitoring.py      # Monitoring system
│
└── run_attack_simulation.py   # Main simulation runner

Usage:
1. Collect Training Data:
   ```
   python src/ml/collect_training_data.py
   ```

2. Train Detection Model:
   ```
   python src/ml/train_model.py
   ```

3. Start Monitoring:
   ```
   python src/monitoring/run_monitoring.py
   ```

4. Run Attack Simulation:
   ```
   python src/run_attack_simulation.py
   ```

Data Organization:
- data/
  ├── events/     # Attack event logs (created automatically)
  └── models/     # Trained models and metadata
- logs/          # Component logs (created automatically)

Note: The system automatically creates necessary directories and handles data
storage locally without requiring external databases or containers.
"""

def show_help():
    """Show usage information."""
    print(__doc__)

if __name__ == "__main__":
    show_help()