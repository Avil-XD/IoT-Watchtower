import logging
from pathlib import Path
from datetime import datetime
import time
import json

from simulation.iot_network import IoTSimulation
from simulation.attack_simulator import AttackSimulator
from data.event_collector import EventCollector
from ml.attack_classifier import AttackClassifier

def setup_logging():
    """Configure logging for data collection."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"data_collection_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("DataCollection")

def collect_normal_behavior(iot_sim, classifier, duration=300):
    """Collect normal network behavior data."""
    logger = logging.getLogger("DataCollection")
    logger.info(f"Collecting normal behavior data for {duration} seconds")
    
    start_time = time.time()
    while time.time() - start_time < duration:
        network_status = iot_sim.get_network_status()
        classifier.collect_training_data(
            network_status=network_status,
            attack_status={"type": "normal", "status": "none"}
        )
        time.sleep(5)  # Sample every 5 seconds

def simulate_attacks(iot_sim, attack_sim, classifier):
    """Run different types of attacks and collect data."""
    logger = logging.getLogger("DataCollection")
    
    attack_types = [
        {
            "type": "botnet",
            "targets": ["camera_01", "lock_01"],
            "duration": 180
        },
        {
            "type": "ddos",
            "targets": ["camera_01"],
            "duration": 120
        },
        {
            "type": "mitm",
            "targets": ["lock_01"],
            "duration": 150
        }
    ]
    
    for attack_config in attack_types:
        logger.info(f"Simulating {attack_config['type']} attack")
        
        # Create and launch attack
        config = attack_sim.create_attack(
            attack_type=attack_config["type"],
            targets=attack_config["targets"],
            duration=attack_config["duration"]
        )
        attack_id = attack_sim.launch_attack(config)
        
        # Collect data during attack
        start_time = time.time()
        while time.time() - start_time < attack_config["duration"]:
            network_status = iot_sim.get_network_status()
            attack_status = attack_sim.get_attack_status(attack_id)
            
            classifier.collect_training_data(
                network_status=network_status,
                attack_status={
                    "type": attack_config["type"],
                    "status": attack_status["status"]
                }
            )
            time.sleep(5)
        
        # Let network recover
        logger.info("Waiting for network recovery...")
        time.sleep(30)

def main():
    logger = setup_logging()
    
    try:
        # Initialize components
        logger.info("Initializing components...")
        event_collector = EventCollector()
        classifier = AttackClassifier(event_collector)
        
        iot_sim = IoTSimulation("src/config/network.json")
        iot_sim.setup_network()
        iot_sim.start_simulation()
        
        attack_sim = AttackSimulator(iot_sim.network)
        
        # Let network stabilize
        logger.info("Letting network stabilize...")
        time.sleep(30)
        
        # Collect normal behavior
        collect_normal_behavior(iot_sim, classifier)
        
        # Simulate various attacks
        simulate_attacks(iot_sim, attack_sim, classifier)
        
        # Train initial model
        logger.info("Training initial model...")
        classifier.train()
        
        # Test model predictions
        logger.info("Testing model predictions...")
        network_status = iot_sim.get_network_status()
        prediction = classifier.predict(network_status)
        logger.info(f"Prediction for current state: {json.dumps(prediction, indent=2)}")
        
    except Exception as e:
        logger.error(f"Data collection failed: {str(e)}")
        raise
    finally:
        logger.info("Stopping simulation...")
        iot_sim.stop_simulation()
        logger.info("Data collection completed")

if __name__ == "__main__":
    main()