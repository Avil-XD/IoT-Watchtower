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
    
    attack_configs = [
        {
            "type": "botnet",
            "targets": ["camera_01", "lock_01"],
            "duration": 180,
            "method": "create_botnet_attack"
        },
        {
            "type": "ddos",
            "targets": ["camera_01"],
            "duration": 120,
            "method": "create_ddos_attack"
        },
        {
            "type": "mitm",
            "targets": ["lock_01"],
            "duration": 150,
            "method": "create_mitm_attack"
        }
    ]
    
    for config in attack_configs:
        logger.info(f"Simulating {config['type']} attack")
        
        # Create and launch attack using the appropriate method
        attack_method = getattr(attack_sim, config["method"])
        attack_config = attack_method(targets=config["targets"])
        attack_id = attack_sim.launch_attack(attack_config)
        
        # Collect data during attack
        start_time = time.time()
        while time.time() - start_time < config["duration"]:
            network_status = iot_sim.get_network_status()
            attack_status = attack_sim.get_attack_status(attack_id)
            
            classifier.collect_training_data(
                network_status=network_status,
                attack_status={
                    "type": config["type"],
                    "status": attack_status["status"],
                    "attack_id": attack_id
                }
            )
            
            logger.info(f"\nAttack Status at {time.time() - start_time:.1f}s:")
            logger.info(f"Status: {attack_status['status']}")
            logger.info(f"Events: {len(attack_status.get('events', []))} recorded")
            
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
        
        # Initialize IoT network
        iot_sim = IoTSimulation("src/config/network.json")
        iot_sim.setup_network()
        iot_sim.start_simulation()
        
        # Let network stabilize
        logger.info("Letting network stabilize...")
        time.sleep(30)
        
        # Collect normal behavior
        collect_normal_behavior(iot_sim, classifier)
        
        # Simulate various attacks
        attack_sim = AttackSimulator(iot_sim.network)
        simulate_attacks(iot_sim, attack_sim, classifier)
        
        # Try to train initial model with collected data
        logger.info("Training initial model...")
        try:
            classifier.train()
            
            # Test model predictions
            network_status = iot_sim.get_network_status()
            prediction = classifier.predict(network_status)
            logger.info(f"Prediction for current state: {json.dumps(prediction, indent=2)}")
        except Exception as e:
            logger.warning(f"Model training failed: {str(e)}")
        
    except Exception as e:
        logger.error(f"Data collection failed: {str(e)}")
        raise
    finally:
        logger.info("Stopping simulation...")
        iot_sim.stop_simulation()
        logger.info("Data collection completed")

if __name__ == "__main__":
    main()