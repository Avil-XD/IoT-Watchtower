"""
Training Data Collection
====================

Collects training data by simulating normal behavior and various attacks.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
import time
import json
import numpy as np

# Add src directory to Python path
src_dir = Path(__file__).resolve().parent.parent
if str(src_dir) not in sys.path:
    sys.path.append(str(src_dir))

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

def collect_normal_behavior(simulator, classifier, duration=300, sample_rate=5):
    """Collect normal network behavior data."""
    logger = logging.getLogger("DataCollection")
    logger.info(f"Collecting normal behavior data for {duration} seconds")
    
    samples_collected = 0
    start_time = time.time()
    
    while time.time() - start_time < duration:
        network_status = simulator.get_network_status()
        classifier.collect_training_data(
            network_status=network_status,
            attack_status={"type": "normal", "status": "none"}
        )
        samples_collected += 1
        
        # Log progress every minute
        elapsed = time.time() - start_time
        if samples_collected % (60 // sample_rate) == 0:
            logger.info(f"Normal behavior samples collected: {samples_collected} ({elapsed:.0f}s)")
        
        time.sleep(sample_rate)

def simulate_attacks(simulator, classifier):
    """Run different types of attacks for ML training."""
    logger = logging.getLogger("DataCollection")
    
    # Define attack scenarios using implemented methods
    attack_configs = [
        # Botnet attacks
        {
            "type": "botnet",
            "target_types": ["SmartCamera", "SmartLock"],
            "duration": 180,
            "method": "malware_propagation",
            "description": "Multi-device botnet infection"
        },
        {
            "type": "botnet",
            "target_types": ["SmartCamera"],
            "duration": 120,
            "method": "malware_propagation",
            "description": "Single device botnet"
        }
    ]
    
    for config in attack_configs:
        logger.info(f"\nSimulating {config['type']} attack: {config['description']}")
        logger.info(f"Targets: {config['target_types']}")
        logger.info(f"Duration: {config['duration']}s")
        
        # Execute attack
        events = simulator.run_attack_scenario(
            attack_type=config["type"],
            target_types=config["target_types"],
            method=config["method"],
            duration=config["duration"],
            interval=5
        )
        
        # Process attack events
        for event in events:
            network_status = simulator.get_network_status()
            
            # Collect training sample
            classifier.collect_training_data(
                network_status=network_status,
                attack_status={
                    "type": config["type"],
                    "status": "active" if event.success else "failed",
                    "description": config["description"]
                }
            )
            
            # Log attack progress
            logger.info(
                f"\nAttack Event:"
                f"\n  Success: {event.success}"
                f"\n  Target: {event.target_device.type}"
                f"\n  Details: {event.details}"
            )
        
        # Let network recover
        recovery_time = min(30, config["duration"] * 0.2)  # 20% of attack duration or 30s
        logger.info(f"Allowing {recovery_time:.0f}s for network recovery...")
        time.sleep(recovery_time)

def main():
    """Collect comprehensive training data for attack detection."""
    logger = setup_logging()
    
    try:
        # Initialize components
        logger.info("Initializing data collection components...")
        event_collector = EventCollector()
        classifier = AttackClassifier(event_collector)
        simulator = AttackSimulator()
        
        # Create data directories
        data_dir = Path("data/processed")
        data_dir.mkdir(parents=True, exist_ok=True)
        
        # Let network stabilize
        logger.info("Letting network stabilize for initial baseline...")
        time.sleep(30)
        
        # Collect normal behavior
        logger.info("\nStarting normal behavior collection...")
        collect_normal_behavior(simulator, classifier, duration=600)  # 10 minutes
        
        # Simulate various attacks
        logger.info("\nStarting attack simulations...")
        simulate_attacks(simulator, classifier)
        
        # Train initial model
        logger.info("\nTraining initial model with collected data...")
        try:
            classifier.train()
            
            # Test model predictions
            logger.info("\nTesting model predictions...")
            network_status = simulator.get_network_status()
            prediction = classifier.predict(network_status)
            logger.info(f"Test prediction:\n{json.dumps(prediction, indent=2)}")
            
        except Exception as e:
            logger.warning(f"Model training failed: {str(e)}")
        
        logger.info("\nData collection completed successfully")
        
    except Exception as e:
        logger.error(f"Data collection failed: {str(e)}")
        raise
    finally:
        logger.info("Data collection process finished")

if __name__ == "__main__":
    main()