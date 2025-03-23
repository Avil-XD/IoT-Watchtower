"""
Attack Simulation Runner
======================

Main script to run the IoT attack simulation.
"""

import json
import logging
import os
from datetime import datetime
from typing import List

from simulation.network import SmartHomeNetwork
from simulation.attack_simulator import AttackSimulator, AttackEvent

def setup_logging():
    """Setup logging configuration."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(
                os.path.join(log_dir, f"attack_simulation_{timestamp}.log")
            ),
            logging.StreamHandler()
        ]
    )

def save_events(events: List[AttackEvent]):
    """Save attack events to file."""
    data_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data",
        "events"
    )
    os.makedirs(data_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(data_dir, f"attack_events_{timestamp}.json")
    
    with open(output_file, "w") as f:
        json.dump(
            [event.to_dict() for event in events],
            f,
            indent=2
        )
    
    logging.info(f"Saved {len(events)} events to {output_file}")

def main():
    """Main simulation runner."""
    setup_logging()
    logging.info("Starting IoT attack simulation")
    
    try:
        # Initialize network
        network = SmartHomeNetwork(num_devices=3)
        logging.info("Network initialized:\n" + network.to_json())
        
        # Setup attack simulator
        simulator = AttackSimulator(network)
        
        # Run attack scenario
        events = simulator.run_attack_scenario(
            attack_type="botnet",
            target_types=["SmartCamera", "SmartLock"],
            method="malware_propagation",
            duration=300,  # 5 minutes
            interval=10    # Attack every 10 seconds
        )
        
        # Save results
        save_events(events)
        
        # Print summary
        total_attacks = len(events)
        successful_attacks = sum(1 for e in events if e.success)
        
        logging.info("\nSimulation Summary:")
        logging.info(f"Total Attacks: {total_attacks}")
        logging.info(f"Successful Attacks: {successful_attacks}")
        logging.info(f"Success Rate: {(successful_attacks/total_attacks)*100:.1f}%")
        
        # Show final network state
        logging.info("\nFinal Network State:")
        logging.info(network.to_json())
        
    except Exception as e:
        logging.error(f"Simulation failed: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    main()