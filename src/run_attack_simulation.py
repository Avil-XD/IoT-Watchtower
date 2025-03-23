"""
Attack Simulation Runner
======================

Main script to run the IoT attack simulation.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import List

from simulation.network import SmartHomeNetwork
from simulation.attack_simulator import AttackSimulator, AttackEvent
from data.event_collector import EventCollector

def setup_logging():
    """Setup logging configuration."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_dir / f"attacks_{timestamp}.log"),
            logging.StreamHandler()
        ]
    )

def process_attack_event(event: AttackEvent, event_collector: EventCollector):
    """Process and collect attack event."""
    target_device = event.target_device
    
    event_collector.collect_event(
        event_type="security_alert",
        data={
            "attack_type": event.attack_type,
            "method": event.method,
            "success": event.success,
            "details": event.details
        },
        source="attack_simulator",
        target=f"{target_device.type}_{target_device.id}",
        severity="high" if event.success else "low",
        confidence=0.9 if event.success else 0.6,
        anomaly_score=0.85 if event.success else 0.4
    )

def main():
    """Main simulation runner."""
    setup_logging()
    logging.info("Starting IoT attack simulation")
    
    try:
        # Initialize components
        network = SmartHomeNetwork(num_devices=3)
        simulator = AttackSimulator(network)
        event_collector = EventCollector()
        
        logging.info("Network initialized:\n" + network.to_json())
        
        # Run attack scenario
        events = simulator.run_attack_scenario(
            attack_type="botnet",
            target_types=["SmartCamera", "SmartLock"],
            method="malware_propagation",
            duration=300,  # 5 minutes
            interval=10    # Attack every 10 seconds
        )
        
        # Process and collect events
        for event in events:
            process_attack_event(event, event_collector)
        
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