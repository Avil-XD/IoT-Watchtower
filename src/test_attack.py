import logging
from pathlib import Path
from datetime import datetime
import time

from simulation.iot_network import IoTSimulation
from simulation.attack_simulator import AttackSimulator
from data.event_collector import EventCollector

def setup_logging():
    """Configure test-specific logging."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"test_attack_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("TestAttack")

def main():
    logger = setup_logging()
    
    try:
        # Initialize event collector
        collector = EventCollector()
        
        # Initialize IoT network
        logger.info("Initializing IoT network...")
        iot_sim = IoTSimulation("src/config/network.json")
        iot_sim.setup_network()
        iot_sim.start_simulation()
        
        # Store initial network state
        collector.collect_event(
            event_type="network_state",
            data=iot_sim.get_network_status(),
            source="iot_network"
        )
        
        # Initialize attack simulator with the IoT network
        logger.info("Initializing attack simulator...")
        attack_sim = AttackSimulator(iot_sim.network)
        
        # Let the network stabilize
        logger.info("Letting network stabilize for 10 seconds...")
        time.sleep(10)
        
        # Get initial network status
        logger.info("\nInitial network status:")
        initial_status = iot_sim.get_network_status()
        print(initial_status)
        
        # Store pre-attack metrics
        collector.collect_event(
            event_type="metrics_snapshot",
            data=initial_status,
            source="pre_attack"
        )
        
        # Create and launch botnet attack
        logger.info("\nLaunching botnet attack...")
        attack_config = attack_sim.create_botnet_attack(
            targets=["camera_01", "lock_01"]  # Attack camera and lock
        )
        
        # Record attack start
        collector.collect_event(
            event_type="attack_started",
            data=attack_config.__dict__,
            source="attack_simulator"
        )
        
        attack_id = attack_sim.launch_attack(attack_config)
        
        # Monitor attack progress
        duration = attack_config.duration
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # Get current status
            status = attack_sim.get_attack_status(attack_id)
            network_status = iot_sim.get_network_status()
            
            # Store attack progress
            collector.collect_event(
                event_type="attack_progress",
                data={
                    "attack_id": attack_id,
                    "attack_status": status,
                    "network_status": network_status
                },
                source="attack_simulator"
            )
            
            logger.info(f"\nAttack Status at {time.time() - start_time:.1f}s:")
            print(f"Status: {status['status']}")
            print(f"Events: {len(status['events'])} recorded")
            print("\nNetwork Status:")
            print(network_status)
            
            time.sleep(5)  # Update every 5 seconds
            
        # Attack will stop automatically after duration
        # Wait a bit to see network recovery
        logger.info("\nAttack completed. Monitoring network recovery...")
        time.sleep(10)
        
        # Get final network status
        logger.info("\nFinal network status:")
        final_status = iot_sim.get_network_status()
        print(final_status)
        
        # Store post-attack metrics
        collector.collect_event(
            event_type="metrics_snapshot",
            data=final_status,
            source="post_attack"
        )
        
        # Record attack completion
        collector.collect_event(
            event_type="attack_completed",
            data={
                "attack_id": attack_id,
                "duration": duration,
                "final_status": attack_sim.get_attack_status(attack_id)
            },
            source="attack_simulator"
        )
        
        # Stop simulation
        iot_sim.stop_simulation()
        
        # Try to upload any locally stored events to Elasticsearch
        collector.upload_backup_to_elasticsearch()
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        raise
    finally:
        logger.info("Test completed")

if __name__ == "__main__":
    main()