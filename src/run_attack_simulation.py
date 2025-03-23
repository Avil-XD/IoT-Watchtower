import logging
from pathlib import Path
from datetime import datetime
import time

from simulation.attack_simulator import AttackSimulator
from ml.attack_detector import AttackDetector
from monitoring.event_collector import EventCollector

def setup_logging():
    """Configure simulation logging."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"simulation_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("Simulation")

def run_simulation():
    """Run the attack simulation and detection."""
    logger = setup_logging()
    logger.info("Starting IoT security simulation")

    try:
        # Initialize components
        simulator = AttackSimulator()  # Now creates its own network
        detector = AttackDetector()
        event_collector = EventCollector()

        # Let network stabilize
        logger.info("Letting network stabilize...")
        time.sleep(10)

        # Create different attack types
        attacks = [
            simulator.create_botnet_attack(["camera1", "lock1"], duration=180),
            simulator.create_ddos_attack(["camera2"], duration=120),
            simulator.create_mitm_attack(["lock2", "thermostat1"], duration=150)
        ]

        # Run simulation
        for attack in attacks:
            # Launch attack
            logger.info(f"Launching {attack.type} attack...")
            attack_id = simulator.launch_attack(attack)

            # Monitor attack progress
            start_time = time.time()
            while time.time() - start_time < attack.duration:
                # Get current network status
                network_status = simulator.get_network_status()
                
                # Detect attacks
                detection_result = detector.detect(network_status)
                
                # Record events
                event_collector.record_attack_detection(detection_result, network_status)
                
                # Log detection results
                logger.info(f"\nDetection Results:")
                logger.info(f"Attack Type: {detection_result['detected_type']}")
                logger.info(f"Confidence: {detection_result['confidence']:.3f}")
                if detection_result.get("severity"):
                    logger.info(f"Severity: {detection_result['severity']}")
                    if detection_result['severity'] == "high":
                        logger.warning("HIGH SEVERITY ATTACK DETECTED!")
                
                time.sleep(5)  # Update every 5 seconds

            # Let network recover between attacks
            logger.info(f"Attack {attack_id} completed")
            logger.info("Letting network recover...")
            time.sleep(20)

        # Print final statistics
        logger.info("\nSimulation Summary:")
        history = detector.get_detection_history()
        
        total_alerts = sum(1 for d in history if d["alert_triggered"])
        high_severity = sum(1 for d in history if d.get("severity") == "high")
        
        logger.info(f"Total Detections: {len(history)}")
        logger.info(f"Total Alerts: {total_alerts}")
        logger.info(f"High Severity Events: {high_severity}")
        
        logger.info("Simulation completed successfully")

    except KeyboardInterrupt:
        logger.info("\nSimulation interrupted by user")
    except Exception as e:
        logger.error(f"Error during simulation: {str(e)}")
        raise

if __name__ == "__main__":
    run_simulation()