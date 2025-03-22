import logging
from pathlib import Path
from datetime import datetime
import time
import threading
from typing import Dict, List, Optional

from simulation.iot_network import IoTSimulation
from simulation.attack_simulator import AttackSimulator, AttackConfig
from data.event_collector import EventCollector, SecurityEvent
from ml.attack_classifier import AttackClassifier

class SecuritySimulationSystem:
    def __init__(self, config_path: str = "config/network.json"):
        """Initialize the complete IoT security simulation system."""
        self._setup_logging()
        self.config_path = config_path
        
        # Initialize components
        self.logger.info("Initializing system components...")
        self.iot_simulation = IoTSimulation(config_path)
        self.attack_simulator = AttackSimulator()
        self.event_collector = EventCollector()
        self.attack_classifier = AttackClassifier()
        
        self.active_attacks: Dict[str, dict] = {}
        self.is_running = False

    def _setup_logging(self):
        """Configure system-wide logging."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"system_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("SecuritySimulationSystem")

    def initialize(self):
        """Initialize the complete system."""
        try:
            # Start IoT network simulation
            self.logger.info("Setting up IoT network...")
            self.iot_simulation.setup_network()

            # Start event collector
            self.logger.info("Starting event collector...")
            self.event_collector.start()

            self.is_running = True
            self.logger.info("System initialization completed")

        except Exception as e:
            self.logger.error(f"System initialization failed: {str(e)}")
            self.shutdown()
            raise

    def simulate_attack(self, attack_config: AttackConfig):
        """Launch an attack simulation and collect events."""
        try:
            # Launch attack
            attack_id = self.attack_simulator.launch_attack(attack_config)
            self.active_attacks[attack_id] = {
                "config": attack_config,
                "start_time": datetime.now().isoformat()
            }

            # Generate security event for attack start
            event = SecurityEvent(
                timestamp=datetime.now().isoformat(),
                event_type="attack_started",
                source="attack_simulator",
                target=",".join(attack_config.targets),
                severity=8,
                details={
                    "attack_type": attack_config.type.value,
                    "parameters": attack_config.parameters
                },
                attack_type=attack_config.type.value,
                attack_id=attack_id
            )
            self.event_collector.collect_event(event)

            return attack_id

        except Exception as e:
            self.logger.error(f"Attack simulation failed: {str(e)}")
            raise

    def stop_attack(self, attack_id: str):
        """Stop an active attack simulation."""
        try:
            if attack_id in self.active_attacks:
                self.attack_simulator.stop_attack(attack_id)
                attack_info = self.active_attacks.pop(attack_id)

                # Generate security event for attack stop
                event = SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="attack_stopped",
                    source="attack_simulator",
                    target=",".join(attack_info["config"].targets),
                    severity=5,
                    details={
                        "attack_type": attack_info["config"].type.value,
                        "duration": (datetime.now() - datetime.fromisoformat(attack_info["start_time"])).seconds
                    },
                    attack_type=attack_info["config"].type.value,
                    attack_id=attack_id
                )
                self.event_collector.collect_event(event)

        except Exception as e:
            self.logger.error(f"Failed to stop attack {attack_id}: {str(e)}")
            raise

    def train_classifier(self, training_data: Optional[List[Dict]] = None):
        """Train the attack classifier with collected events."""
        try:
            if training_data is None:
                # Get historical events from collector
                training_data = self.event_collector.get_events()

            if not training_data:
                raise ValueError("No training data available")

            # Extract labels from events
            labels = [event.get("attack_type") for event in training_data]

            # Train the classifier
            self.attack_classifier.train(training_data, labels)
            self.logger.info("Classifier training completed")

        except Exception as e:
            self.logger.error(f"Classifier training failed: {str(e)}")
            raise

    def classify_events(self, events: List[Dict]) -> List[Dict]:
        """Classify security events using the trained model."""
        try:
            predictions = self.attack_classifier.predict(events)
            
            # Update events with classifications
            for event, prediction in zip(events, predictions):
                event["ml_classification"] = prediction

            return events

        except Exception as e:
            self.logger.error(f"Event classification failed: {str(e)}")
            raise

    def run_simulation(self, duration: int = 3600):
        """Run the complete simulation for a specified duration."""
        try:
            self.initialize()
            self.iot_simulation.start_simulation()
            
            start_time = time.time()
            self.logger.info(f"Starting simulation for {duration} seconds")

            while time.time() - start_time < duration and self.is_running:
                # Process any pending events
                events = self.event_collector.get_events(
                    start_time=datetime.fromtimestamp(time.time() - 60).isoformat()
                )
                
                if events:
                    # Classify new events
                    classified_events = self.classify_events(events)
                    self.logger.info(f"Classified {len(classified_events)} new events")

                time.sleep(1)  # Prevent CPU overuse

            self.shutdown()

        except Exception as e:
            self.logger.error(f"Simulation run failed: {str(e)}")
            self.shutdown()
            raise

    def shutdown(self):
        """Shutdown the complete system."""
        try:
            self.is_running = False
            
            # Stop all active attacks
            for attack_id in list(self.active_attacks.keys()):
                self.stop_attack(attack_id)

            # Stop components
            self.iot_simulation.stop_simulation()
            self.event_collector.stop()

            self.logger.info("System shutdown completed")

        except Exception as e:
            self.logger.error(f"System shutdown failed: {str(e)}")
            raise

if __name__ == "__main__":
    # Create and run the complete system
    system = SecuritySimulationSystem()
    
    try:
        # Run simulation for 1 hour
        system.run_simulation(duration=3600)
        
    except KeyboardInterrupt:
        system.logger.info("Received shutdown signal")
        system.shutdown()
    except Exception as e:
        system.logger.error(f"System error: {str(e)}")
        system.shutdown()
        raise