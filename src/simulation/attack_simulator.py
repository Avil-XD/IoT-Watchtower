import time
import uuid
from typing import Dict, List, Any
import random
import logging
from datetime import datetime
from pathlib import Path

class AttackConfig:
    def __init__(self, attack_type: str, targets: List[str], duration: int = 300):
        """Initialize an attack configuration."""
        self.id = str(uuid.uuid4())
        self.type = attack_type
        self.targets = targets
        self.duration = duration
        self.start_time = None
        self.status = "initialized"

class AttackSimulator:
    def __init__(self, network):
        """Initialize attack simulator with network reference."""
        self._setup_logging()
        self.network = network
        self.active_attacks = {}

    def _setup_logging(self):
        """Configure attack-specific logging."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"attacks_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("AttackSimulator")

    def create_botnet_attack(self, targets: List[str], duration: int = 300) -> AttackConfig:
        """Create a botnet attack configuration."""
        self.logger.info(f"Creating botnet attack targeting {targets}")
        attack_id = f"botnet_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        config = AttackConfig(
            attack_type="botnet",
            targets=targets,
            duration=duration
        )
        self.logger.info(f"Attack {attack_id} created")
        return config

    def create_ddos_attack(self, targets: List[str], duration: int = 300) -> AttackConfig:
        """Create a DDoS attack configuration."""
        self.logger.info(f"Creating DDoS attack targeting {targets}")
        attack_id = f"ddos_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        config = AttackConfig(
            attack_type="ddos",
            targets=targets,
            duration=duration
        )
        self.logger.info(f"Attack {attack_id} created")
        return config

    def create_mitm_attack(self, targets: List[str], duration: int = 300) -> AttackConfig:
        """Create a Man-in-the-Middle attack configuration."""
        self.logger.info(f"Creating MitM attack targeting {targets}")
        attack_id = f"mitm_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        config = AttackConfig(
            attack_type="mitm",
            targets=targets,
            duration=duration
        )
        self.logger.info(f"Attack {attack_id} created")
        return config

    def launch_attack(self, config: AttackConfig) -> str:
        """Launch an attack with the given configuration."""
        self.logger.info(f"Launching {config.type} attack on targets: {config.targets}")
        
        config.start_time = time.time()
        config.status = "active"
        self.active_attacks[config.id] = config
        
        # Apply attack effects to network
        for target in config.targets:
            device = self.network.devices.get(target)
            if device:
                if config.type == "botnet":
                    self._apply_botnet_effects(device)
                elif config.type == "ddos":
                    self._apply_ddos_effects(device)
                elif config.type == "mitm":
                    self._apply_mitm_effects(device)
        
        self.logger.info(f"Attack {config.id} launched successfully")
        return config.id

    def _apply_botnet_effects(self, device):
        """Apply botnet attack effects to device."""
        device.metrics["cpu_usage"] *= random.uniform(1.3, 1.7)  # Increased CPU usage
        device.metrics["memory_usage"] *= random.uniform(1.2, 1.5)  # Increased memory usage
        device.metrics["error_count"] += random.randint(5, 15)  # More errors
        device.metrics["bandwidth_usage"] *= random.uniform(1.1, 1.4)  # Increased bandwidth
        
    def _apply_ddos_effects(self, device):
        """Apply DDoS attack effects to device."""
        device.metrics["bandwidth_usage"] *= random.uniform(1.8, 2.5)  # Major bandwidth spike
        device.metrics["error_count"] += random.randint(10, 20)  # Many errors
        device.metrics["packet_count"] *= random.uniform(1.4, 1.8)  # Increased packets
        device.metrics["cpu_usage"] *= random.uniform(1.2, 1.6)  # High CPU load
        
    def _apply_mitm_effects(self, device):
        """Apply MitM attack effects to device."""
        device.metrics["error_count"] += random.randint(3, 8)  # Some errors
        device.metrics["packet_count"] *= random.uniform(1.1, 1.3)  # Slightly increased packets
        device.metrics["bandwidth_usage"] *= random.uniform(1.05, 1.2)  # Minor bandwidth increase
        
    def get_attack_status(self, attack_id: str) -> Dict[str, Any]:
        """Get the current status of an attack."""
        if attack_id not in self.active_attacks:
            return {"status": "not_found", "events": []}
            
        attack = self.active_attacks[attack_id]
        elapsed_time = time.time() - attack.start_time
        
        # Check if attack duration has elapsed
        if elapsed_time >= attack.duration:
            if attack.status == "active":
                self._cleanup_attack(attack)
            return {
                "status": "completed",
                "type": attack.type,
                "elapsed_time": elapsed_time,
                "events": self._generate_attack_events(attack)
            }
            
        return {
            "status": "in_progress",
            "type": attack.type,
            "elapsed_time": elapsed_time,
            "events": self._generate_attack_events(attack)
        }

    def _cleanup_attack(self, attack: AttackConfig):
        """Clean up attack effects."""
        attack.status = "completed"
        
        # Restore normal device operation
        for target in attack.targets:
            device = self.network.devices.get(target)
            if device:
                device.metrics["cpu_usage"] = max(
                    device.metrics["cpu_usage"] * random.uniform(0.6, 0.8),
                    random.uniform(20, 60)
                )
                device.metrics["memory_usage"] = max(
                    device.metrics["memory_usage"] * random.uniform(0.7, 0.9),
                    random.uniform(30, 70)
                )
                device.metrics["bandwidth_usage"] = max(
                    device.metrics["bandwidth_usage"] * random.uniform(0.5, 0.7),
                    random.uniform(10, 50)
                )

    def _generate_attack_events(self, attack: AttackConfig) -> List[Dict[str, Any]]:
        """Generate event data for the attack."""
        events = []
        elapsed_time = time.time() - attack.start_time
        
        # Generate events based on attack type and progress
        if attack.type == "botnet":
            if elapsed_time < attack.duration * 0.3:
                events.append({
                    "phase": "initial",
                    "description": "Establishing control over target devices"
                })
            elif elapsed_time < attack.duration * 0.7:
                events.append({
                    "phase": "active",
                    "description": "Executing malicious commands on infected devices"
                })
            else:
                events.append({
                    "phase": "final",
                    "description": "Maintaining persistence and hiding traces"
                })
                
        elif attack.type == "ddos":
            if elapsed_time < attack.duration * 0.2:
                events.append({
                    "phase": "initial",
                    "description": "Building up attack traffic"
                })
            elif elapsed_time < attack.duration * 0.8:
                events.append({
                    "phase": "peak",
                    "description": "Maximum traffic flood"
                })
            else:
                events.append({
                    "phase": "decreasing",
                    "description": "Attack traffic reducing"
                })
                
        elif attack.type == "mitm":
            if elapsed_time < attack.duration * 0.4:
                events.append({
                    "phase": "intercept",
                    "description": "Intercepting network traffic"
                })
            else:
                events.append({
                    "phase": "active",
                    "description": "Monitoring and potentially modifying traffic"
                })
        
        return events