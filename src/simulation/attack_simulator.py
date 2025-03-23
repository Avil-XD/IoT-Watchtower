import time
import uuid
from typing import Dict, List, Any
import random
import logging
from datetime import datetime
from pathlib import Path
from .network import IoTNetwork

class AttackConfig:
    def __init__(self, attack_type: str, targets: List[str], duration: int = 300, method: str = None):
        """Initialize an attack configuration."""
        self.id = str(uuid.uuid4())
        self.type = attack_type
        self.targets = targets
        self.duration = duration
        self.method = method
        self.start_time = None
        self.status = "initialized"
        self.propagation_rate = random.uniform(0.1, 0.3)  # For botnet attacks
        self.success_probability = random.uniform(0.4, 0.8)

class AttackSimulator:
    def __init__(self):
        """Initialize attack simulator with IoT network."""
        self._setup_logging()
        self.network = IoTNetwork()
        self.active_attacks = {}
        self.compromised_devices = set()

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

    def get_network_status(self) -> Dict[str, Any]:
        """Get current network status."""
        return self.network.get_status()

    def create_botnet_attack(self, targets: List[str], duration: int = 300) -> AttackConfig:
        """Create a botnet attack with malware propagation."""
        self.logger.info(f"Creating botnet attack targeting {targets}")
        config = AttackConfig(
            attack_type="botnet",
            targets=targets,
            duration=duration,
            method="malware_propagation"
        )
        self.logger.info(f"Attack {config.id} created")
        return config

    def create_ddos_attack(self, targets: List[str], duration: int = 300) -> AttackConfig:
        """Create a DDoS attack configuration."""
        self.logger.info(f"Creating DDoS attack targeting {targets}")
        config = AttackConfig(
            attack_type="ddos",
            targets=targets,
            duration=duration,
            method="flood_attack"
        )
        self.logger.info(f"Attack {config.id} created")
        return config

    def create_mitm_attack(self, targets: List[str], duration: int = 300) -> AttackConfig:
        """Create a Man-in-the-Middle attack configuration."""
        self.logger.info(f"Creating MitM attack targeting {targets}")
        config = AttackConfig(
            attack_type="mitm",
            targets=targets,
            duration=duration,
            method="arp_spoofing"
        )
        self.logger.info(f"Attack {config.id} created")
        return config

    def launch_attack(self, config: AttackConfig) -> str:
        """Launch an attack with the given configuration."""
        self.logger.info(f"Launching {config.type} attack on targets: {config.targets}")
        
        config.start_time = time.time()
        config.status = "active"
        self.active_attacks[config.id] = config

        # Attempt to compromise devices based on their security level
        for target in config.targets:
            device = self.network.devices.get(target)
            if device:
                success_chance = config.success_probability
                # Adjust success chance based on vulnerabilities
                if config.type == "botnet" and device.vulnerabilities.get("firmware_outdated", False):
                    success_chance *= 1.5
                elif config.type == "mitm" and device.vulnerabilities.get("unencrypted_stream", False):
                    success_chance *= 1.3

                if random.random() < success_chance:
                    self.compromised_devices.add(target)
                    if config.type == "botnet":
                        self._apply_botnet_effects(device)
                    elif config.type == "ddos":
                        self._apply_ddos_effects(device)
                    elif config.type == "mitm":
                        self._apply_mitm_effects(device)

        self.logger.info(f"Attack {config.id} launched successfully")
        return config.id

    def _apply_botnet_effects(self, device):
        """Apply botnet attack effects with malware propagation."""
        device.status = "compromised"
        device.metrics["cpu_usage"] *= random.uniform(1.3, 1.7)
        device.metrics["memory_usage"] *= random.uniform(1.2, 1.5)
        device.metrics["error_count"] += random.randint(5, 15)
        device.metrics["bandwidth_usage"] *= random.uniform(1.1, 1.4)
        
        # Additional botnet-specific effects
        if device.type == "SmartCamera":
            device.metrics["stream_latency"] *= random.uniform(1.5, 2.0)
        elif device.type == "SmartLock":
            device.metrics["failed_auths"] += random.randint(10, 20)
        
    def _apply_ddos_effects(self, device):
        """Apply DDoS attack effects with flood attack."""
        device.status = "under_attack"
        device.metrics["bandwidth_usage"] *= random.uniform(1.8, 2.5)
        device.metrics["error_count"] += random.randint(10, 20)
        device.metrics["packet_count"] *= random.uniform(1.4, 1.8)
        device.metrics["cpu_usage"] *= random.uniform(1.2, 1.6)
        
    def _apply_mitm_effects(self, device):
        """Apply MitM attack effects with ARP spoofing."""
        device.status = "intercepted"
        device.metrics["error_count"] += random.randint(3, 8)
        device.metrics["packet_count"] *= random.uniform(1.1, 1.3)
        device.metrics["bandwidth_usage"] *= random.uniform(1.05, 1.2)
        
        # Device-specific MitM effects
        if device.type == "SmartLock":
            device.metrics["successful_auths"] += random.randint(5, 10)  # Unauthorized access
        elif device.type == "SmartCamera":
            device.metrics["stream_latency"] *= random.uniform(1.2, 1.4)

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
                "method": attack.method,
                "elapsed_time": elapsed_time,
                "compromised_devices": list(self.compromised_devices),
                "events": self._generate_attack_events(attack)
            }
            
        return {
            "status": "in_progress",
            "type": attack.type,
            "method": attack.method,
            "elapsed_time": elapsed_time,
            "compromised_devices": list(self.compromised_devices),
            "events": self._generate_attack_events(attack)
        }

    def _cleanup_attack(self, attack: AttackConfig):
        """Clean up attack effects and restore devices."""
        attack.status = "completed"
        
        # Restore devices
        for target in attack.targets:
            device = self.network.devices.get(target)
            if device and target in self.compromised_devices:
                device.status = "recovering"
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

        # Record attack in network history
        self.network.record_attack({
            "attack_id": attack.id,
            "type": attack.type,
            "method": attack.method,
            "targets": attack.targets,
            "duration": attack.duration,
            "compromised_devices": list(self.compromised_devices)
        })

    def _generate_attack_events(self, attack: AttackConfig) -> List[Dict[str, Any]]:
        """Generate detailed attack event data."""
        events = []
        elapsed_time = time.time() - attack.start_time
        
        if attack.type == "botnet":
            if elapsed_time < attack.duration * 0.3:
                events.append({
                    "phase": "infection",
                    "description": "Malware propagation in progress",
                    "compromised_count": len(self.compromised_devices)
                })
            elif elapsed_time < attack.duration * 0.7:
                events.append({
                    "phase": "control",
                    "description": "Botnet command and control established",
                    "compromised_count": len(self.compromised_devices)
                })
            else:
                events.append({
                    "phase": "persistence",
                    "description": "Maintaining botnet control",
                    "compromised_count": len(self.compromised_devices)
                })
                
        elif attack.type == "ddos":
            if elapsed_time < attack.duration * 0.2:
                events.append({
                    "phase": "preparation",
                    "description": "Building attack traffic"
                })
            elif elapsed_time < attack.duration * 0.8:
                events.append({
                    "phase": "flood",
                    "description": "Maximum flood attack in progress",
                    "traffic_multiplier": random.uniform(1.8, 2.5)
                })
            else:
                events.append({
                    "phase": "cooldown",
                    "description": "Attack traffic reducing"
                })
                
        elif attack.type == "mitm":
            if elapsed_time < attack.duration * 0.4:
                events.append({
                    "phase": "interception",
                    "description": "ARP cache poisoning in progress",
                    "intercepted_devices": list(self.compromised_devices)
                })
            else:
                events.append({
                    "phase": "extraction",
                    "description": "Data interception active",
                    "intercepted_devices": list(self.compromised_devices)
                })
        
        return events