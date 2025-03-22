import logging
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Any
from datetime import datetime
import json
from pathlib import Path
import random
import threading
import time

class AttackType(Enum):
    BOTNET = "botnet"
    DDOS = "ddos"
    DATA_THEFT = "data_theft"
    AUTH_ATTACK = "authentication"
    PROTOCOL_EXPLOIT = "protocol_exploit"

class AttackStatus(Enum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class AttackConfig:
    type: AttackType
    targets: List[str]
    duration: int
    parameters: Dict[str, Any]

class AttackSimulator:
    def __init__(self, iot_network=None):
        """Initialize attack simulator with logging."""
        self._setup_logging()
        self.active_attacks = {}
        self.attack_history = []
        self.iot_network = iot_network
        self.attack_threads = {}
        
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

    def create_botnet_attack(self, targets: List[str]) -> AttackConfig:
        """Create a botnet attack configuration."""
        return AttackConfig(
            type=AttackType.BOTNET,
            targets=targets,
            duration=300,  # 5 minutes
            parameters={
                "propagation_method": "malware",
                "c2_server": "simulated_c2_server",
                "bot_behavior": {
                    "scan_rate": 100,
                    "infection_probability": 0.7,
                    "command_interval": 30
                }
            }
        )

    def create_ddos_attack(self, targets: List[str]) -> AttackConfig:
        """Create a DDoS attack configuration."""
        return AttackConfig(
            type=AttackType.DDOS,
            targets=targets,
            duration=180,  # 3 minutes
            parameters={
                "attack_type": "syn_flood",
                "packets_per_second": 1000,
                "packet_size": 64,
                "source_ips": ["simulated_ip_range"]
            }
        )

    def create_data_theft_attack(self, targets: List[str]) -> AttackConfig:
        """Create a data theft attack configuration."""
        return AttackConfig(
            type=AttackType.DATA_THEFT,
            targets=targets,
            duration=240,  # 4 minutes
            parameters={
                "method": "packet_sniffing",
                "data_types": ["credentials", "sensor_data", "user_info"],
                "exfiltration_rate": 50  # KB/s
            }
        )

    def create_auth_attack(self, targets: List[str]) -> AttackConfig:
        """Create an authentication attack configuration."""
        return AttackConfig(
            type=AttackType.AUTH_ATTACK,
            targets=targets,
            duration=120,  # 2 minutes
            parameters={
                "method": "brute_force",
                "attempts_per_second": 10,
                "credential_list": "common_passwords",
                "timeout": 1
            }
        )

    def create_protocol_attack(self, targets: List[str]) -> AttackConfig:
        """Create a protocol-specific attack configuration."""
        return AttackConfig(
            type=AttackType.PROTOCOL_EXPLOIT,
            targets=targets,
            duration=150,  # 2.5 minutes
            parameters={
                "protocol": "MQTT",
                "exploit_type": "topic_injection",
                "payload_size": 256,
                "interval": 5
            }
        )
    
    def _simulate_attack_effects(self, attack_id: str, attack_config: AttackConfig):
        """Simulate the effects of an attack on the IoT network."""
        while attack_id in self.active_attacks and self.active_attacks[attack_id]["status"] == AttackStatus.IN_PROGRESS.value:
            try:
                # Get target devices
                for target_id in attack_config.targets:
                    if target_id in self.iot_network.devices:
                        device = self.iot_network.devices[target_id]
                        
                        # Apply attack effects based on attack type
                        if attack_config.type == AttackType.BOTNET:
                            # Simulate botnet effects
                            device.metrics["cpu_usage"] = min(100, device.metrics["cpu_usage"] + random.uniform(20, 40))
                            device.metrics["memory_usage"] = min(100, device.metrics["memory_usage"] + random.uniform(15, 30))
                            device.metrics["bandwidth_usage"] = min(100, device.metrics["bandwidth_usage"] + random.uniform(30, 50))
                            device.metrics["error_count"] += random.randint(1, 3)
                            
                        elif attack_config.type == AttackType.DDOS:
                            # Simulate DDoS effects
                            device.metrics["bandwidth_usage"] = min(100, device.metrics["bandwidth_usage"] + random.uniform(60, 90))
                            device.metrics["packet_count"] += attack_config.parameters["packets_per_second"]
                            device.metrics["error_count"] += random.randint(3, 7)
                            
                        elif attack_config.type == AttackType.DATA_THEFT:
                            # Simulate data theft effects
                            device.metrics["bandwidth_usage"] = min(100, device.metrics["bandwidth_usage"] + random.uniform(10, 20))
                            device.metrics["packet_count"] += random.randint(50, 100)
                            
                        elif attack_config.type == AttackType.AUTH_ATTACK:
                            # Simulate authentication attack effects
                            device.metrics["cpu_usage"] = min(100, device.metrics["cpu_usage"] + random.uniform(10, 25))
                            device.metrics["error_count"] += random.randint(1, 5)
                            
                        elif attack_config.type == AttackType.PROTOCOL_EXPLOIT:
                            # Simulate protocol exploit effects
                            device.metrics["cpu_usage"] = min(100, device.metrics["cpu_usage"] + random.uniform(15, 35))
                            device.metrics["memory_usage"] = min(100, device.metrics["memory_usage"] + random.uniform(10, 20))
                            device.metrics["error_count"] += random.randint(2, 4)
                
                # Add attack event
                event = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "attack_impact",
                    "details": {
                        "affected_devices": attack_config.targets,
                        "impact_level": "high"
                    }
                }
                self.active_attacks[attack_id]["events"].append(event)
                
            except Exception as e:
                self.logger.error(f"Error in attack simulation: {str(e)}")
                
            time.sleep(1)  # Update effects every second

    def launch_attack(self, attack_config: AttackConfig):
        """Launch a configured attack."""
        try:
            self.logger.info(f"Launching {attack_config.type.value} attack on targets: {attack_config.targets}")
            
            if not self.iot_network:
                raise ValueError("IoT network not configured for attack simulation")
            
            # Generate unique attack ID
            attack_id = f"{attack_config.type.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Record attack start
            attack_record = {
                "id": attack_id,
                "config": {
                    "type": attack_config.type.value,
                    "targets": attack_config.targets,
                    "duration": attack_config.duration,
                    "parameters": attack_config.parameters
                },
                "status": AttackStatus.IN_PROGRESS.value,
                "start_time": datetime.now().isoformat(),
                "events": []
            }
            
            # Store active attack
            self.active_attacks[attack_id] = attack_record
            
            # Start attack simulation thread
            attack_thread = threading.Thread(
                target=self._simulate_attack_effects,
                args=(attack_id, attack_config)
            )
            attack_thread.daemon = True
            attack_thread.start()
            
            # Store thread reference
            self.attack_threads[attack_id] = attack_thread
            
            # Schedule attack stop
            stop_thread = threading.Thread(
                target=self._schedule_attack_stop,
                args=(attack_id, attack_config.duration)
            )
            stop_thread.daemon = True
            stop_thread.start()
            
            self.logger.info(f"Attack {attack_id} launched successfully")
            return attack_id
            
        except Exception as e:
            self.logger.error(f"Failed to launch attack: {str(e)}")
            raise

    def _schedule_attack_stop(self, attack_id: str, duration: int):
        """Schedule the attack to stop after specified duration."""
        time.sleep(duration)
        if attack_id in self.active_attacks:
            self.stop_attack(attack_id)

    def stop_attack(self, attack_id: str):
        """Stop an active attack."""
        try:
            if attack_id not in self.active_attacks:
                raise ValueError(f"Attack {attack_id} not found in active attacks")
            
            attack_record = self.active_attacks[attack_id]
            attack_record["status"] = AttackStatus.COMPLETED.value
            attack_record["end_time"] = datetime.now().isoformat()
            
            # Wait for attack thread to complete
            if attack_id in self.attack_threads:
                self.attack_threads[attack_id].join(timeout=5)
                del self.attack_threads[attack_id]
            
            # Move to history
            self.attack_history.append(attack_record)
            del self.active_attacks[attack_id]
            
            self.logger.info(f"Attack {attack_id} stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to stop attack {attack_id}: {str(e)}")
            raise

    def get_attack_status(self, attack_id: str) -> dict:
        """Get the current status of an attack."""
        if attack_id in self.active_attacks:
            return self.active_attacks[attack_id]
        
        # Search in history
        for attack in self.attack_history:
            if attack["id"] == attack_id:
                return attack
                
        raise ValueError(f"Attack {attack_id} not found")