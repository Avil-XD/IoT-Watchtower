"""
Attack Simulator
==============

Simulates various cyberattacks on IoT devices in the network.
"""

import logging
import random
import time
from datetime import datetime
from typing import Dict, List, Optional

from .network import SmartHomeNetwork, IoTDevice

class AttackEvent:
    def __init__(self, 
                 attack_type: str,
                 target_device: IoTDevice,
                 method: str,
                 timestamp: Optional[datetime] = None):
        self.attack_type = attack_type
        self.target_device = target_device
        self.method = method
        self.timestamp = timestamp or datetime.now()
        self.success = False
        self.details = {}
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "attack_type": self.attack_type,
            "target_device": self.target_device.to_dict(),
            "method": self.method,
            "success": self.success,
            "details": self.details
        }

class BotnetAttack:
    def __init__(self, network: SmartHomeNetwork):
        self.logger = logging.getLogger(__name__)
        self.network = network
        self.infected_devices: List[str] = []
        
    def propagate_malware(self, target_types: List[str]) -> AttackEvent:
        """Simulate malware propagation across targeted device types."""
        # Select random target device from specified types
        potential_targets = []
        for device_type in target_types:
            potential_targets.extend(self.network.get_devices_by_type(device_type))
            
        if not potential_targets:
            self.logger.warning(f"No devices found of types: {target_types}")
            return None
            
        target_device = random.choice(potential_targets)
        
        # Create attack event
        event = AttackEvent(
            attack_type="botnet",
            target_device=target_device,
            method="malware_propagation"
        )
        
        # Check if device is vulnerable
        is_vulnerable = any(
            vuln in ["weak_password", "firmware_vulnerability"]
            for vuln in target_device.vulnerabilities
        )
        
        if is_vulnerable and target_device.id not in self.infected_devices:
            self.infected_devices.append(target_device.id)
            self.network.update_device_status(target_device.id, "infected")
            
            event.success = True
            event.details = {
                "infection_time": datetime.now().isoformat(),
                "vulnerabilities_exploited": target_device.vulnerabilities,
                "network_position": len(self.infected_devices)
            }
            
            self.logger.info(
                f"Device {target_device.id} infected. "
                f"Total infected: {len(self.infected_devices)}"
            )
        else:
            event.details = {
                "reason": "Device already infected" if target_device.id in self.infected_devices
                         else "No exploitable vulnerabilities"
            }
            self.logger.info(f"Attack failed on device {target_device.id}")
            
        return event

class AttackSimulator:
    def __init__(self, network: SmartHomeNetwork):
        self.network = network
        self.logger = logging.getLogger(__name__)
        self.attacks = {
            "botnet": BotnetAttack(network)
        }
        
    def execute_attack(self, 
                      attack_type: str,
                      target_types: List[str],
                      method: str) -> AttackEvent:
        """Execute specified attack type on target devices."""
        if attack_type not in self.attacks:
            raise ValueError(f"Unsupported attack type: {attack_type}")
            
        attack = self.attacks[attack_type]
        
        if method == "malware_propagation":
            return attack.propagate_malware(target_types)
        else:
            raise ValueError(f"Unsupported attack method: {method}")
            
    def run_attack_scenario(self,
                          attack_type: str,
                          target_types: List[str],
                          method: str,
                          duration: int = 60,
                          interval: int = 5) -> List[AttackEvent]:
        """Run an attack scenario for specified duration."""
        events = []
        end_time = time.time() + duration
        
        self.logger.info(
            f"Starting {attack_type} attack scenario targeting {target_types}"
        )
        
        while time.time() < end_time:
            event = self.execute_attack(attack_type, target_types, method)
            if event:
                events.append(event)
            time.sleep(interval)
            
        self.logger.info(
            f"Attack scenario completed. Generated {len(events)} events"
        )
        return events

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Test attack simulation
    network = SmartHomeNetwork(num_devices=3)
    simulator = AttackSimulator(network)
    
    events = simulator.run_attack_scenario(
        attack_type="botnet",
        target_types=["SmartCamera", "SmartLock"],
        method="malware_propagation",
        duration=30,
        interval=5
    )
    
    for event in events:
        print(f"\nAttack Event: {event.to_dict()}")