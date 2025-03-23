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
    def __init__(self, network: Optional[SmartHomeNetwork] = None):
        """Initialize attack simulator with network."""
        self.network = network or SmartHomeNetwork(num_devices=3)
        self.logger = logging.getLogger(__name__)
        self.attacks = {
            "botnet": BotnetAttack(self.network)
        }
        self.active_events: List[AttackEvent] = []
        
    def get_network_status(self) -> Dict:
        """Get current network status including device metrics."""
        network_state = self.network.get_network_state()
        
        # Add simulated metrics
        for device in network_state["devices"]:
            device["metrics"] = self._generate_device_metrics(device)
            
        network_state["metrics"] = self._generate_network_metrics()
        return network_state
    
    def _generate_device_metrics(self, device: Dict) -> Dict:
        """Generate realistic device metrics based on state."""
        is_infected = device["status"] == "infected"
        is_compromised = device["status"] == "compromised"
        
        base_cpu = 20 if not is_infected else random.uniform(70, 95)
        base_memory = 30 if not is_infected else random.uniform(60, 90)
        
        return {
            "cpu_usage": min(100, base_cpu + random.uniform(-5, 5)),
            "memory_usage": min(100, base_memory + random.uniform(-5, 5)),
            "bandwidth_usage": random.uniform(20, 90) if is_infected else random.uniform(5, 30),
            "packet_count": int(random.uniform(100, 1000)) if is_infected else int(random.uniform(10, 100)),
            "error_count": int(random.uniform(50, 200)) if is_compromised else int(random.uniform(0, 10)),
            "stream_latency": random.uniform(100, 300) if is_infected else random.uniform(20, 100),
            "video_quality": random.uniform(0.3, 0.6) if is_compromised else random.uniform(0.8, 1.0),
            "failed_auths": int(random.uniform(5, 20)) if is_compromised else int(random.uniform(0, 3)),
            "battery_level": random.uniform(0.2, 0.4) if is_infected else random.uniform(0.7, 1.0),
            "temperature": random.uniform(18, 26),
            "energy_consumption": random.uniform(40, 80) if is_infected else random.uniform(10, 30)
        }
    
    def _generate_network_metrics(self) -> Dict:
        """Generate overall network metrics."""
        infected_count = len(self.attacks["botnet"].infected_devices)
        is_under_attack = infected_count > 0
        
        return {
            "total_bandwidth": random.uniform(50, 90) if is_under_attack else random.uniform(10, 40),
            "latency": random.uniform(100, 300) if is_under_attack else random.uniform(20, 80),
            "packet_loss_rate": random.uniform(0.1, 0.3) if is_under_attack else random.uniform(0, 0.05),
            "error_rate": random.uniform(0.2, 0.5) if is_under_attack else random.uniform(0, 0.1),
            "connection_stability": random.uniform(0.4, 0.7) if is_under_attack else random.uniform(0.9, 1.0)
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
            event = attack.propagate_malware(target_types)
            if event:
                self.active_events.append(event)
            return event
        else:
            raise ValueError(f"Unsupported attack method: {method}")
            
    def get_attack_status(self, event: AttackEvent) -> Dict:
        """Get current status of an attack event."""
        return {
            "status": "active" if event in self.active_events else "completed",
            "target_devices": [
                device.id for device in self.network.devices.values()
                if device.status in ["infected", "compromised"]
            ],
            "success": event.success,
            "details": event.details
        }
            
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