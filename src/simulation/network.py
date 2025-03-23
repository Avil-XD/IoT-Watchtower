"""
IoT Network Simulation
====================

Simulates a smart home IoT network with multiple device types and network connections.
"""

import json
import logging
from dataclasses import dataclass
from typing import List, Dict
import networkx as nx

@dataclass
class IoTDevice:
    id: str
    type: str
    ip_address: str
    status: str = "online"
    vulnerabilities: List[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "type": self.type,
            "ip_address": self.ip_address,
            "status": self.status,
            "vulnerabilities": self.vulnerabilities or []
        }

class SmartHomeNetwork:
    def __init__(self, num_devices: int = 3):
        self.logger = logging.getLogger(__name__)
        self.network = nx.Graph()
        self.devices: Dict[str, IoTDevice] = {}
        self.connection_type = "WiFi"
        
        # Define device types and their default vulnerabilities
        self.device_types = {
            "SmartCamera": ["weak_password", "unencrypted_stream"],
            "SmartLock": ["weak_authentication", "replay_attack"],
            "SmartThermostat": ["firmware_vulnerability", "unauthorized_access"]
        }
        
        self._initialize_network(num_devices)
    
    def _initialize_network(self, num_devices: int):
        """Initialize the IoT network with specified number of devices."""
        base_ip = "192.168.1"
        
        # Create router node
        router_id = "router_01"
        self.network.add_node(router_id, type="router")
        
        # Create IoT devices
        for i, (device_type, vulnerabilities) in enumerate(self.device_types.items(), 1):
            if i > num_devices:
                break
                
            device_id = f"{device_type.lower()}_{i:02d}"
            device = IoTDevice(
                id=device_id,
                type=device_type,
                ip_address=f"{base_ip}.{i+10}",
                vulnerabilities=vulnerabilities.copy()
            )
            
            self.devices[device_id] = device
            self.network.add_node(device_id, **device.to_dict())
            
            # Connect device to router
            self.network.add_edge(router_id, device_id, type=self.connection_type)
            
            self.logger.info(f"Added device: {device_id} ({device.type})")
    
    def get_device(self, device_id: str) -> IoTDevice:
        """Get device by ID."""
        return self.devices.get(device_id)
    
    def get_devices_by_type(self, device_type: str) -> List[IoTDevice]:
        """Get all devices of specified type."""
        return [d for d in self.devices.values() if d.type == device_type]
    
    def update_device_status(self, device_id: str, status: str):
        """Update device status."""
        if device_id in self.devices:
            self.devices[device_id].status = status
            self.network.nodes[device_id]["status"] = status
            self.logger.info(f"Updated {device_id} status to {status}")
    
    def get_network_state(self) -> Dict:
        """Get current state of the network."""
        return {
            "devices": [d.to_dict() for d in self.devices.values()],
            "connection_type": self.connection_type,
            "topology": {
                "nodes": list(self.network.nodes()),
                "edges": list(self.network.edges())
            }
        }
    
    def to_json(self) -> str:
        """Convert network state to JSON string."""
        return json.dumps(self.get_network_state(), indent=2)

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Test network setup
    network = SmartHomeNetwork(num_devices=3)
    print(network.to_json())