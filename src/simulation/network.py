from typing import Dict, List, Any
import random
from datetime import datetime

class IoTDevice:
    def __init__(self, device_id: str, device_type: str):
        """Initialize an IoT device with smart home capabilities."""
        self.id = device_id
        self.type = device_type
        self.status = "normal"
        self.connection_type = "WiFi"
        self.metrics = self._init_metrics()
        self.security_level = random.uniform(0.6, 0.9)  # Device security rating
        self.vulnerabilities = self._init_vulnerabilities()

    def _init_metrics(self) -> Dict:
        """Initialize device metrics based on type."""
        base_metrics = {
            "cpu_usage": random.uniform(20, 40),
            "memory_usage": random.uniform(30, 50),
            "bandwidth_usage": random.uniform(10, 30),
            "packet_count": random.randint(100, 500),
            "error_count": random.randint(0, 5),
            "connection_strength": random.uniform(0.7, 1.0)
        }

        # Add device-specific metrics
        if self.type == "SmartCamera":
            base_metrics.update({
                "video_quality": random.uniform(0.8, 1.0),
                "stream_latency": random.uniform(50, 200),  # ms
                "motion_detection": "enabled"
            })
        elif self.type == "SmartLock":
            base_metrics.update({
                "battery_level": random.uniform(0.7, 1.0),
                "successful_auths": random.randint(10, 50),
                "failed_auths": random.randint(0, 5)
            })
        elif self.type == "SmartThermostat":
            base_metrics.update({
                "temperature": random.uniform(20, 25),  # Celsius
                "humidity": random.uniform(40, 60),
                "energy_consumption": random.uniform(10, 30)
            })

        return base_metrics

    def _init_vulnerabilities(self) -> Dict:
        """Initialize potential device vulnerabilities."""
        vuln_types = {
            "SmartCamera": ["weak_password", "unencrypted_stream", "firmware_outdated"],
            "SmartLock": ["replay_attack", "brute_force", "firmware_outdated"],
            "SmartThermostat": ["command_injection", "firmware_outdated"]
        }
        
        return {
            vuln: random.random() < 0.3  # 30% chance of vulnerability
            for vuln in vuln_types.get(self.type, [])
        }

    def update_status(self):
        """Update device metrics and status."""
        # Normal fluctuations
        self.metrics["cpu_usage"] *= random.uniform(0.9, 1.1)
        self.metrics["memory_usage"] *= random.uniform(0.95, 1.05)
        self.metrics["bandwidth_usage"] *= random.uniform(0.9, 1.1)
        
        # Device-specific updates
        if self.type == "SmartCamera":
            self.metrics["stream_latency"] *= random.uniform(0.9, 1.1)
        elif self.type == "SmartLock":
            self.metrics["battery_level"] = max(0, self.metrics["battery_level"] - random.uniform(0, 0.01))
        elif self.type == "SmartThermostat":
            self.metrics["temperature"] += random.uniform(-0.5, 0.5)

class IoTNetwork:
    def __init__(self):
        """Initialize the smart home IoT network."""
        self.devices = {}
        self.metrics = {
            "total_bandwidth": 0,
            "latency": random.uniform(5, 15),
            "packet_loss_rate": random.uniform(0.01, 0.03),
            "error_rate": random.uniform(0.01, 0.02),
            "connection_stability": random.uniform(0.9, 1.0)
        }
        self._setup_devices()
        self.attack_history = []

    def _setup_devices(self):
        """Set up default IoT devices."""
        devices = [
            ("camera_1", "SmartCamera"),
            ("lock_1", "SmartLock"),
            ("thermostat_1", "SmartThermostat")
        ]
        
        for device_id, device_type in devices:
            self.devices[device_id] = IoTDevice(device_id, device_type)

    def update_metrics(self):
        """Update network metrics based on device states."""
        # Update devices
        for device in self.devices.values():
            device.update_status()

        # Calculate network-wide metrics
        total_bandwidth = sum(d.metrics["bandwidth_usage"] for d in self.devices.values())
        self.metrics["total_bandwidth"] = total_bandwidth
        
        # Adjust metrics based on load
        load_factor = total_bandwidth / (100 * len(self.devices))
        self.metrics["latency"] *= (1 + 0.1 * load_factor)
        self.metrics["packet_loss_rate"] *= (1 + 0.2 * load_factor)
        self.metrics["error_rate"] *= (1 + 0.15 * load_factor)
        
        # Update connection stability
        self.metrics["connection_stability"] = max(
            0.6,
            self.metrics["connection_stability"] * random.uniform(0.95, 1.05)
        )

    def get_status(self) -> Dict[str, Any]:
        """Get current network status."""
        self.update_metrics()
        return {
            "timestamp": datetime.now().isoformat(),
            "metrics": self.metrics.copy(),
            "devices": [
                {
                    "id": device.id,
                    "type": device.type,
                    "status": device.status,
                    "metrics": device.metrics.copy(),
                    "security_level": device.security_level,
                    "vulnerabilities": device.vulnerabilities.copy()
                }
                for device in self.devices.values()
            ]
        }

    def record_attack(self, attack_data: Dict):
        """Record an attack event in the network history."""
        attack_data["timestamp"] = datetime.now().isoformat()
        self.attack_history.append(attack_data)