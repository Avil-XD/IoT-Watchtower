import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import threading
import time
import random

class IoTDevice:
    def __init__(self, device_id: str, device_type: str, protocols: List[str], 
                 security_features: List[str], properties: Dict):
        self.id = device_id
        self.type = device_type
        self.protocols = protocols
        self.security_features = security_features
        self.properties = properties
        self.status = "offline"
        self.connected_devices = []
        self.metrics = {
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "bandwidth_usage": 0.0,
            "packet_count": 0,
            "error_count": 0
        }
        
    def connect(self):
        """Simulate device connecting to network."""
        self.status = "online"
        
    def disconnect(self):
        """Simulate device disconnecting from network."""
        self.status = "offline"
        
    def update_metrics(self):
        """Update device performance metrics."""
        self.metrics["cpu_usage"] = random.uniform(10, 90)
        self.metrics["memory_usage"] = random.uniform(20, 80)
        self.metrics["bandwidth_usage"] = random.uniform(0, 100)
        self.metrics["packet_count"] += random.randint(10, 100)
        
        # Simulate occasional errors
        if random.random() < 0.05:  # 5% chance of error
            self.metrics["error_count"] += 1

    def get_status(self) -> Dict:
        """Get current device status and metrics."""
        return {
            "id": self.id,
            "type": self.type,
            "status": self.status,
            "metrics": self.metrics,
            "security_features": self.security_features
        }

class IoTNetwork:
    def __init__(self, connection_type: str, simulation_params: Dict):
        self.connection_type = connection_type
        self.simulation_params = simulation_params
        self.devices: Dict[str, IoTDevice] = {}
        self.is_running = False
        self.update_thread = None
        self.network_metrics = {
            "latency": simulation_params.get("network_latency", 50),
            "packet_loss_rate": simulation_params.get("packet_loss_rate", 0.01),
            "total_bandwidth": 0.0,
            "total_packets": 0,
            "error_rate": 0.0
        }
        
    def add_device(self, device: IoTDevice):
        """Add device to network."""
        self.devices[device.id] = device
        
    def remove_device(self, device_id: str):
        """Remove device from network."""
        if device_id in self.devices:
            self.devices[device_id].disconnect()
            del self.devices[device_id]
            
    def start(self):
        """Start network simulation."""
        self.is_running = True
        for device in self.devices.values():
            device.connect()
            
        # Start metrics update thread
        self.update_thread = threading.Thread(target=self._update_loop)
        self.update_thread.daemon = True
        self.update_thread.start()
        
    def stop(self):
        """Stop network simulation."""
        self.is_running = False
        if self.update_thread:
            self.update_thread.join()
        for device in self.devices.values():
            device.disconnect()
            
    def _update_loop(self):
        """Background thread to update network and device metrics."""
        while self.is_running:
            self._update_network_metrics()
            for device in self.devices.values():
                device.update_metrics()
            time.sleep(1)  # Update every second
            
    def _update_network_metrics(self):
        """Update network-wide metrics."""
        total_bandwidth = 0
        total_packets = 0
        total_errors = 0
        
        for device in self.devices.values():
            total_bandwidth += device.metrics["bandwidth_usage"]
            total_packets += device.metrics["packet_count"]
            total_errors += device.metrics["error_count"]
            
        self.network_metrics["total_bandwidth"] = total_bandwidth
        self.network_metrics["total_packets"] = total_packets
        self.network_metrics["error_rate"] = total_errors / max(total_packets, 1)
        
    def get_status(self) -> Dict:
        """Get current network status including all devices."""
        return {
            "connection_type": self.connection_type,
            "device_count": len(self.devices),
            "metrics": self.network_metrics,
            "devices": [device.get_status() for device in self.devices.values()]
        }

class IoTSimulation:
    def __init__(self, config_path: str):
        """Initialize IoT network simulation."""
        self.config = self._load_config(config_path)
        self.network = None
        
        # Set up logging
        self._setup_logging()
        
    def _load_config(self, config_path: str) -> dict:
        """Load network configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            raise Exception(f"Configuration file not found: {config_path}")
        except json.JSONDecodeError:
            raise Exception(f"Invalid JSON in configuration file: {config_path}")

    def _setup_logging(self):
        """Configure logging for the simulation."""
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
        self.logger = logging.getLogger("IoTSimulation")

    def setup_network(self):
        """Initialize and configure the IoT network."""
        try:
            network_config = self.config['network']
            self.logger.info(f"Setting up network with {network_config['num_devices']} devices")
            
            # Initialize network
            self.network = IoTNetwork(
                connection_type=network_config['connection_type'],
                simulation_params=network_config['simulation']
            )
            
            # Set up devices
            for device_config in network_config['devices']:
                self._setup_device(device_config)
                
            self.logger.info("Network setup completed successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to setup network: {str(e)}")
            raise

    def _setup_device(self, device_config: dict):
        """Configure and add a device to the network."""
        try:
            self.logger.info(f"Setting up device: {device_config['id']} ({device_config['type']})")
            
            device = IoTDevice(
                device_id=device_config['id'],
                device_type=device_config['type'],
                protocols=device_config['protocols'],
                security_features=device_config['security_features'],
                properties=device_config['properties']
            )
            self.network.add_device(device)
            
        except Exception as e:
            self.logger.error(f"Failed to setup device {device_config['id']}: {str(e)}")
            raise

    def start_simulation(self):
        """Start the IoT network simulation."""
        try:
            self.logger.info("Starting simulation")
            if self.network:
                self.network.start()
            else:
                raise Exception("Network not initialized. Call setup_network() first.")
            
        except Exception as e:
            self.logger.error(f"Failed to start simulation: {str(e)}")
            raise

    def stop_simulation(self):
        """Stop the IoT network simulation."""
        try:
            self.logger.info("Stopping simulation")
            if self.network:
                self.network.stop()
            
        except Exception as e:
            self.logger.error(f"Failed to stop simulation: {str(e)}")
            raise

    def get_network_status(self) -> Dict:
        """Get current status of the network and all devices."""
        if not self.network:
            raise Exception("Network not initialized")
        return self.network.get_status()

if __name__ == "__main__":
    # Initialize and run simulation
    config_path = Path(__file__).parent.parent / "config" / "network.json"
    simulation = IoTSimulation(str(config_path))
    
    try:
        simulation.setup_network()
        simulation.start_simulation()
        
        # Keep simulation running for specified duration
        duration = simulation.config['network']['simulation']['duration']
        start_time = time.time()
        
        while time.time() - start_time < duration:
            status = simulation.get_network_status()
            print(f"\nNetwork Status at {time.time() - start_time:.1f}s:")
            print(json.dumps(status, indent=2))
            time.sleep(5)  # Update status every 5 seconds
            
        simulation.stop_simulation()
        
    except Exception as e:
        logging.error(f"Simulation failed: {str(e)}")
        raise