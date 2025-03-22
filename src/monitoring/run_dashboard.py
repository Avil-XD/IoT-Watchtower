import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))

import logging
import time
import threading
from datetime import datetime

from ml.attack_detector import AttackDetector
from simulation.iot_network import IoTSimulation
from simulation.attack_simulator import AttackSimulator
from monitoring.dashboard import MonitoringDashboard

def setup_logging():
    """Configure logging for the dashboard runner."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"dashboard_runner_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("DashboardRunner")

def monitor_network(dashboard, iot_sim, detector, logger):
    """Monitor network and update dashboard."""
    try:
        while True:
            # Get current network status
            status = iot_sim.get_network_status()
            
            # Run detection
            detection_result = detector.detect(status)
            
            # Update dashboard data
            dashboard.update_data(status, detection_result)
            
            # Log significant events
            if detection_result["alert_triggered"]:
                logger.warning(
                    f"Alert! {detection_result['detected_type']} detected "
                    f"with {detection_result['confidence']:.3f} confidence"
                )
            
            time.sleep(5)  # Update every 5 seconds
            
    except Exception as e:
        logger.error(f"Monitoring error: {str(e)}")
        raise

def main():
    logger = setup_logging()
    logger.info("Starting IoT network monitoring dashboard")
    
    dashboard = None
    detector = None
    iot_sim = None
    
    try:
        # Initialize components
        dashboard = MonitoringDashboard()
        detector = AttackDetector()
        
        iot_sim = IoTSimulation(str(project_root / "src/config/network.json"))
        iot_sim.setup_network()
        iot_sim.start_simulation()
        
        # Start monitoring in a separate thread
        monitor_thread = threading.Thread(
            target=monitor_network,
            args=(dashboard, iot_sim, detector, logger),
            daemon=True
        )
        monitor_thread.start()
        
        # Run the dashboard
        dashboard.run(debug=True)
        
    except Exception as e:
        logger.error(f"Dashboard startup failed: {str(e)}")
        raise
    finally:
        logger.info("Stopping simulation...")
        if iot_sim:
            iot_sim.stop_simulation()
        logger.info("Dashboard stopped")

if __name__ == "__main__":
    main()