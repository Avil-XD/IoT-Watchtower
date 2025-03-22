import logging
from pathlib import Path
from datetime import datetime
import time
import json

from simulation.iot_network import IoTSimulation
from simulation.attack_simulator import AttackSimulator
from ml.attack_detector import AttackDetector

def setup_logging():
    """Configure test-specific logging."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"detector_test_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("DetectorTest")

def monitor_network(iot_sim, detector, duration=60):
    """Monitor network for specified duration."""
    logger = logging.getLogger("DetectorTest")
    start_time = time.time()
    
    while time.time() - start_time < duration:
        # Get current network status
        status = iot_sim.get_network_status()
        
        # Run detection
        result = detector.detect(status)
        
        # Log results
        if result["alert_triggered"]:
            logger.warning(
                f"Alert! {result['detected_type']} attack detected "
                f"with {result['confidence']:.3f} confidence"
            )
        else:
            logger.info(
                f"Network status: {result['detected_type']} "
                f"(confidence: {result['confidence']:.3f})"
            )
        
        # Brief analysis of recent detections
        analysis = detector.analyze_time_window(window_seconds=30)
        if analysis["status"] == "success":
            logger.info("Recent Activity Summary:")
            logger.info(f"  Total Detections: {analysis['total_detections']}")
            logger.info(f"  Alerts Triggered: {analysis['alert_count']}")
            for attack_type, count in analysis['attack_counts'].items():
                avg_conf = analysis['attack_confidence'].get(attack_type, 0)
                logger.info(f"  {attack_type}: {count} detections "
                          f"(avg confidence: {avg_conf:.3f})")
        
        time.sleep(5)  # Check every 5 seconds

def main():
    logger = setup_logging()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        # Initialize components
        logger.info("Initializing components...")
        detector = AttackDetector()
        detector.alert_threshold = 0.7  # Adjust threshold for better sensitivity
        
        iot_sim = IoTSimulation("src/config/network.json")
        iot_sim.setup_network()
        iot_sim.start_simulation()
        
        attack_sim = AttackSimulator(iot_sim.network)
        
        # Let network stabilize and monitor normal behavior
        logger.info("Monitoring normal network behavior...")
        monitor_network(iot_sim, detector, duration=30)
        
        # Test botnet attack detection
        logger.info("\nSimulating botnet attack...")
        attack_config = attack_sim.create_botnet_attack(
            targets=["camera_01", "lock_01"],
            duration=60
        )
        attack_sim.launch_attack(attack_config)
        monitor_network(iot_sim, detector, duration=60)
        
        # Let network recover
        logger.info("\nWaiting for network recovery...")
        time.sleep(30)
        
        # Test DDoS attack detection
        logger.info("\nSimulating DDoS attack...")
        attack_config = attack_sim.create_ddos_attack(
            targets=["camera_01"],
            duration=60
        )
        attack_sim.launch_attack(attack_config)
        monitor_network(iot_sim, detector, duration=60)
        
        # Final analysis
        logger.info("\nFinal Detection Summary:")
        all_detections = detector.get_detection_history()
        total_alerts = sum(1 for d in all_detections if d["alert_triggered"])
        
        logger.info(f"Total detections: {len(all_detections)}")
        logger.info(f"Total alerts: {total_alerts}")
        
        # Calculate detection statistics
        attack_stats = {}
        for detection in all_detections:
            attack_type = detection["detected_type"]
            if attack_type not in attack_stats:
                attack_stats[attack_type] = {
                    "count": 0,
                    "alerts": 0,
                    "total_confidence": 0
                }
            
            stats = attack_stats[attack_type]
            stats["count"] += 1
            if detection["alert_triggered"]:
                stats["alerts"] += 1
            stats["total_confidence"] += detection["confidence"]
        
        # Save results
        results = {
            "detections": all_detections,
            "summary": {
                "total_detections": len(all_detections),
                "total_alerts": total_alerts,
                "attack_stats": {
                    attack_type: {
                        "total": stats["count"],
                        "alerts": stats["alerts"],
                        "avg_confidence": stats["total_confidence"] / stats["count"]
                    }
                    for attack_type, stats in attack_stats.items()
                },
                "timestamp": datetime.now().isoformat()
            }
        }
        
        # Save results to file
        results_dir = Path("results")
        results_dir.mkdir(exist_ok=True)
        
        results_file = results_dir / f"detection_results_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Results saved to {results_file}")
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        raise
    finally:
        logger.info("Stopping simulation...")
        iot_sim.stop_simulation()
        logger.info("Test completed")

if __name__ == "__main__":
    main()