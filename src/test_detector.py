import logging
from pathlib import Path
from datetime import datetime, timezone
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
    detections = []
    
    while time.time() - start_time < duration:
        # Get current network status
        status = iot_sim.get_network_status()
        
        # Run detection
        result = detector.detect(status)
        detections.append(result)
        
        # Log results
        if result["alert_triggered"]:
            if result["is_attack"]:
                logger.warning(
                    f"Attack Alert! {result['detected_type']} detected "
                    f"with {result['confidence']:.3f} confidence"
                )
            else:
                logger.info(
                    f"State Change: {result['detected_type']} behavior "
                    f"(confidence: {result['confidence']:.3f})"
                )
        
        # Brief analysis of recent detections
        analysis = detector.analyze_time_window(window_seconds=30)
        if analysis["status"] == "success":
            logger.info("Recent Activity Summary:")
            logger.info(f"  Total Detections: {analysis['total_detections']}")
            logger.info(f"  Attack Detections: {analysis['attack_detections']}")
            logger.info(f"  Alerts Triggered: {analysis['alert_count']}")
            for attack_type, stats in analysis['attack_stats'].items():
                logger.info(
                    f"  {attack_type}: {stats['count']} detections, "
                    f"{stats['alerts']} alerts "
                    f"(avg conf: {stats['avg_confidence']:.3f})"
                )
        
        time.sleep(5)  # Check every 5 seconds
    
    return detections

def analyze_test_results(all_detections: list) -> dict:
    """Analyze the complete test results."""
    phases = {
        "normal": [],
        "botnet": [],
        "ddos": []
    }
    
    current_phase = "normal"
    for detection in all_detections:
        if current_phase == "normal" and len(phases["normal"]) >= 6:
            current_phase = "botnet"
        elif current_phase == "botnet" and len(phases["botnet"]) >= 12:
            current_phase = "ddos"
            
        phases[current_phase].append(detection)
    
    analysis = {
        "phases": {},
        "overall": {
            "total_detections": len(all_detections),
            "attack_detections": sum(1 for d in all_detections if d["is_attack"]),
            "false_positives": 0,
            "false_negatives": 0
        }
    }
    
    # Analyze each phase
    for phase_name, detections in phases.items():
        if not detections:
            continue
            
        phase_analysis = {
            "detections": len(detections),
            "alerts": sum(1 for d in detections if d["alert_triggered"]),
            "attacks_detected": sum(1 for d in detections if d["is_attack"]),
            "avg_confidence": sum(d["confidence"] for d in detections) / len(detections),
            "detection_types": {}
        }
        
        # Count detection types
        for detection in detections:
            det_type = detection["detected_type"]
            if det_type not in phase_analysis["detection_types"]:
                phase_analysis["detection_types"][det_type] = 0
            phase_analysis["detection_types"][det_type] += 1
        
        # Calculate false positives/negatives
        if phase_name == "normal":
            phase_analysis["false_positives"] = sum(
                1 for d in detections if d["is_attack"]
            )
            analysis["overall"]["false_positives"] += phase_analysis["false_positives"]
        else:
            phase_analysis["false_negatives"] = sum(
                1 for d in detections if not d["is_attack"]
            )
            analysis["overall"]["false_negatives"] += phase_analysis["false_negatives"]
        
        analysis["phases"][phase_name] = phase_analysis
    
    return analysis

def main():
    logger = setup_logging()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        # Initialize components
        logger.info("Initializing components...")
        detector = AttackDetector()
        
        iot_sim = IoTSimulation("src/config/network.json")
        iot_sim.setup_network()
        iot_sim.start_simulation()
        
        attack_sim = AttackSimulator(iot_sim.network)
        
        all_detections = []
        
        # Monitor normal behavior
        logger.info("Monitoring normal network behavior...")
        normal_detections = monitor_network(iot_sim, detector, duration=30)
        all_detections.extend(normal_detections)
        
        # Test botnet attack detection
        logger.info("\nSimulating botnet attack...")
        attack_config = attack_sim.create_botnet_attack(
            targets=["camera_01", "lock_01"],
            duration=60
        )
        attack_sim.launch_attack(attack_config)
        botnet_detections = monitor_network(iot_sim, detector, duration=60)
        all_detections.extend(botnet_detections)
        
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
        ddos_detections = monitor_network(iot_sim, detector, duration=60)
        all_detections.extend(ddos_detections)
        
        # Analyze results
        logger.info("\nAnalyzing test results...")
        analysis = analyze_test_results(all_detections)
        
        # Log analysis summary
        logger.info("\nTest Analysis Summary:")
        logger.info(f"Total Detections: {analysis['overall']['total_detections']}")
        logger.info(f"Attack Detections: {analysis['overall']['attack_detections']}")
        logger.info(f"False Positives: {analysis['overall']['false_positives']}")
        logger.info(f"False Negatives: {analysis['overall']['false_negatives']}")
        
        for phase, stats in analysis["phases"].items():
            logger.info(f"\n{phase.upper()} Phase:")
            logger.info(f"  Detections: {stats['detections']}")
            logger.info(f"  Alerts: {stats['alerts']}")
            logger.info(f"  Attacks Detected: {stats['attacks_detected']}")
            logger.info(f"  Avg Confidence: {stats['avg_confidence']:.3f}")
            logger.info("  Detection Types:")
            for det_type, count in stats["detection_types"].items():
                logger.info(f"    {det_type}: {count}")
        
        # Save results
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detections": [
                {
                    "timestamp": d["timestamp"],
                    "detected_type": d["detected_type"],
                    "is_attack": d["is_attack"],
                    "confidence": d["confidence"],
                    "alert_triggered": d["alert_triggered"],
                    "probabilities": d["probabilities"]
                }
                for d in all_detections
            ],
            "analysis": analysis
        }
        
        results_dir = Path("results")
        results_dir.mkdir(exist_ok=True)
        
        results_file = results_dir / f"detection_results_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"\nResults saved to {results_file}")
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        raise
    finally:
        logger.info("Stopping simulation...")
        iot_sim.stop_simulation()
        logger.info("Test completed")

if __name__ == "__main__":
    main()