import logging
from pathlib import Path
from datetime import datetime
import numpy as np
from typing import Dict, Optional, List
import joblib
import json

class AttackDetector:
    def __init__(self):
        """Initialize the attack detector with the latest trained model."""
        self._setup_logging()
        self.model = None
        self.scaler = None
        self.load_latest_model()
        self.detection_history = []
        self.alert_threshold = 0.8  # Confidence threshold for alerts

    def _setup_logging(self):
        """Configure detector-specific logging."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"attack_detector_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("AttackDetector")

    def load_latest_model(self):
        """Load the most recently trained model and scaler."""
        try:
            models_dir = Path("models")
            
            # Find latest model files
            model_files = list(models_dir.glob("attack_classifier_*.joblib"))
            scaler_files = list(models_dir.glob("feature_scaler_*.joblib"))
            
            if not model_files or not scaler_files:
                raise FileNotFoundError("No model or scaler files found")
            
            latest_model = max(model_files, key=lambda x: x.stat().st_mtime)
            latest_scaler = max(scaler_files, key=lambda x: x.stat().st_mtime)
            
            self.model = joblib.load(latest_model)
            self.scaler = joblib.load(latest_scaler)
            
            self.logger.info(f"Loaded model from {latest_model}")
            self.logger.info(f"Loaded scaler from {latest_scaler}")
            
        except Exception as e:
            self.logger.error(f"Failed to load model: {str(e)}")
            raise

    def extract_features(self, network_status: Dict) -> np.ndarray:
        """Extract features from network status for prediction."""
        # Extract network-level metrics
        network_metrics = [
            network_status["metrics"]["total_bandwidth"],
            network_status["metrics"]["latency"],
            network_status["metrics"]["packet_loss_rate"],
            network_status["metrics"]["error_rate"]
        ]
        
        # Extract device-level metrics
        device_metrics = []
        for device in network_status["devices"]:
            device_metrics.extend([
                device["metrics"]["cpu_usage"],
                device["metrics"]["memory_usage"],
                device["metrics"]["bandwidth_usage"],
                device["metrics"]["packet_count"],
                device["metrics"]["error_count"]
            ])
        
        return np.array(network_metrics + device_metrics).reshape(1, -1)

    def detect(self, network_status: Dict) -> Dict:
        """Detect potential attacks in current network status."""
        if not self.model or not self.scaler:
            raise RuntimeError("Model not loaded")
        
        try:
            # Extract and scale features
            features = self.extract_features(network_status)
            features_scaled = self.scaler.transform(features)
            
            # Get prediction and probabilities
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            confidence = max(probabilities)
            
            # Create detection result
            result = {
                "timestamp": datetime.now().isoformat(),
                "detected_type": prediction,
                "confidence": float(confidence),
                "alert_triggered": confidence >= self.alert_threshold,
                "probabilities": {
                    class_name: float(prob)
                    for class_name, prob in zip(self.model.classes_, probabilities)
                }
            }
            
            # Store in history
            self.detection_history.append(result)
            
            # Log if alert threshold exceeded
            if result["alert_triggered"]:
                self.logger.warning(
                    f"Attack detected: {prediction} "
                    f"(confidence: {confidence:.3f})"
                )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Detection failed: {str(e)}")
            raise

    def analyze_time_window(self, window_seconds: int = 300) -> Dict:
        """Analyze detections over a time window."""
        if not self.detection_history:
            return {"status": "no_data"}
        
        current_time = datetime.now()
        window_start = current_time.timestamp() - window_seconds
        
        # Filter detections within window
        recent_detections = [
            d for d in self.detection_history
            if datetime.fromisoformat(d["timestamp"]).timestamp() > window_start
        ]
        
        if not recent_detections:
            return {"status": "no_recent_data"}
        
        # Count attack types
        attack_counts = {}
        alert_count = 0
        
        for detection in recent_detections:
            attack_type = detection["detected_type"]
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
            if detection["alert_triggered"]:
                alert_count += 1
        
        # Calculate average confidence per attack type
        attack_confidence = {}
        for detection in recent_detections:
            attack_type = detection["detected_type"]
            if attack_type not in attack_confidence:
                attack_confidence[attack_type] = []
            attack_confidence[attack_type].append(detection["confidence"])
        
        for attack_type in attack_confidence:
            attack_confidence[attack_type] = np.mean(attack_confidence[attack_type])
        
        return {
            "status": "success",
            "window_seconds": window_seconds,
            "total_detections": len(recent_detections),
            "alert_count": alert_count,
            "attack_counts": attack_counts,
            "attack_confidence": attack_confidence,
            "latest_detection": recent_detections[-1]
        }

    def get_detection_history(self) -> List[Dict]:
        """Get all historical detections."""
        return self.detection_history

    def clear_history(self):
        """Clear detection history."""
        self.detection_history = []
        self.logger.info("Detection history cleared")

if __name__ == "__main__":
    # Test the detector
    detector = AttackDetector()
    
    # Example network status for testing
    test_status = {
        "metrics": {
            "total_bandwidth": 150.0,
            "latency": 50,
            "packet_loss_rate": 0.01,
            "error_rate": 0.002
        },
        "devices": [
            {
                "metrics": {
                    "cpu_usage": 75.0,
                    "memory_usage": 60.0,
                    "bandwidth_usage": 45.0,
                    "packet_count": 1000,
                    "error_count": 5
                }
            }
        ]
    }
    
    # Test detection
    result = detector.detect(test_status)
    print(f"Detection result: {json.dumps(result, indent=2)}")