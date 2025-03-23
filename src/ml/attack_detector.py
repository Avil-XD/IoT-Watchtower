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
        
        # Detection thresholds with severity levels
        self.thresholds = {
            "normal": {
                "min_confidence": 0.7,  # Minimum confidence for normal behavior
                "max_anomaly_score": 0.3  # Maximum allowed anomaly score
            },
            "low": {
                "confidence": 0.5,  # Low severity attack threshold
                "alert_timeout": 300  # 5 minutes between alerts
            },
            "medium": {
                "confidence": 0.7,  # Medium severity attack threshold
                "alert_timeout": 180  # 3 minutes between alerts
            },
            "high": {
                "confidence": 0.9,  # High severity attack threshold
                "alert_timeout": 60  # 1 minute between alerts
            }
        }
        
        # Track last alerts by severity
        self.last_alerts = {
            "low": None,
            "medium": None,
            "high": None
        }

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
        """Extract features from network status with advanced pattern detection."""
        # Network-level features
        network_metrics = [
            network_status["metrics"]["total_bandwidth"],
            network_status["metrics"]["latency"],
            network_status["metrics"]["packet_loss_rate"],
            network_status["metrics"]["error_rate"]
        ]
        
        # Network-level derived features
        network_health = 1.0 - (
            network_status["metrics"]["error_rate"] * 0.4 +
            network_status["metrics"]["packet_loss_rate"] * 0.6
        )
        network_metrics.append(network_health)
        
        # Traffic anomaly score
        baseline_bandwidth = 100  # Typical baseline, adjust based on network
        traffic_anomaly = abs(
            network_status["metrics"]["total_bandwidth"] - baseline_bandwidth
        ) / baseline_bandwidth
        network_metrics.append(traffic_anomaly)
        
        # Device-level features with temporal patterns
        device_metrics = []
        device_ratios = []
        device_anomalies = []
        
        for device in network_status["devices"]:
            metrics = device["metrics"]
            current_metrics = [
                metrics["cpu_usage"],
                metrics["memory_usage"],
                metrics["bandwidth_usage"],
                metrics["packet_count"],
                metrics["error_count"]
            ]
            device_metrics.extend(current_metrics)
            
            # Performance ratios
            if metrics["packet_count"] > 0:
                error_rate = metrics["error_count"] / metrics["packet_count"]
                device_ratios.append(error_rate)
            
            if metrics["bandwidth_usage"] > 0:
                packet_density = metrics["packet_count"] / metrics["bandwidth_usage"]
                device_ratios.append(packet_density)
            
            # Resource utilization patterns
            resource_usage = (metrics["cpu_usage"] + metrics["memory_usage"]) / 2
            device_ratios.append(resource_usage)
            
            # Detect unusual patterns
            cpu_memory_ratio = metrics["cpu_usage"] / max(metrics["memory_usage"], 1)
            bandwidth_packet_ratio = metrics["bandwidth_usage"] / max(metrics["packet_count"], 1)
            
            # Anomaly indicators
            is_cpu_spike = metrics["cpu_usage"] > 80
            is_memory_spike = metrics["memory_usage"] > 80
            is_bandwidth_spike = metrics["bandwidth_usage"] > baseline_bandwidth * 1.5
            is_error_spike = metrics["error_count"] > 10
            
            device_anomalies.extend([
                float(is_cpu_spike),
                float(is_memory_spike),
                float(is_bandwidth_spike),
                float(is_error_spike),
                cpu_memory_ratio,
                bandwidth_packet_ratio
            ])
        
        # Combine all features
        features = network_metrics + device_metrics + device_ratios + device_anomalies
        return np.array(features).reshape(1, -1)

    def detect(self, network_status: Dict) -> Dict:
        """Detect potential attacks in current network status."""
        if not self.model or not self.scaler:
            raise RuntimeError("Model not loaded")
        
        try:
            # Extract and scale features
            features = self.extract_features(network_status)
            features_scaled = self.scaler.transform(features)
            
            # Get prediction and probabilities
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            # Calculate anomaly score
            normal_prob = probabilities[list(self.model.classes_).index("normal")]
            anomaly_score = 1.0 - normal_prob

            # Get initial attack type with highest probability
            class_idx = np.argmax(probabilities)
            attack_type = self.model.classes_[class_idx]
            confidence = probabilities[class_idx]

            # Determine attack severity and type
            severity = None
            is_attack = False
            current_time = datetime.now()

            if attack_type == "normal":
                if (normal_prob >= self.thresholds["normal"]["min_confidence"] and 
                    anomaly_score <= self.thresholds["normal"]["max_anomaly_score"]):
                    is_attack = False
                else:
                    # Abnormal behavior detected, find most likely attack
                    attack_probs = [(cls, prob) for cls, prob in zip(self.model.classes_, probabilities)
                                  if cls != "normal"]
                    if attack_probs:
                        attack_type, confidence = max(attack_probs, key=lambda x: x[1])
                        is_attack = True
            else:
                is_attack = True

            # Determine severity level if it's an attack
            if is_attack:
                if confidence >= self.thresholds["high"]["confidence"]:
                    severity = "high"
                elif confidence >= self.thresholds["medium"]["confidence"]:
                    severity = "medium"
                elif confidence >= self.thresholds["low"]["confidence"]:
                    severity = "low"

            # Check if alert should be triggered based on timeout
            alert_triggered = False
            if severity:
                timeout = self.thresholds[severity]["alert_timeout"]
                last_alert = self.last_alerts[severity]
                
                if not last_alert or (current_time - last_alert).total_seconds() >= timeout:
                    alert_triggered = True
                    self.last_alerts[severity] = current_time
                    self.logger.warning(
                        f"{severity.upper()} severity attack detected: {attack_type} "
                        f"(confidence: {confidence:.3f}, anomaly score: {anomaly_score:.3f})"
                    )

            # Create enhanced detection result
            result = {
                "timestamp": current_time.isoformat(),
                "detected_type": attack_type,
                "is_attack": is_attack,
                "severity": severity,
                "confidence": float(confidence),
                "anomaly_score": float(anomaly_score),
                "alert_triggered": alert_triggered,
                "probabilities": {
                    str(class_name): float(prob)
                    for class_name, prob in zip(self.model.classes_, probabilities)
                }
            }
            
            # Store in history
            self.detection_history.append(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Detection failed: {str(e)}")
            raise

    def analyze_time_window(self, window_seconds: int = 300) -> Dict:
        """Analyze detections over a time window with advanced pattern recognition."""
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
        
        # Initialize analysis counters
        severity_counts = {"high": 0, "medium": 0, "low": 0}
        attack_counts = {}
        alert_count = 0
        attack_count = 0
        total_anomaly_score = 0.0
        
        # Track trends
        attack_sequences = []
        current_sequence = []
        
        for detection in recent_detections:
            attack_type = detection["detected_type"]
            if attack_type not in attack_counts:
                attack_counts[attack_type] = {
                    "count": 0,
                    "alerts": 0,
                    "total_confidence": 0.0,
                    "total_anomaly": 0.0,
                    "by_severity": {"high": 0, "medium": 0, "low": 0}
                }
            
            stats = attack_counts[attack_type]
            stats["count"] += 1
            stats["total_confidence"] += detection["confidence"]
            stats["total_anomaly"] += detection.get("anomaly_score", 0)
            
            if detection["alert_triggered"]:
                stats["alerts"] += 1
                alert_count += 1
            
            if detection["is_attack"]:
                attack_count += 1
                severity = detection.get("severity")
                if severity:
                    severity_counts[severity] += 1
                    stats["by_severity"][severity] += 1
                
                # Track attack sequences
                if not current_sequence or current_sequence[-1]["detected_type"] == attack_type:
                    current_sequence.append(detection)
                else:
                    if len(current_sequence) > 1:
                        attack_sequences.append(current_sequence)
                    current_sequence = [detection]
            
            total_anomaly_score += detection.get("anomaly_score", 0)
        
        # Add final sequence if exists
        if len(current_sequence) > 1:
            attack_sequences.append(current_sequence)
        
        # Calculate averages and trends
        avg_anomaly_score = total_anomaly_score / len(recent_detections)
        for attack_type, stats in attack_counts.items():
            if stats["count"] > 0:
                stats["avg_confidence"] = stats["total_confidence"] / stats["count"]
                stats["avg_anomaly"] = stats["total_anomaly"] / stats["count"]
        
        # Analyze attack patterns
        attack_patterns = []
        for sequence in attack_sequences:
            if len(sequence) >= 3:  # Consider sequences of 3 or more same-type attacks
                pattern = {
                    "attack_type": sequence[0]["detected_type"],
                    "duration": (datetime.fromisoformat(sequence[-1]["timestamp"]).timestamp() - 
                               datetime.fromisoformat(sequence[0]["timestamp"]).timestamp()),
                    "avg_confidence": sum(d["confidence"] for d in sequence) / len(sequence),
                    "count": len(sequence)
                }
                attack_patterns.append(pattern)
        
        return {
            "status": "success",
            "window_seconds": window_seconds,
            "total_detections": len(recent_detections),
            "attack_detections": attack_count,
            "alert_count": alert_count,
            "severity_distribution": severity_counts,
            "attack_stats": attack_counts,
            "avg_anomaly_score": float(avg_anomaly_score),
            "attack_patterns": attack_patterns,
            "latest_detection": recent_detections[-1]
        }

    def get_detection_history(self) -> List[Dict]:
        """Get all historical detections."""
        return self.detection_history

    def clear_history(self):
        """Clear detection history."""
        self.detection_history = []
        self.logger.info("Detection history cleared")