import logging
from pathlib import Path
from datetime import datetime
import numpy as np
from typing import Dict, Optional, List
import joblib
import json

class AttackDetector:
    def __init__(self):
        """Initialize the attack detector with ML-based classification."""
        self._setup_logging()
        self.model = None
        self.scaler = None
        self.load_latest_model()
        self.detection_history = []
        
        # Enhanced detection thresholds with pattern recognition
        self.thresholds = {
            "normal": {
                "min_confidence": 0.8,    # Higher confidence for normal state
                "max_anomaly_score": 0.2  # Lower anomaly tolerance
            },
            "low": {
                "confidence": 0.6,        # Base confidence for low severity
                "alert_timeout": 300,     # 5 minutes between alerts
                "consecutive_alerts": 2    # Minimum alerts to escalate
            },
            "medium": {
                "confidence": 0.75,       # Higher confidence for medium severity
                "alert_timeout": 180,     # 3 minutes between alerts
                "consecutive_alerts": 3    # Alerts before high severity
            },
            "high": {
                "confidence": 0.9,        # Highest confidence requirement
                "alert_timeout": 60,      # 1 minute between alerts
                "pattern_boost": 0.1      # Boost for recognized patterns
            }
        }
        
        # Track alert history
        self.alert_history = {
            "low": {"last_alert": None, "consecutive": 0},
            "medium": {"last_alert": None, "consecutive": 0},
            "high": {"last_alert": None, "consecutive": 0}
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
        """Load the most recent model with metadata."""
        try:
            models_dir = Path("models")
            if not models_dir.exists():
                self.logger.warning("Models directory not found, using rule-based detection")
                return

            # Find latest model files
            model_files = list(models_dir.glob("attack_classifier_*.joblib"))
            scaler_files = list(models_dir.glob("feature_scaler_*.joblib"))
            metadata_files = list(models_dir.glob("model_metadata_*.json"))
            
            if not model_files or not scaler_files:
                self.logger.warning("Model or scaler files not found, using rule-based detection")
                return
            
            # Load model and scaler
            latest_model = max(model_files, key=lambda x: x.stat().st_mtime)
            latest_scaler = max(scaler_files, key=lambda x: x.stat().st_mtime)
            
            self.model = joblib.load(latest_model)
            self.scaler = joblib.load(latest_scaler)
            
            # Load metadata if available
            if metadata_files:
                latest_metadata = max(metadata_files, key=lambda x: x.stat().st_mtime)
                with open(latest_metadata, 'r') as f:
                    self.metadata = json.load(f)
            
            self.logger.info(f"Loaded model from {latest_model}")
            self.logger.info(f"Performance metrics: {self.metadata.get('performance', {}).get('accuracy', 'N/A')}")
            
        except Exception as e:
            self.logger.warning(f"Failed to load model: {str(e)}. Using rule-based detection.")

    def _detect_with_rules(self, network_status: Dict, current_time: datetime) -> Dict:
        """Rule-based attack detection when ML model is not available."""
        # Extract key metrics
        metrics = network_status["metrics"]
        error_rate = metrics["error_rate"]
        packet_loss = metrics["packet_loss_rate"]
        
        # Initialize detection result
        attack_type = "normal"
        is_attack = False
        confidence = 0.0
        severity = None
        anomaly_score = 0.0
        
        # Check for suspicious network behavior
        if error_rate > 0.5 or packet_loss > 0.3:
            attack_type = "network_flood"
            is_attack = True
            confidence = min(1.0, max(error_rate, packet_loss))
            anomaly_score = confidence
        
        # Check device status
        compromised_count = sum(
            1 for device in network_status["devices"]
            if device["status"] == "compromised"
        )
        high_resource_count = sum(
            1 for device in network_status["devices"]
            if device["metrics"]["cpu_usage"] > 90 or
               device["metrics"]["memory_usage"] > 90
        )
        
        if compromised_count > 0:
            attack_type = "device_compromise"
            is_attack = True
            confidence = min(1.0, compromised_count * 0.4)
            anomaly_score = max(anomaly_score, confidence)
        
        if high_resource_count > 1:
            attack_type = "resource_abuse"
            is_attack = True
            confidence = min(1.0, high_resource_count * 0.3)
            anomaly_score = max(anomaly_score, confidence)
        
        # Determine severity based on confidence and impact
        if is_attack:
            if confidence >= 0.8 or compromised_count > 1:
                severity = "high"
            elif confidence >= 0.6 or high_resource_count > 1:
                severity = "medium"
            else:
                severity = "low"
        
        # Check alert triggers and escalation
        alert_triggered = False
        if severity:
            alert_info = self.alert_history[severity]
            timeout = self.thresholds[severity]["alert_timeout"]
            
            if not alert_info["last_alert"] or (
                current_time - alert_info["last_alert"]
            ).total_seconds() >= timeout:
                alert_triggered = True
                alert_info["last_alert"] = current_time
                alert_info["consecutive"] += 1
                
                if alert_info["consecutive"] >= self.thresholds[severity]["consecutive_alerts"]:
                    if severity == "low":
                        severity = "medium"
                    elif severity == "medium":
                        severity = "high"
                
                self.logger.warning(
                    f"{severity.upper()} severity {attack_type} detected (Rule-based)!\n"
                    f"Confidence: {confidence:.3f}, Anomaly Score: {anomaly_score:.3f}\n"
                    f"Consecutive Alerts: {alert_info['consecutive']}"
                )
        
        result = {
            "timestamp": current_time.isoformat(),
            "detected_type": attack_type,
            "is_attack": is_attack,
            "severity": severity,
            "confidence": float(confidence),
            "anomaly_score": float(anomaly_score),
            "alert_triggered": alert_triggered,
            "consecutive_alerts": self.alert_history[severity]["consecutive"] if severity else 0,
            "detection_method": "rule-based"
        }
        
        # Store in history
        self.detection_history.append(result)
        return result

    def detect(self, network_status: Dict) -> Dict:
        """Enhanced attack detection with pattern recognition."""
        current_time = datetime.now()
        
        if self.model and self.scaler:
            return self._detect_with_model(network_status, current_time)
        else:
            return self._detect_with_rules(network_status, current_time)
            
    def _detect_with_model(self, network_status: Dict, current_time: datetime) -> Dict:
        """ML-based attack detection."""
        
        try:
            # Extract and scale features
            features = self._extract_features(network_status)
            features_scaled = self.scaler.transform(features)
            
            # Get prediction and probabilities
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            # Calculate anomaly score
            normal_idx = list(self.model.classes_).index("normal")
            normal_prob = probabilities[normal_idx]
            anomaly_score = 1.0 - normal_prob

            # Get initial attack type with highest probability
            class_idx = np.argmax(probabilities)
            attack_type = self.model.classes_[class_idx]
            confidence = probabilities[class_idx]
            
            # Pattern recognition boost
            pattern_boost = self._check_attack_patterns(attack_type)
            confidence = min(1.0, confidence + pattern_boost)

            # Determine attack characteristics
            severity = None
            is_attack = False
            current_time = datetime.now()

            if attack_type == "normal":
                if (normal_prob >= self.thresholds["normal"]["min_confidence"] and 
                    anomaly_score <= self.thresholds["normal"]["max_anomaly_score"]):
                    is_attack = False
                else:
                    # Abnormal behavior, find most likely attack
                    attack_probs = [(cls, prob) for cls, prob in zip(self.model.classes_, probabilities)
                                  if cls != "normal"]
                    if attack_probs:
                        attack_type, confidence = max(attack_probs, key=lambda x: x[1])
                        is_attack = True
            else:
                is_attack = True

            # Enhanced severity determination
            if is_attack:
                severity = self._determine_severity(
                    attack_type, confidence, anomaly_score, network_status
                )

            # Check alert triggers with timeout and escalation
            alert_triggered = False
            if severity:
                alert_info = self.alert_history[severity]
                timeout = self.thresholds[severity]["alert_timeout"]
                
                if not alert_info["last_alert"] or (
                    current_time - alert_info["last_alert"]
                ).total_seconds() >= timeout:
                    alert_triggered = True
                    alert_info["last_alert"] = current_time
                    alert_info["consecutive"] += 1
                    
                    if alert_info["consecutive"] >= self.thresholds[severity]["consecutive_alerts"]:
                        # Escalate severity if pattern persists
                        if severity == "low":
                            severity = "medium"
                        elif severity == "medium":
                            severity = "high"
                    
                    self.logger.warning(
                        f"{severity.upper()} severity {attack_type} attack detected!\n"
                        f"Confidence: {confidence:.3f}, Anomaly Score: {anomaly_score:.3f}\n"
                        f"Consecutive Alerts: {alert_info['consecutive']}"
                    )

            # Enhanced detection result
            result = {
                "timestamp": current_time.isoformat(),
                "detected_type": attack_type,
                "is_attack": is_attack,
                "severity": severity,
                "confidence": float(confidence),
                "anomaly_score": float(anomaly_score),
                "alert_triggered": alert_triggered,
                "consecutive_alerts": self.alert_history[severity]["consecutive"] if severity else 0,
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

    def _extract_features(self, network_status: Dict) -> np.ndarray:
        """Extract detection features from network status."""
        # Network-level metrics
        network_metrics = [
            network_status["metrics"]["total_bandwidth"],
            network_status["metrics"]["latency"],
            network_status["metrics"]["packet_loss_rate"],
            network_status["metrics"]["error_rate"]
        ]
        
        # Device metrics and status
        device_metrics = []
        for device in network_status["devices"]:
            metrics = device["metrics"]
            device_metrics.extend([
                metrics["cpu_usage"],
                metrics["memory_usage"],
                metrics["bandwidth_usage"],
                metrics["packet_count"],
                metrics["error_count"],
                float(device["status"] == "compromised")
            ])
        
        features = network_metrics + device_metrics
        return np.array(features).reshape(1, -1)

    def _determine_severity(self, attack_type: str, confidence: float, 
                          anomaly_score: float, network_status: Dict) -> str:
        """Determine attack severity based on multiple factors."""
        # Base severity from confidence
        if confidence >= self.thresholds["high"]["confidence"]:
            severity = "high"
        elif confidence >= self.thresholds["medium"]["confidence"]:
            severity = "medium"
        elif confidence >= self.thresholds["low"]["confidence"]:
            severity = "low"
        else:
            return None

        # Adjust based on anomaly score
        if anomaly_score > 0.8:
            severity = "high"
        elif anomaly_score > 0.6 and severity == "low":
            severity = "medium"

        # Consider attack type
        if attack_type == "botnet" and confidence > 0.7:
            severity = max(severity, "medium")
        
        # Check network impact
        if network_status["metrics"]["error_rate"] > 0.5:
            severity = "high"
        
        # Check device status
        compromised_count = sum(
            1 for device in network_status["devices"]
            if device["status"] == "compromised"
        )
        if compromised_count > 1:
            severity = max(severity, "medium")
        
        return severity

    def _check_attack_patterns(self, current_attack: str) -> float:
        """Check for attack patterns in recent history."""
        if len(self.detection_history) < 3:
            return 0.0

        recent_attacks = [
            d["detected_type"] for d in self.detection_history[-3:]
            if d["is_attack"]
        ]

        # Pattern boost for consistent attack types
        if len(recent_attacks) >= 2 and all(a == current_attack for a in recent_attacks):
            return self.thresholds["high"]["pattern_boost"]
        
        return 0.0

    def get_detection_history(self) -> List[Dict]:
        """Get all historical detections."""
        return self.detection_history

    def clear_history(self):
        """Reset detection history and alert tracking."""
        self.detection_history = []
        for severity in self.alert_history:
            self.alert_history[severity] = {"last_alert": None, "consecutive": 0}
        self.logger.info("Detection history and alert tracking cleared")