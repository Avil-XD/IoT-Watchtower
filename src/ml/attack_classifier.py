import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import logging
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
import joblib
import json

class AttackClassifier:
    def __init__(self, event_collector=None):
        """Initialize the attack classifier."""
        self._setup_logging()
        self.event_collector = event_collector
        self.training_data = []
        self.model = None
        self.scaler = None
        
        # Attack characteristics for improved classification
        self.attack_signatures = {
            "botnet": {
                "indicators": ["high_cpu", "high_memory", "irregular_traffic", "propagation"],
                "thresholds": {
                    "cpu_usage": 70,
                    "memory_usage": 80,
                    "error_rate": 0.3
                }
            },
            "ddos": {
                "indicators": ["bandwidth_spike", "packet_flood", "high_latency"],
                "thresholds": {
                    "bandwidth_usage": 150,  # % of normal
                    "packet_count": 1000,
                    "error_rate": 0.4
                }
            },
            "mitm": {
                "indicators": ["auth_anomalies", "traffic_routing", "latency_changes"],
                "thresholds": {
                    "latency": 200,  # ms
                    "packet_loss": 0.1
                }
            }
        }

    def _setup_logging(self):
        """Configure classifier-specific logging."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"classifier_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("AttackClassifier")

    def _extract_features(self, network_status: Dict) -> List[float]:
        """Extract advanced features from network status."""
        # Network-level features
        network_metrics = [
            network_status["metrics"]["total_bandwidth"],
            network_status["metrics"]["latency"],
            network_status["metrics"]["packet_loss_rate"],
            network_status["metrics"]["error_rate"],
            network_status["metrics"]["connection_stability"]
        ]
        
        # Calculate network health score
        network_health = 1.0 - (
            network_status["metrics"]["error_rate"] * 0.4 +
            network_status["metrics"]["packet_loss_rate"] * 0.6
        )
        network_metrics.append(network_health)
        
        # Device metrics and anomaly indicators
        device_metrics = []
        security_metrics = []
        anomaly_indicators = []
        
        for device in network_status["devices"]:
            metrics = device["metrics"]
            
            # Basic device metrics
            device_metrics.extend([
                metrics["cpu_usage"],
                metrics["memory_usage"],
                metrics["bandwidth_usage"],
                metrics["packet_count"],
                metrics["error_count"]
            ])
            
            # Security-related features
            security_metrics.extend([
                device["security_level"],
                len(device["vulnerabilities"]),
                float(device["status"] == "compromised")
            ])
            
            # Device-specific anomaly detection
            if device["type"] == "SmartCamera":
                anomaly_indicators.extend([
                    float(metrics["stream_latency"] > 150),  # High latency
                    float(metrics["video_quality"] < 0.7),   # Quality degradation
                ])
            elif device["type"] == "SmartLock":
                anomaly_indicators.extend([
                    float(metrics["failed_auths"] > 10),     # Auth failures
                    float(metrics["battery_level"] < 0.3),   # Low battery
                ])
            elif device["type"] == "SmartThermostat":
                anomaly_indicators.extend([
                    float(abs(metrics["temperature"] - 22) > 5),  # Unusual temp
                    float(metrics["energy_consumption"] > 50),    # High energy use
                ])
        
        # Combine all features
        return network_metrics + device_metrics + security_metrics + anomaly_indicators

    def collect_training_data(self, network_status: Dict, attack_status: Dict):
        """Collect network status data for training."""
        features = self._extract_features(network_status)
        
        training_sample = {
            "features": features,
            "label": attack_status["type"],
            "timestamp": datetime.now().isoformat()
        }
        
        self.training_data.append(training_sample)
        
        # Log collection event
        if self.event_collector:
            self.event_collector.record_event(
                event_type="training_data",
                details={
                    "network_metrics": network_status["metrics"],
                    "attack_type": attack_status["type"],
                    "features_count": len(features)
                }
            )

    def train(self):
        """Train the classifier with optimized parameters."""
        if not self.training_data:
            raise ValueError("No training data available")
        
        # Prepare training data
        X = np.array([sample["features"] for sample in self.training_data])
        y = np.array([sample["label"] for sample in self.training_data])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Calculate class weights
        unique_classes = np.unique(y_train)
        class_counts = np.bincount([np.where(unique_classes == c)[0][0] for c in y_train])
        total_samples = len(y_train)
        class_weights = {
            cls: (total_samples / (len(unique_classes) * count))
            for cls, count in zip(unique_classes, class_counts)
        }
        
        # Initialize model with optimized parameters
        self.model = RandomForestClassifier(
            n_estimators=300,
            max_depth=20,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight=class_weights,
            random_state=42,
            n_jobs=-1
        )
        
        # Train model
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test_scaled)
        class_report = classification_report(y_test, y_pred, output_dict=True)
        
        # Generate metadata
        metadata = {
            "training_date": datetime.now().isoformat(),
            "num_samples": len(y),
            "class_distribution": {
                str(cls): int(count)
                for cls, count in zip(unique_classes, class_counts)
            },
            "feature_importance": {
                f"feature_{i}": float(imp)
                for i, imp in enumerate(self.model.feature_importances_)
            },
            "performance": class_report
        }
        
        # Save model and metadata
        self._save_model(metadata)
        
        self.logger.info("\nTraining Results:")
        self.logger.info("\n" + classification_report(y_test, y_pred))

    def predict(self, network_status: Dict) -> Dict:
        """Predict attack probability for current network status."""
        if not self.model or not self.scaler:
            raise RuntimeError("Model not trained")
        
        # Extract and scale features
        features = self._extract_features(network_status)
        features_scaled = self.scaler.transform(np.array(features).reshape(1, -1))
        
        # Get predictions and probabilities
        prediction = self.model.predict(features_scaled)[0]
        probabilities = self.model.predict_proba(features_scaled)[0]
        
        # Calculate attack confidence
        confidence = float(max(probabilities))
        
        # Determine attack signatures
        detected_signatures = []
        if prediction != "normal":
            signatures = self.attack_signatures.get(prediction, {}).get("indicators", [])
            thresholds = self.attack_signatures.get(prediction, {}).get("thresholds", {})
            
            # Check for signature matches
            for device in network_status["devices"]:
                metrics = device["metrics"]
                if prediction == "botnet" and metrics["cpu_usage"] > thresholds["cpu_usage"]:
                    detected_signatures.append("high_cpu")
                elif prediction == "ddos" and metrics["bandwidth_usage"] > thresholds["bandwidth_usage"]:
                    detected_signatures.append("bandwidth_spike")
                elif prediction == "mitm" and device["status"] == "intercepted":
                    detected_signatures.append("traffic_routing")
        
        return {
            "prediction": prediction,
            "confidence": confidence,
            "probabilities": {
                str(cls): float(prob)
                for cls, prob in zip(self.model.classes_, probabilities)
            },
            "detected_signatures": detected_signatures
        }

    def _save_model(self, metadata: Dict):
        """Save trained model and metadata."""
        models_dir = Path("models")
        models_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save model
        model_path = models_dir / f"attack_classifier_{timestamp}.joblib"
        joblib.dump(self.model, model_path)
        
        # Save scaler
        scaler_path = models_dir / f"feature_scaler_{timestamp}.joblib"
        joblib.dump(self.scaler, scaler_path)
        
        # Save metadata
        metadata_path = models_dir / f"model_metadata_{timestamp}.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Model saved to {model_path}")
        self.logger.info(f"Scaler saved to {scaler_path}")
        self.logger.info(f"Metadata saved to {metadata_path}")