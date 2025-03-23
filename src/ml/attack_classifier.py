import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import logging
from pathlib import Path
from typing import Dict, List, Tuple
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
        
        return network_metrics + device_metrics + device_ratios + device_anomalies

    def collect_training_data(self, network_status: Dict, attack_status: Dict):
        """Collect network status data for training."""
        features = self._extract_features(network_status)
        
        training_sample = {
            "features": features,
            "label": attack_status["type"]
        }
        
        self.training_data.append(training_sample)
        
        if self.event_collector:
            self.event_collector.record_event(
                event_type="training_data",
                details={
                    "network_metrics": network_status["metrics"],
                    "device_metrics": {
                        d["id"]: d["metrics"]
                        for d in network_status["devices"]
                    },
                    "attack_type": attack_status["type"]
                }
            )

    def train(self):
        """Train the classifier with advanced feature analysis and evaluation."""
        if not self.training_data:
            raise ValueError("No training data available")
        
        # Prepare training data
        X = np.array([sample["features"] for sample in self.training_data])
        y = np.array([sample["label"] for sample in self.training_data])
        
        # Split data with stratification
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Calculate class weights for imbalanced data
        unique_classes = np.unique(y_train)
        class_counts = np.bincount([np.where(unique_classes == c)[0][0] for c in y_train])
        total_samples = len(y_train)
        class_weights = {
            cls: (total_samples / (len(unique_classes) * count))
            for cls, count in zip(unique_classes, class_counts)
        }
        
        # Initialize model with optimized hyperparameters
        self.model = RandomForestClassifier(
            n_estimators=300,  # Increased for better stability
            max_depth=20,      # Increased for complex patterns
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight=class_weights,
            random_state=42,
            n_jobs=-1  # Parallel processing
        )
        
        # Train model
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)
        
        # Calculate and log performance metrics
        self.logger.info("\nModel Performance Metrics:")
        class_report = classification_report(y_test, y_pred, output_dict=True)
        self.logger.info("\n" + classification_report(y_test, y_pred))
        
        # Analyze feature importance
        feature_importance = self.model.feature_importances_
        feature_importance_dict = {
            f"feature_{i}": importance
            for i, importance in enumerate(feature_importance)
        }
        
        # Save model with metadata
        metadata = {
            "training_date": datetime.now().isoformat(),
            "num_samples": len(y),
            "class_distribution": {
                str(cls): int(count)
                for cls, count in zip(unique_classes, class_counts)
            },
            "feature_importance": feature_importance_dict,
            "model_params": self.model.get_params(),
            "performance_metrics": {
                "accuracy": float(class_report['accuracy']),
                "macro_avg": class_report['macro avg'],
                "class_metrics": {
                    str(cls): metrics
                    for cls, metrics in class_report.items()
                    if cls not in ['accuracy', 'macro avg', 'weighted avg']
                }
            }
        }
        
        self._save_model(metadata)

    def predict(self, network_status: Dict) -> Dict:
        """Predict attack probability for current network status."""
        if not self.model or not self.scaler:
            raise RuntimeError("Model not trained")
        
        features = self._extract_features(network_status)
        features_scaled = self.scaler.transform(np.array(features).reshape(1, -1))
        
        prediction = self.model.predict(features_scaled)[0]
        probabilities = self.model.predict_proba(features_scaled)[0]
        
        return {
            "prediction": prediction,
            "confidence": float(max(probabilities)),
            "probabilities": {
                str(cls): float(prob)
                for cls, prob in zip(self.model.classes_, probabilities)
            }
        }

    def _save_model(self, metadata: Dict = None):
        """Save trained model, scaler and metadata."""
        models_dir = Path("models")
        models_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save model
        model_path = models_dir / f"attack_classifier_{timestamp}.joblib"
        joblib.dump(self.model, model_path)
        
        # Save scaler
        scaler_path = models_dir / f"feature_scaler_{timestamp}.joblib"
        joblib.dump(self.scaler, scaler_path)
        
        # Save metadata if provided
        if metadata:
            metadata_path = models_dir / f"model_metadata_{timestamp}.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            self.logger.info(f"Model metadata saved to {metadata_path}")
        
        self.logger.info(f"Model saved to {model_path}")
        self.logger.info(f"Scaler saved to {scaler_path}")

    def load_model(self, model_path: Path, scaler_path: Path):
        """Load trained model and scaler."""
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.logger.info(f"Model loaded from {model_path}")
        self.logger.info(f"Scaler loaded from {scaler_path}")

if __name__ == "__main__":
    # For testing
    from datetime import datetime
    classifier = AttackClassifier()
    print("Classifier initialized")