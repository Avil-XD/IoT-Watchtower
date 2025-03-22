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
        """Extract features from network status."""
        # Network-level features
        network_metrics = [
            network_status["metrics"]["total_bandwidth"],
            network_status["metrics"]["latency"],
            network_status["metrics"]["packet_loss_rate"],
            network_status["metrics"]["error_rate"]
        ]
        
        # Device-level features
        device_metrics = []
        device_ratios = []
        for device in network_status["devices"]:
            metrics = device["metrics"]
            device_metrics.extend([
                metrics["cpu_usage"],
                metrics["memory_usage"],
                metrics["bandwidth_usage"],
                metrics["packet_count"],
                metrics["error_count"]
            ])
            
            # Calculate performance ratios
            if metrics["packet_count"] > 0:
                error_rate = metrics["error_count"] / metrics["packet_count"]
                device_ratios.append(error_rate)
            
            if metrics["bandwidth_usage"] > 0:
                packet_density = metrics["packet_count"] / metrics["bandwidth_usage"]
                device_ratios.append(packet_density)
            
            resource_usage = (metrics["cpu_usage"] + metrics["memory_usage"]) / 2
            device_ratios.append(resource_usage)
        
        return network_metrics + device_metrics + device_ratios

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
        """Train the classifier on collected data."""
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
        
        # Initialize and train model
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight=class_weights,
            random_state=42
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test_scaled)
        self.logger.info("\nModel Performance:")
        self.logger.info("\n" + classification_report(y_test, y_pred))
        
        # Save model
        self._save_model()

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

    def _save_model(self):
        """Save trained model and scaler."""
        models_dir = Path("models")
        models_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save model
        model_path = models_dir / f"attack_classifier_{timestamp}.joblib"
        joblib.dump(self.model, model_path)
        
        # Save scaler
        scaler_path = models_dir / f"feature_scaler_{timestamp}.joblib"
        joblib.dump(self.scaler, scaler_path)
        
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