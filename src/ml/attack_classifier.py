import logging
from pathlib import Path
from datetime import datetime
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Any
import joblib

class AttackClassifier:
    def __init__(self, event_collector=None):
        """Initialize the attack classifier with optional event collector."""
        self._setup_logging()
        self.model = None
        self.scaler = StandardScaler()
        self.event_collector = event_collector
        self.feature_columns = [
            'cpu_usage', 'memory_usage', 'bandwidth_usage',
            'packet_count', 'error_count', 'error_rate'
        ]

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

    def extract_features(self, network_status: Dict[str, Any]) -> np.ndarray:
        """Extract relevant features from network status."""
        features = []
        
        # Network-level features
        features.extend([
            network_status['metrics']['total_bandwidth'],
            network_status['metrics']['error_rate']
        ])
        
        # Device-level features
        for device in network_status['devices']:
            features.extend([
                device['metrics']['cpu_usage'],
                device['metrics']['memory_usage'],
                device['metrics']['bandwidth_usage'],
                device['metrics']['error_count']
            ])
            
        return np.array(features).reshape(1, -1)

    def collect_training_data(self, network_status: Dict[str, Any], 
                            attack_status: Dict[str, Any]) -> None:
        """Collect training data from current network and attack status."""
        if self.event_collector:
            features = self.extract_features(network_status)
            
            training_data = {
                "features": features.tolist(),
                "attack_type": attack_status.get("type", "normal"),
                "attack_phase": attack_status.get("status", "none"),
                "network_metrics": network_status["metrics"],
                "device_metrics": {
                    device["id"]: device["metrics"] 
                    for device in network_status["devices"]
                }
            }
            
            self.event_collector.collect_event(
                event_type="training_data",
                data=training_data
            )

    def prepare_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare collected data for training."""
        if not self.event_collector:
            raise ValueError("Event collector not configured")
            
        training_events = self.event_collector.get_events("training_data")
        
        X, y = [], []
        for event in training_events:
            X.append(event["details"]["features"][0])  # First row of features
            y.append(event["details"]["attack_type"])
            
        return np.array(X), np.array(y)

    def train(self) -> None:
        """Train the classifier on collected data."""
        try:
            X, y = self.prepare_training_data()
            
            if len(X) == 0:
                raise ValueError("No training data available")
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Initialize and train model
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            self.model.fit(X_scaled, y)
            
            self.logger.info(f"Model trained on {len(X)} samples")
            
            # Save model and scaler
            self._save_model()
            
        except Exception as e:
            self.logger.error(f"Training failed: {str(e)}")
            raise

    def predict(self, network_status: Dict[str, Any]) -> Dict[str, Any]:
        """Predict attack type from current network status."""
        try:
            if self.model is None:
                self._load_model()
                
            features = self.extract_features(network_status)
            features_scaled = self.scaler.transform(features)
            
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            result = {
                "predicted_type": prediction,
                "confidence": float(max(probabilities)),
                "probabilities": {
                    class_name: float(prob)
                    for class_name, prob in zip(self.model.classes_, probabilities)
                }
            }
            
            if self.event_collector:
                self.event_collector.collect_event(
                    event_type="ml_prediction",
                    data=result
                )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Prediction failed: {str(e)}")
            raise

    def _save_model(self) -> None:
        """Save trained model and scaler to disk."""
        try:
            models_dir = Path("models")
            models_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save model
            model_path = models_dir / f"attack_classifier_{timestamp}.joblib"
            joblib.dump(self.model, model_path)
            
            # Save scaler
            scaler_path = models_dir / f"feature_scaler_{timestamp}.joblib"
            joblib.dump(self.scaler, scaler_path)
            
            self.logger.info(f"Model and scaler saved to {models_dir}")
            
        except Exception as e:
            self.logger.error(f"Failed to save model: {str(e)}")
            raise

    def _load_model(self) -> None:
        """Load latest model and scaler from disk."""
        try:
            models_dir = Path("models")
            if not models_dir.exists():
                raise FileNotFoundError("No models directory found")
            
            # Get latest model file
            model_files = list(models_dir.glob("attack_classifier_*.joblib"))
            if not model_files:
                raise FileNotFoundError("No model files found")
            
            latest_model = max(model_files, key=lambda x: x.stat().st_mtime)
            self.model = joblib.load(latest_model)
            
            # Get latest scaler file
            scaler_files = list(models_dir.glob("feature_scaler_*.joblib"))
            if not scaler_files:
                raise FileNotFoundError("No scaler files found")
            
            latest_scaler = max(scaler_files, key=lambda x: x.stat().st_mtime)
            self.scaler = joblib.load(latest_scaler)
            
            self.logger.info(f"Loaded model from {latest_model}")
            
        except Exception as e:
            self.logger.error(f"Failed to load model: {str(e)}")
            raise

if __name__ == "__main__":
    # Test classifier
    from data.event_collector import EventCollector
    
    collector = EventCollector()
    classifier = AttackClassifier(collector)
    
    # Example network status for testing
    test_status = {
        "metrics": {
            "total_bandwidth": 100.0,
            "error_rate": 0.001
        },
        "devices": [
            {
                "metrics": {
                    "cpu_usage": 50.0,
                    "memory_usage": 60.0,
                    "bandwidth_usage": 30.0,
                    "error_count": 2
                }
            }
        ]
    }
    
    features = classifier.extract_features(test_status)
    print(f"Extracted features shape: {features.shape}")