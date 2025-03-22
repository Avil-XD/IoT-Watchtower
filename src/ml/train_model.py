import logging
from pathlib import Path
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight
import joblib
import json

def setup_logging() -> logging.Logger:
    """Configure logging for model training."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"model_training_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("ModelTraining")

def load_training_data(data_dir: Path):
    """Load processed training data."""
    # Get latest files
    feature_files = list(data_dir.glob("features_*.npy"))
    label_files = list(data_dir.glob("labels_*.npy"))
    
    if not feature_files or not label_files:
        raise FileNotFoundError("No training data found")
    
    latest_feature_file = max(feature_files, key=lambda x: x.stat().st_mtime)
    latest_label_file = max(label_files, key=lambda x: x.stat().st_mtime)
    
    features = np.load(latest_feature_file)
    labels = np.load(latest_label_file)
    
    return features, labels

def compute_feature_importance(features, labels):
    """Compute initial feature importance scores."""
    from sklearn.feature_selection import mutual_info_classif
    
    importance_scores = mutual_info_classif(features, labels)
    return importance_scores

def train_evaluate_model(X_train, X_test, y_train, y_test, logger):
    """Train and evaluate the model with optimized parameters."""
    # Compute class weights for imbalanced data
    class_weights = compute_class_weight(
        'balanced',
        classes=np.unique(y_train),
        y=y_train
    )
    class_weight_dict = {
        cls: weight 
        for cls, weight in zip(np.unique(y_train), class_weights)
    }
    
    logger.info("Class weights:")
    for cls, weight in class_weight_dict.items():
        logger.info(f"  {cls}: {weight:.3f}")
    
    # Initialize model with optimized parameters
    model = RandomForestClassifier(
        n_estimators=200,      # More trees for better generalization
        max_depth=15,          # Deeper trees for complex patterns
        min_samples_split=5,   # Minimum samples required to split
        min_samples_leaf=2,    # Minimum samples required at leaf
        class_weight=class_weight_dict,
        criterion='entropy',   # Use information gain
        random_state=42
    )
    
    # Compute initial feature importance
    importance_scores = compute_feature_importance(X_train, y_train)
    
    # Train model
    logger.info("Training model...")
    model.fit(X_train, y_train)
    
    # Cross-validation
    cv_scores = cross_val_score(model, X_train, y_train, cv=5)
    logger.info(f"Cross-validation scores: {cv_scores}")
    logger.info(f"Average CV score: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
    
    # Evaluate on test set
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)
    
    # Log classification report
    logger.info("\nClassification Report:")
    logger.info("\n" + classification_report(y_test, y_pred))
    
    # Log confusion matrix
    logger.info("\nConfusion Matrix:")
    logger.info("\n" + str(confusion_matrix(y_test, y_pred)))
    
    # Analyze feature importance
    feature_importance = {
        'mutual_info': importance_scores.tolist(),
        'random_forest': model.feature_importances_.tolist()
    }
    
    logger.info("\nTop 10 Most Important Features:")
    sorted_idx = np.argsort(model.feature_importances_)[::-1]
    for idx in sorted_idx[:10]:
        logger.info(
            f"Feature {idx}: "
            f"RF Importance={model.feature_importances_[idx]:.4f}, "
            f"MI Score={importance_scores[idx]:.4f}"
        )
    
    return model, feature_importance

def save_model(model, scaler, metrics, feature_importance):
    """Save trained model and associated metadata."""
    models_dir = Path("models")
    models_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save model
    model_path = models_dir / f"attack_classifier_{timestamp}.joblib"
    joblib.dump(model, model_path)
    
    # Save scaler
    scaler_path = models_dir / f"feature_scaler_{timestamp}.joblib"
    joblib.dump(scaler, scaler_path)
    
    # Save metrics and feature importance
    metadata = {
        "metrics": metrics,
        "feature_importance": feature_importance,
        "model_params": model.get_params(),
        "timestamp": datetime.now().isoformat(),
        "training_date": timestamp
    }
    
    metadata_path = models_dir / f"model_metadata_{timestamp}.json"
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    return model_path, scaler_path, metadata_path

def main():
    logger = setup_logging()
    logger.info("Starting model training")
    
    try:
        # Load data
        data_dir = Path("data/processed")
        logger.info("Loading training data")
        features, labels = load_training_data(data_dir)
        logger.info(f"Loaded {len(features)} samples")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Scale features
        logger.info("Scaling features")
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train and evaluate model
        model, feature_importance = train_evaluate_model(
            X_train_scaled, X_test_scaled, y_train, y_test, logger
        )
        
        # Calculate and save metrics
        y_pred = model.predict(X_test_scaled)
        metrics = {
            "cv_scores": cross_val_score(model, X_train_scaled, y_train, cv=5).tolist(),
            "classification_report": classification_report(y_test, y_pred, output_dict=True),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "training_samples": len(X_train),
            "test_samples": len(X_test)
        }
        
        # Save model and artifacts
        logger.info("Saving model and artifacts")
        model_path, scaler_path, metadata_path = save_model(
            model, scaler, metrics, feature_importance
        )
        logger.info(f"Model saved to {model_path}")
        logger.info(f"Scaler saved to {scaler_path}")
        logger.info(f"Metadata saved to {metadata_path}")
        
    except Exception as e:
        logger.error(f"Model training failed: {str(e)}")
        raise
    finally:
        logger.info("Model training completed")

if __name__ == "__main__":
    main()