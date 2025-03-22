import logging
from pathlib import Path
import json
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Tuple, List, Dict

def setup_logging() -> logging.Logger:
    """Configure logging for data processing."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"data_processing_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("DataProcessing")

def load_events(file_path: Path) -> List[Dict]:
    """Load collected events from backup file."""
    events = []
    with open(file_path, 'r') as f:
        for line in f:
            events.append(json.loads(line.strip()))
    return events

def extract_features(events: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
    """Extract features and labels from events."""
    features = []
    labels = []
    
    for event in events:
        if event["event_type"] == "training_data":
            # Extract network-level metrics
            network_metrics = event["details"]["network_metrics"]
            
            # Extract device-level metrics
            device_metrics = []
            for device in event["details"]["device_metrics"].values():
                device_metrics.extend([
                    device["cpu_usage"],
                    device["memory_usage"],
                    device["bandwidth_usage"],
                    device["packet_count"],
                    device["error_count"]
                ])
            
            # Combine all features
            feature_vector = [
                network_metrics["total_bandwidth"],
                network_metrics["latency"],
                network_metrics["packet_loss_rate"],
                network_metrics["error_rate"]
            ] + device_metrics
            
            features.append(feature_vector)
            labels.append(event["details"]["attack_type"])
    
    return np.array(features), np.array(labels)

def save_processed_data(features: np.ndarray, labels: np.ndarray, output_dir: Path):
    """Save processed features and labels."""
    output_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save as numpy arrays for efficient loading
    np.save(output_dir / f"features_{timestamp}.npy", features)
    np.save(output_dir / f"labels_{timestamp}.npy", labels)
    
    # Save as CSV for inspection
    df = pd.DataFrame(features)
    df['label'] = labels
    df.to_csv(output_dir / f"training_data_{timestamp}.csv", index=False)

def analyze_data_distribution(features: np.ndarray, labels: np.ndarray, logger: logging.Logger):
    """Analyze the distribution of attack types in the dataset."""
    unique_labels, counts = np.unique(labels, return_counts=True)
    total = len(labels)
    
    logger.info("Data Distribution:")
    for label, count in zip(unique_labels, counts):
        percentage = (count / total) * 100
        logger.info(f"  {label}: {count} samples ({percentage:.2f}%)")
    
    logger.info(f"\nFeature Statistics:")
    df = pd.DataFrame(features)
    logger.info("\nSummary Statistics:")
    logger.info(df.describe().to_string())

def main():
    logger = setup_logging()
    logger.info("Starting data processing")
    
    try:
        # Load collected events
        events_file = Path("logs/events_backup.jsonl")
        if not events_file.exists():
            raise FileNotFoundError("No events file found. Run data collection first.")
        
        logger.info("Loading events from backup file")
        events = load_events(events_file)
        logger.info(f"Loaded {len(events)} events")
        
        # Extract features and labels
        logger.info("Extracting features and labels")
        features, labels = extract_features(events)
        logger.info(f"Extracted {len(features)} training samples")
        
        # Analyze data distribution
        analyze_data_distribution(features, labels, logger)
        
        # Save processed data
        output_dir = Path("data/processed")
        logger.info("Saving processed data")
        save_processed_data(features, labels, output_dir)
        logger.info(f"Data saved to {output_dir}")
        
    except Exception as e:
        logger.error(f"Data processing failed: {str(e)}")
        raise
    finally:
        logger.info("Data processing completed")

if __name__ == "__main__":
    main()