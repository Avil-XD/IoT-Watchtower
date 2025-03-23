#!/usr/bin/env python3
import os
import sys
from pathlib import Path
import logging
from typing import List

def setup_directories() -> List[Path]:
    """Create necessary directories for the monitoring system."""
    dirs = [
        Path("data/events"),
        Path("logs"),
        Path("models")
    ]
    
    for directory in dirs:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory: {directory}")
    
    return dirs

def verify_python_environment():
    """Verify Python environment and dependencies."""
    try:
        import numpy
        import sklearn
        import pandas
        import joblib
        print("✓ All required Python packages are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing required package: {str(e)}")
        print("\nPlease install required packages:")
        print("pip install -r requirements.txt")
        return False

def setup_logging():
    """Configure basic logging for the monitoring system."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "setup.log"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("Setup")

def print_usage_instructions():
    """Print instructions for using the monitoring system."""
    print("\n" + "="*80)
    print("IoT Security Monitoring System - Usage Instructions")
    print("="*80)
    print("\n1. Start the monitoring system:")
    print("   python src/monitoring/run_monitoring.py")
    print("\n2. The console dashboard will show:")
    print("   - Real-time attack alerts")
    print("   - Alert severity distribution")
    print("   - Attack type statistics")
    print("   - Recent alert details")
    print("\n3. Monitor log files in the 'logs' directory for detailed history")
    print("\n4. Data files are stored in:")
    print("   - data/events/current_events.jsonl  (all events)")
    print("   - data/events/current_alerts.jsonl  (security alerts only)")
    print("\n5. Press Ctrl+C to stop monitoring")
    print("\nNote: The system uses local file storage for all data.")
    print("="*80)

def main():
    """Set up the IoT security monitoring system."""
    print("\n🛠️  Setting up IoT Security Monitoring System\n")
    
    logger = setup_logging()
    
    try:
        # Check Python environment
        if not verify_python_environment():
            return
        
        # Create required directories
        setup_directories()
        
        print("\n✅ Setup completed successfully!")
        print_usage_instructions()
        
    except Exception as e:
        logger.error(f"Setup failed: {str(e)}")
        print("\n❌ Setup failed. Check logs for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()