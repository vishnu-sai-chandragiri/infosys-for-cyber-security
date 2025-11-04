#!/usr/bin/env python3
"""
Simple test script to verify the cybersecurity system components
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

def test_imports():
    """Test if all modules can be imported"""
    try:
        print("Testing imports...")
        
        # Test basic imports
        from utils.helpers import Logger, PerformanceMonitor
        print("✅ Utils imports successful")
        
        from config.config import get_config, create_directories
        print("✅ Config imports successful")
        
        from data.preprocess import CICIDS2017Preprocessor
        print("✅ Data preprocessing imports successful")
        
        from models.ml_models import create_ml_models
        print("✅ ML models imports successful")
        
        from realtime.threat_detector import create_threat_detector
        print("✅ Threat detector imports successful")
        
        from realtime.threat_predictor import create_threat_predictor
        print("✅ Threat predictor imports successful")
        
        from chatbot.cybersecurity_chatbot import create_chatbot
        print("✅ Chatbot imports successful")
        
        print("\n🎉 All imports successful! System is ready.")
        return True
        
    except Exception as e:
        print(f"❌ Import error: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality"""
    try:
        print("\nTesting basic functionality...")
        
        # Test logger
        from utils.helpers import Logger
        logger = Logger("test")
        logger.info("Test log message")
        print("✅ Logger working")
        
        # Test config
        from config.config import get_config
        config = get_config()
        print("✅ Config loading working")
        
        # Test ML models creation
        from models.ml_models import create_ml_models
        ml_models = create_ml_models()
        print(f"✅ ML models created: {list(ml_models.keys())}")
        
        # Test threat detector
        from realtime.threat_detector import create_threat_detector
        detector = create_threat_detector(ml_models)
        print("✅ Threat detector created")
        
        # Test threat predictor
        from realtime.threat_predictor import create_threat_predictor
        predictor = create_threat_predictor(ml_models)
        print("✅ Threat predictor created")
        
        print("\n🎉 All basic functionality tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Functionality test error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Cybersecurity AI System - Component Test")
    print("=" * 50)
    
    # Test imports
    if test_imports():
        # Test functionality
        test_basic_functionality()
        
        print("\n✅ System is ready for real-time threat prediction!")
        print("You can now run: python main.py")
    else:
        print("\n❌ System has import issues that need to be resolved.")
