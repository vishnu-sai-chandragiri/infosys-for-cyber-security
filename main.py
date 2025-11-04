"""
Main Entry Point for Cybersecurity AI System

This is the main application entry point that integrates all components
of the cybersecurity threat detection system.
"""

import os
import sys
import argparse
import signal
import time
from pathlib import Path
from typing import Dict, Any, Optional
import warnings
warnings.filterwarnings('ignore')

# Check Python version compatibility
def check_python_version():
    """Check if Python version is compatible"""
    required_version = (3, 8)
    current_version = sys.version_info[:2]
    
    if current_version < required_version:
        print(f"❌ Python {current_version[0]}.{current_version[1]} is not supported.")
        print(f"✅ This system requires Python {required_version[0]}.{required_version[1]} or higher.")
        print(f"💡 Recommended: Python 3.10.11")
        sys.exit(1)
    
    if current_version >= (3, 11):
        print(f"⚠️  Python {current_version[0]}.{current_version[1]} detected.")
        print("💡 This system is optimized for Python 3.10.11")
        print("🔧 Some packages may need manual installation")
    
    print(f"✅ Python {current_version[0]}.{current_version[1]} is compatible")

# Check Python version on startup
check_python_version()

# Add project root to path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

# Import our modules
from utils.helpers import Logger, PerformanceMonitor
from config.config import get_config, create_directories
from data.preprocess import CICIDS2017Preprocessor
from models.ml_models import create_ml_models
from models.dl_models import create_dl_models
from models.train_models import ModelTrainer
from realtime.threat_detector import create_threat_detector
from realtime.threat_predictor import create_threat_predictor
from chatbot.cybersecurity_chatbot import create_chatbot
from web.app import create_web_app

class CybersecuritySystem:
    """Main system class that orchestrates all components"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = Logger("CybersecuritySystem")
        self.performance_monitor = PerformanceMonitor()
        self.config = get_config()
        
        # System components
        self.preprocessor = None
        self.ml_models = {}
        self.dl_models = {}
        self.threat_detector = None
        self.chatbot = None
        self.web_app = None
        
        # System state
        self.is_initialized = False
        self.is_running = False
        
        # Create necessary directories
        create_directories()
        
        self.logger.info("Cybersecurity AI System initialized")
    
    def initialize_components(self, load_models: bool = True) -> bool:
        """Initialize all system components"""
        try:
            self.logger.info("Initializing system components...")
            self.performance_monitor.start_timer("system_initialization")
            
            # Initialize data preprocessor
            self.logger.info("Initializing data preprocessor...")
            self.preprocessor = CICIDS2017Preprocessor()
            
            # Load or create models
            if load_models:
                self.logger.info("Loading AI models...")
                self._load_models()
            
            # Initialize threat detector
            self.logger.info("Initializing threat detector...")
            all_models = {**self.ml_models, **self.dl_models}
            self.threat_detector = create_threat_detector(all_models)
            
            # Initialize threat predictor
            self.logger.info("Initializing threat predictor...")
            self.threat_predictor = create_threat_predictor(all_models)
            
            # Initialize chatbot
            self.logger.info("Initializing AI chatbot...")
            self.chatbot = create_chatbot(self.threat_detector)
            
            # Initialize web application
            self.logger.info("Initializing web application...")
            self.web_app = create_web_app()
            
            self.is_initialized = True
            self.performance_monitor.end_timer("system_initialization")
            
            self.logger.info("All components initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            return False
    
    def _load_models(self):
        """Load trained models or create new ones"""
        try:
            # Check if processed data exists
            processed_data_path = self.config['data']['processed_data_path'] / 'processed_data.pkl'
            
            if not processed_data_path.exists():
                self.logger.info("Processed data not found. Running preprocessing...")
                self._run_preprocessing()
            
            # Check if trained models exist
            saved_models_dir = self.config['models']['saved_models_dir']
            
            if not any(saved_models_dir.glob('*.pkl')) and not any(saved_models_dir.glob('*.h5')):
                self.logger.info("Trained models not found. Training models...")
                self._train_models()
            
            # Load ML models
            self.logger.info("Loading ML models...")
            self.ml_models = create_ml_models()
            
            # Load DL models
            self.logger.info("Loading DL models...")
            self.dl_models = create_dl_models()
            
            # Load trained models from files
            self._load_trained_models()
            
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
            # Create default models for demo
            self.logger.info("Creating default models for demo...")
            self.ml_models = create_ml_models()
            self.dl_models = create_dl_models()
    
    def _run_preprocessing(self):
        """Run data preprocessing with memory optimization"""
        try:
            self.logger.info("Starting data preprocessing...")
            # Use sample size for memory optimization (100K records)
            processed_data = self.preprocessor.preprocess_pipeline(sample_size=100000)
            
            if processed_data:
                self.logger.info("Data preprocessing completed successfully")
            else:
                self.logger.warning("Data preprocessing completed with warnings")
                
        except Exception as e:
            self.logger.error(f"Data preprocessing failed: {e}")
            raise
    
    def _train_models(self):
        """Train all models"""
        try:
            self.logger.info("Starting model training...")
            trainer = ModelTrainer()
            success = trainer.run_training_pipeline()
            
            if success:
                self.logger.info("Model training completed successfully")
            else:
                self.logger.error("Model training failed")
                raise Exception("Model training failed")
                
        except Exception as e:
            self.logger.error(f"Model training failed: {e}")
            raise
    
    def _load_trained_models(self):
        """Load trained models from saved files"""
        try:
            saved_models_dir = self.config['models']['saved_models_dir']
            
            # Load ML models
            for model_name, model in self.ml_models.items():
                model_file = saved_models_dir / self.config['models']['individual_models'][model_name]
                if model_file.exists():
                    try:
                        model.load_model(str(model_file))
                        self.logger.info(f"Loaded {model_name} model")
                    except Exception as e:
                        self.logger.warning(f"Could not load {model_name} model: {e}")
            
            # Load DL models
            for model_name, model in self.dl_models.items():
                model_file = saved_models_dir / self.config['models']['individual_models'][model_name]
                if model_file.exists():
                    try:
                        model.load_model(str(model_file))
                        self.logger.info(f"Loaded {model_name} model")
                    except Exception as e:
                        self.logger.warning(f"Could not load {model_name} model: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error loading trained models: {e}")
    
    def start_system(self, web_port: int = 5000, web_host: str = "0.0.0.0") -> bool:
        """Start the complete system"""
        try:
            if not self.is_initialized:
                self.logger.error("System not initialized. Please run initialize_components() first.")
                return False
            
            self.logger.info("Starting cybersecurity system...")
            self.performance_monitor.start_timer("system_startup")
            
            # Start threat detection
            if self.threat_detector:
                self.logger.info("Starting real-time threat detection...")
                self.threat_detector.start_detection()
            
            # Start web application
            if self.web_app:
                self.logger.info(f"Starting web application on {web_host}:{web_port}...")
                # Start web app in a separate thread
                import threading
                web_thread = threading.Thread(
                    target=self.web_app.run,
                    kwargs={'host': web_host, 'port': web_port, 'debug': False},
                    daemon=True
                )
                web_thread.start()
            
            self.is_running = True
            self.performance_monitor.end_timer("system_startup")
            
            self.logger.info("Cybersecurity system started successfully!")
            self.logger.info(f"Web interface available at: http://{web_host}:{web_port}")
            self.logger.info("Press Ctrl+C to stop the system")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start system: {e}")
            return False
    
    def stop_system(self):
        """Stop the system gracefully"""
        try:
            self.logger.info("Stopping cybersecurity system...")
            
            # Stop threat detection
            if self.threat_detector:
                self.threat_detector.stop_detection()
            
            self.is_running = False
            self.logger.info("System stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping system: {e}")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status"""
        status = {
            'is_initialized': self.is_initialized,
            'is_running': self.is_running,
            'components': {
                'preprocessor': self.preprocessor is not None,
                'ml_models': len(self.ml_models) > 0,
                'dl_models': len(self.dl_models) > 0,
                'threat_detector': self.threat_detector is not None,
                'chatbot': self.chatbot is not None,
                'web_app': self.web_app is not None
            },
            'performance_metrics': self.performance_monitor.get_metrics(),
            'timestamp': time.time()
        }
        
        # Add threat detection stats if available
        if self.threat_detector:
            status['threat_detection'] = self.threat_detector.get_detection_stats()
        
        return status
    
    def run_demo(self):
        """Run a demonstration of the system"""
        self.logger.info("Running system demonstration...")
        
        try:
            # Initialize components
            if not self.initialize_components(load_models=False):
                self.logger.error("Failed to initialize components for demo")
                return False
            
            # Start system
            if not self.start_system():
                self.logger.error("Failed to start system for demo")
                return False
            
            # Simulate some traffic
            if self.threat_detector:
                self.logger.info("Simulating network traffic...")
                self.threat_detector.simulate_traffic(100)
            
            # Keep system running
            self.logger.info("Demo running. Check the web interface for real-time updates.")
            self.logger.info("Press Ctrl+C to stop the demo.")
            
            # Wait for interrupt
            try:
                while self.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Demo interrupted by user")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Demo failed: {e}")
            return False
        finally:
            self.stop_system()

def signal_handler(signum, frame):
    """Handle system signals for graceful shutdown"""
    print("\n🛑 Shutdown signal received. Stopping system...")
    if 'system' in globals():
        system.stop_system()
    sys.exit(0)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Cybersecurity AI System')
    parser.add_argument('--mode', choices=['full', 'demo', 'preprocess', 'train'], 
                       default='full', help='System mode')
    parser.add_argument('--port', type=int, default=5000, help='Web server port')
    parser.add_argument('--host', default='0.0.0.0', help='Web server host')
    parser.add_argument('--no-models', action='store_true', 
                       help='Skip loading trained models')
    parser.add_argument('--config', help='Path to configuration file')
    
    args = parser.parse_args()
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("🚀 Cybersecurity AI System")
    print("=" * 50)
    
    # Create system instance
    global system
    system = CybersecuritySystem(args.config)
    
    try:
        if args.mode == 'preprocess':
            print("📊 Running data preprocessing...")
            system.initialize_components(load_models=False)
            system._run_preprocessing()
            print("✅ Data preprocessing completed!")
            
        elif args.mode == 'train':
            print("🤖 Training AI models...")
            system.initialize_components(load_models=False)
            system._train_models()
            print("✅ Model training completed!")
            
        elif args.mode == 'demo':
            print("🎮 Running system demonstration...")
            system.run_demo()
            
        else:  # full mode
            print("🔧 Initializing full system...")
            
            # Initialize components
            if not system.initialize_components(load_models=not args.no_models):
                print("❌ Failed to initialize system components")
                return 1
            
            # Start system
            if not system.start_system(web_port=args.port, web_host=args.host):
                print("❌ Failed to start system")
                return 1
            
            # Keep system running
            try:
                while system.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n🛑 System interrupted by user")
            
        return 0
        
    except Exception as e:
        print(f"❌ System error: {e}")
        return 1
    finally:
        if system:
            system.stop_system()

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)


