"""
Model Training Script for Cybersecurity Threat Detection System

This script trains all ML and DL models and creates an ensemble for optimal performance.
"""

import os
import sys
import numpy as np
import pandas as pd
import pickle
import json
from datetime import datetime
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from data.preprocess import CICIDS2017Preprocessor
from models.ml_models import (
    RandomForestModel, XGBoostModel, IsolationForestModel, 
    EnsembleModel, train_all_models
)
from models.dl_models import (
    LSTMModel, AutoencoderModel, DeepLearningEnsemble, 
    train_all_dl_models
)
from utils.helpers import Logger, PerformanceMonitor, create_performance_report
from config.config import MODEL_CONFIG, get_config

class ModelTrainer:
    """Main class for training all models"""
    
    def __init__(self):
        self.logger = Logger("ModelTrainer")
        self.performance_monitor = PerformanceMonitor()
        self.config = get_config()
        
        # Create necessary directories
        self.models_dir = Path(self.config['models']['models_dir'])
        self.saved_models_dir = Path(self.config['models']['saved_models_dir'])
        self.metrics_dir = Path(self.config['models']['model_metrics_dir'])
        
        for directory in [self.saved_models_dir, self.metrics_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        self.ml_models = {}
        self.dl_models = {}
        self.ensemble_model = None
        self.training_results = {}
    
    def load_data(self):
        """Load and preprocess the dataset"""
        self.logger.info("Loading and preprocessing dataset...")
        
        preprocessor = CICIDS2017Preprocessor()
        processed_data = preprocessor.load_processed_data()
        
        if processed_data is None:
            self.logger.error("No processed data found. Please run preprocessing first.")
            return None
        
        self.logger.info("Dataset loaded successfully")
        return processed_data
    
    def train_ml_models(self, processed_data):
        """Train all machine learning models"""
        self.logger.info("Starting ML model training...")
        self.performance_monitor.start_timer("ml_training")
        
        try:
            # Train all ML models
            self.ml_models = train_all_models(
                processed_data['X_train'], processed_data['y_train'],
                processed_data['X_val'], processed_data['y_val']
            )
            
            # Evaluate each model
            ml_results = {}
            for name, model in self.ml_models.items():
                self.logger.info(f"Evaluating {name}...")
                results = model.evaluate(processed_data['X_test'], processed_data['y_test'])
                ml_results[name] = results
                
                # Save individual model
                model_path = self.saved_models_dir / self.config['models']['individual_models'][name]
                model.save_model(str(model_path))
                
                # Save metrics
                metrics_path = self.metrics_dir / f"{name}_metrics.json"
                with open(metrics_path, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
            
            self.training_results['ml_models'] = ml_results
            self.performance_monitor.end_timer("ml_training")
            
            self.logger.info("ML model training completed successfully")
            return ml_results
            
        except Exception as e:
            self.logger.error(f"Error in ML model training: {e}")
            raise
    
    def train_dl_models(self, processed_data):
        """Train all deep learning models"""
        self.logger.info("Starting DL model training...")
        self.performance_monitor.start_timer("dl_training")
        
        try:
            # Train all DL models
            self.dl_models = train_all_dl_models(
                processed_data['X_train'], processed_data['y_train'],
                processed_data['X_val'], processed_data['y_val']
            )
            
            # Evaluate each model
            dl_results = {}
            for name, model in self.dl_models.items():
                self.logger.info(f"Evaluating {name}...")
                results = model.evaluate(processed_data['X_test'], processed_data['y_test'])
                dl_results[name] = results
                
                # Save individual model
                model_path = self.saved_models_dir / self.config['models']['individual_models'][name]
                model.save_model(str(model_path))
                
                # Save metrics
                metrics_path = self.metrics_dir / f"{name}_metrics.json"
                with open(metrics_path, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
            
            self.training_results['dl_models'] = dl_results
            self.performance_monitor.end_timer("dl_training")
            
            self.logger.info("DL model training completed successfully")
            return dl_results
            
        except Exception as e:
            self.logger.error(f"Error in DL model training: {e}")
            raise
    
    def create_ensemble(self, processed_data):
        """Create and train ensemble model"""
        self.logger.info("Creating ensemble model...")
        self.performance_monitor.start_timer("ensemble_training")
        
        try:
            # Combine ML and DL models for ensemble
            all_models = list(self.ml_models.values()) + list(self.dl_models.values())
            
            # Create ensemble with equal weights
            weights = [1.0 / len(all_models)] * len(all_models)
            self.ensemble_model = EnsembleModel(all_models, weights)
            
            # Train ensemble
            ensemble_results = self.ensemble_model.train(
                processed_data['X_train'], processed_data['y_train'],
                processed_data['X_val'], processed_data['y_val']
            )
            
            # Evaluate ensemble
            ensemble_evaluation = self.ensemble_model.evaluate(
                processed_data['X_test'], processed_data['y_test']
            )
            
            # Save ensemble model
            ensemble_path = self.saved_models_dir / self.config['models']['ensemble_model_name']
            self.ensemble_model.save_ensemble(str(ensemble_path))
            
            # Save ensemble metrics
            ensemble_metrics_path = self.metrics_dir / "ensemble_metrics.json"
            with open(ensemble_metrics_path, 'w') as f:
                json.dump(ensemble_evaluation, f, indent=2, default=str)
            
            self.training_results['ensemble'] = ensemble_evaluation
            self.performance_monitor.end_timer("ensemble_training")
            
            self.logger.info("Ensemble model created and trained successfully")
            return ensemble_evaluation
            
        except Exception as e:
            self.logger.error(f"Error in ensemble creation: {e}")
            raise
    
    def optimize_models(self, processed_data):
        """Optimize hyperparameters for best performing models"""
        self.logger.info("Starting model optimization...")
        
        try:
            # Optimize Random Forest
            if 'random_forest' in self.ml_models:
                self.logger.info("Optimizing Random Forest...")
                rf_model = self.ml_models['random_forest']
                rf_optimization = rf_model.optimize_hyperparameters(
                    processed_data['X_train'], processed_data['y_train']
                )
                
                # Save optimization results
                opt_path = self.metrics_dir / "rf_optimization.json"
                with open(opt_path, 'w') as f:
                    json.dump(rf_optimization, f, indent=2, default=str)
            
            # Optimize XGBoost
            if 'xgboost' in self.ml_models:
                self.logger.info("Optimizing XGBoost...")
                xgb_model = self.ml_models['xgboost']
                xgb_optimization = xgb_model.optimize_hyperparameters(
                    processed_data['X_train'], processed_data['y_train']
                )
                
                # Save optimization results
                opt_path = self.metrics_dir / "xgb_optimization.json"
                with open(opt_path, 'w') as f:
                    json.dump(xgb_optimization, f, indent=2, default=str)
            
            self.logger.info("Model optimization completed")
            
        except Exception as e:
            self.logger.error(f"Error in model optimization: {e}")
            raise
    
    def generate_training_report(self):
        """Generate comprehensive training report"""
        self.logger.info("Generating training report...")
        
        try:
            # Create performance report
            all_results = {}
            if 'ml_models' in self.training_results:
                all_results.update(self.training_results['ml_models'])
            if 'dl_models' in self.training_results:
                all_results.update(self.training_results['dl_models'])
            if 'ensemble' in self.training_results:
                all_results['ensemble'] = self.training_results['ensemble']
            
            report = create_performance_report(all_results)
            
            # Save report
            report_path = self.metrics_dir / "training_report.txt"
            with open(report_path, 'w') as f:
                f.write(report)
            
            # Create detailed JSON report
            detailed_report = {
                'training_timestamp': datetime.now().isoformat(),
                'performance_metrics': self.performance_monitor.get_metrics(),
                'model_results': self.training_results,
                'configuration': self.config
            }
            
            detailed_report_path = self.metrics_dir / "detailed_training_report.json"
            with open(detailed_report_path, 'w') as f:
                json.dump(detailed_report, f, indent=2, default=str)
            
            self.logger.info(f"Training report saved to {report_path}")
            print("\n" + "="*80)
            print(report)
            print("="*80)
            
        except Exception as e:
            self.logger.error(f"Error generating training report: {e}")
            raise
    
    def run_training_pipeline(self):
        """Run the complete training pipeline"""
        self.logger.info("Starting complete training pipeline...")
        
        try:
            # Load data
            processed_data = self.load_data()
            if processed_data is None:
                return False
            
            # Train ML models
            ml_results = self.train_ml_models(processed_data)
            
            # Train DL models
            dl_results = self.train_dl_models(processed_data)
            
            # Create ensemble
            ensemble_results = self.create_ensemble(processed_data)
            
            # Optimize best models
            self.optimize_models(processed_data)
            
            # Generate report
            self.generate_training_report()
            
            self.logger.info("Complete training pipeline finished successfully!")
            return True
            
        except Exception as e:
            self.logger.error(f"Training pipeline failed: {e}")
            return False

def main():
    """Main function to run model training"""
    print("🚀 Starting Cybersecurity Threat Detection Model Training 🚀")
    print("="*80)
    
    trainer = ModelTrainer()
    success = trainer.run_training_pipeline()
    
    if success:
        print("\n✅ Model training completed successfully!")
        print("📊 Check the metrics/ directory for detailed results")
        print("💾 Trained models saved in models/saved/ directory")
    else:
        print("\n❌ Model training failed!")
        print("🔍 Check the logs for error details")
    
    print("="*80)

if __name__ == "__main__":
    main()



