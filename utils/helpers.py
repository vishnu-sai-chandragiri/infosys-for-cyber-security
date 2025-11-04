"""
Utility functions for the cybersecurity threat detection system
"""

import numpy as np
import pandas as pd
import pickle
import json
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
import joblib
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import matplotlib.pyplot as plt
import seaborn as sns

class Logger:
    """Custom logger for the cybersecurity system"""
    
    def __init__(self, name: str, log_file: str = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def debug(self, message: str):
        self.logger.debug(message)

class DataValidator:
    """Data validation utilities"""
    
    @staticmethod
    def validate_features(X: np.ndarray, expected_features: int) -> bool:
        """Validate feature matrix dimensions"""
        if X.shape[1] != expected_features:
            raise ValueError(f"Expected {expected_features} features, got {X.shape[1]}")
        return True
    
    @staticmethod
    def validate_labels(y: np.ndarray, expected_classes: List[int]) -> bool:
        """Validate label array"""
        unique_labels = np.unique(y)
        for label in unique_labels:
            if label not in expected_classes:
                raise ValueError(f"Unexpected label {label} found")
        return True
    
    @staticmethod
    def check_data_quality(X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Check data quality metrics"""
        quality_report = {
            'samples': X.shape[0],
            'features': X.shape[1],
            'missing_values': np.isnan(X).sum(),
            'infinite_values': np.isinf(X).sum(),
            'class_distribution': dict(zip(*np.unique(y, return_counts=True))),
            'feature_ranges': {
                'min': X.min(axis=0),
                'max': X.max(axis=0),
                'mean': X.mean(axis=0),
                'std': X.std(axis=0)
            }
        }
        return quality_report

class ModelEvaluator:
    """Model evaluation utilities"""
    
    @staticmethod
    def evaluate_classification_model(y_true: np.ndarray, y_pred: np.ndarray, 
                                    y_prob: np.ndarray = None, 
                                    class_names: List[str] = None) -> Dict[str, Any]:
        """Comprehensive model evaluation"""
        evaluation_results = {}
        
        # Classification report
        evaluation_results['classification_report'] = classification_report(
            y_true, y_pred, target_names=class_names, output_dict=True
        )
        
        # Confusion matrix
        evaluation_results['confusion_matrix'] = confusion_matrix(y_true, y_pred).tolist()
        
        # ROC AUC score (if probabilities provided)
        if y_prob is not None:
            try:
                if len(np.unique(y_true)) == 2:  # Binary classification
                    evaluation_results['roc_auc'] = roc_auc_score(y_true, y_prob)
                else:  # Multiclass classification
                    evaluation_results['roc_auc'] = roc_auc_score(
                        y_true, y_prob, multi_class='ovr', average='weighted'
                    )
            except Exception as e:
                evaluation_results['roc_auc'] = None
                print(f"Could not calculate ROC AUC: {e}")
        
        # Additional metrics
        evaluation_results['accuracy'] = (y_true == y_pred).mean()
        evaluation_results['total_samples'] = len(y_true)
        
        return evaluation_results
    
    @staticmethod
    def plot_confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray, 
                            class_names: List[str] = None, 
                            save_path: str = None):
        """Plot confusion matrix"""
        cm = confusion_matrix(y_true, y_pred)
        
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=class_names, yticklabels=class_names)
        plt.title('Confusion Matrix')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    @staticmethod
    def plot_class_distribution(y: np.ndarray, class_names: List[str] = None,
                              save_path: str = None):
        """Plot class distribution"""
        unique, counts = np.unique(y, return_counts=True)
        
        plt.figure(figsize=(12, 6))
        bars = plt.bar(range(len(unique)), counts)
        plt.xlabel('Class')
        plt.ylabel('Count')
        plt.title('Class Distribution')
        
        if class_names:
            plt.xticks(range(len(unique)), [class_names[i] for i in unique], rotation=45)
        
        # Add value labels on bars
        for bar, count in zip(bars, counts):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                    str(count), ha='center', va='bottom')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

class ModelManager:
    """Model saving and loading utilities"""
    
    @staticmethod
    def save_model(model: Any, filepath: str, metadata: Dict[str, Any] = None):
        """Save model with metadata"""
        model_data = {
            'model': model,
            'metadata': metadata or {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Create directory if it doesn't exist
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        
        # Save model
        if filepath.endswith('.pkl'):
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
        elif filepath.endswith('.joblib'):
            joblib.dump(model_data, filepath)
        else:
            raise ValueError("Unsupported file format. Use .pkl or .joblib")
        
        print(f"Model saved to {filepath}")
    
    @staticmethod
    def load_model(filepath: str) -> Tuple[Any, Dict[str, Any]]:
        """Load model with metadata"""
        if not Path(filepath).exists():
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        # Load model
        if filepath.endswith('.pkl'):
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
        elif filepath.endswith('.joblib'):
            model_data = joblib.load(filepath)
        else:
            raise ValueError("Unsupported file format. Use .pkl or .joblib")
        
        model = model_data['model']
        metadata = model_data.get('metadata', {})
        
        print(f"Model loaded from {filepath}")
        return model, metadata

class SecurityUtils:
    """Security-related utility functions"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def generate_session_token() -> str:
        """Generate secure session token"""
        import secrets
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_input(input_data: Any, max_length: int = 1000) -> bool:
        """Validate user input for security"""
        if isinstance(input_data, str):
            if len(input_data) > max_length:
                return False
            # Check for potential SQL injection patterns
            dangerous_patterns = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'SELECT', 'UNION']
            if any(pattern in input_data.upper() for pattern in dangerous_patterns):
                return False
        return True

class PerformanceMonitor:
    """Performance monitoring utilities"""
    
    def __init__(self):
        self.metrics = {}
        self.start_time = None
    
    def start_timer(self, operation: str):
        """Start timing an operation"""
        self.start_time = datetime.now()
        self.metrics[operation] = {'start_time': self.start_time}
    
    def end_timer(self, operation: str):
        """End timing an operation"""
        if operation in self.metrics and self.start_time:
            end_time = datetime.now()
            duration = (end_time - self.start_time).total_seconds()
            self.metrics[operation]['end_time'] = end_time
            self.metrics[operation]['duration'] = duration
            print(f"{operation} completed in {duration:.2f} seconds")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        return self.metrics

class DataProcessor:
    """Data processing utilities"""
    
    @staticmethod
    def create_sequences(data: np.ndarray, sequence_length: int) -> np.ndarray:
        """Create sequences for time series data"""
        sequences = []
        for i in range(len(data) - sequence_length + 1):
            sequences.append(data[i:i + sequence_length])
        return np.array(sequences)
    
    @staticmethod
    def normalize_data(data: np.ndarray, method: str = 'standard') -> Tuple[np.ndarray, Any]:
        """Normalize data using specified method"""
        from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler
        
        if method == 'standard':
            scaler = StandardScaler()
        elif method == 'minmax':
            scaler = MinMaxScaler()
        elif method == 'robust':
            scaler = RobustScaler()
        else:
            raise ValueError("Method must be 'standard', 'minmax', or 'robust'")
        
        normalized_data = scaler.fit_transform(data)
        return normalized_data, scaler
    
    @staticmethod
    def handle_imbalanced_data(X: np.ndarray, y: np.ndarray, 
                             method: str = 'smote') -> Tuple[np.ndarray, np.ndarray]:
        """Handle imbalanced dataset"""
        from imblearn.over_sampling import SMOTE, ADASYN
        from imblearn.under_sampling import RandomUnderSampler
        
        if method == 'smote':
            sampler = SMOTE(random_state=42)
        elif method == 'adasyn':
            sampler = ADASYN(random_state=42)
        elif method == 'undersample':
            sampler = RandomUnderSampler(random_state=42)
        else:
            raise ValueError("Method must be 'smote', 'adasyn', or 'undersample'")
        
        X_resampled, y_resampled = sampler.fit_resample(X, y)
        return X_resampled, y_resampled

def format_threat_alert(threat_data: Dict[str, Any]) -> str:
    """Format threat alert message"""
    timestamp = threat_data.get('timestamp', datetime.now().isoformat())
    threat_type = threat_data.get('threat_type', 'Unknown')
    severity = threat_data.get('severity', 'Medium')
    confidence = threat_data.get('confidence', 0.0)
    source_ip = threat_data.get('source_ip', 'Unknown')
    target_ip = threat_data.get('target_ip', 'Unknown')
    
    alert_message = f"""
🚨 THREAT ALERT 🚨
Timestamp: {timestamp}
Threat Type: {threat_type}
Severity: {severity}
Confidence: {confidence:.2%}
Source IP: {source_ip}
Target IP: {target_ip}
"""
    return alert_message

def calculate_threat_score(features: np.ndarray, model: Any) -> float:
    """Calculate threat score for given features"""
    try:
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(features)
            # Use the maximum probability as threat score
            threat_score = np.max(probabilities)
        elif hasattr(model, 'decision_function'):
            scores = model.decision_function(features)
            # Normalize scores to 0-1 range
            threat_score = (scores - scores.min()) / (scores.max() - scores.min())
            threat_score = np.mean(threat_score)
        else:
            # For models without probability output
            predictions = model.predict(features)
            threat_score = float(predictions[0]) if len(predictions) > 0 else 0.0
        
        return min(max(threat_score, 0.0), 1.0)  # Clamp to [0, 1]
    except Exception as e:
        print(f"Error calculating threat score: {e}")
        return 0.0

def create_performance_report(model_results: Dict[str, Any]) -> str:
    """Create formatted performance report"""
    report = "📊 MODEL PERFORMANCE REPORT 📊\n\n"
    
    for model_name, results in model_results.items():
        report += f"Model: {model_name}\n"
        report += f"Accuracy: {results.get('accuracy', 0):.4f}\n"
        report += f"ROC AUC: {results.get('roc_auc', 0):.4f}\n"
        
        if 'classification_report' in results:
            cr = results['classification_report']
            report += f"Precision (weighted): {cr.get('weighted avg', {}).get('precision', 0):.4f}\n"
            report += f"Recall (weighted): {cr.get('weighted avg', {}).get('recall', 0):.4f}\n"
            report += f"F1-Score (weighted): {cr.get('weighted avg', {}).get('f1-score', 0):.4f}\n"
        
        report += "\n" + "="*50 + "\n\n"
    
    return report



