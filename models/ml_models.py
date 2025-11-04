"""
Machine Learning Models for Cybersecurity Threat Detection

This module implements various ML models including Random Forest, XGBoost, and Isolation Forest
for detecting cybersecurity threats in network traffic data.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import GridSearchCV, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import xgboost as xgb
import joblib
import pickle
from typing import Dict, List, Tuple, Any, Optional
import warnings
warnings.filterwarnings('ignore')

from utils.helpers import ModelEvaluator, ModelManager, Logger, PerformanceMonitor
from config.config import ML_MODEL_PARAMS, MODEL_CONFIG

class BaseMLModel:
    """Base class for machine learning models"""
    
    def __init__(self, model_name: str, logger: Logger = None):
        self.model_name = model_name
        self.model = None
        self.is_trained = False
        self.logger = logger or Logger(f"{model_name}_model")
        self.performance_monitor = PerformanceMonitor()
        self.feature_importance = None
        self.training_history = {}
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray = None, y_val: np.ndarray = None) -> Dict[str, Any]:
        """Train the model"""
        raise NotImplementedError("Subclasses must implement train method")
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        return self.model.predict(X)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        if hasattr(self.model, 'predict_proba'):
            return self.model.predict_proba(X)
        else:
            raise ValueError(f"{self.model_name} does not support probability predictions")
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Evaluate model performance"""
        if not self.is_trained:
            raise ValueError("Model must be trained before evaluation")
        
        y_pred = self.predict(X_test)
        y_prob = self.predict_proba(X_test) if hasattr(self.model, 'predict_proba') else None
        
        evaluator = ModelEvaluator()
        evaluation_results = evaluator.evaluate_classification_model(
            y_test, y_pred, y_prob
        )
        
        self.logger.info(f"{self.model_name} evaluation completed")
        return evaluation_results
    
    def save_model(self, filepath: str):
        """Save trained model"""
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        metadata = {
            'model_name': self.model_name,
            'is_trained': self.is_trained,
            'feature_importance': self.feature_importance,
            'training_history': self.training_history
        }
        
        ModelManager.save_model(self, filepath, metadata)
        self.logger.info(f"{self.model_name} saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load trained model"""
        model_data, metadata = ModelManager.load_model(filepath)
        
        self.model = model_data.model
        self.is_trained = metadata.get('is_trained', False)
        self.feature_importance = metadata.get('feature_importance')
        self.training_history = metadata.get('training_history', {})
        
        self.logger.info(f"{self.model_name} loaded from {filepath}")

class RandomForestModel(BaseMLModel):
    """Random Forest classifier for threat detection"""
    
    def __init__(self, **params):
        super().__init__("RandomForest")
        self.params = {**ML_MODEL_PARAMS['random_forest'], **params}
        self.model = RandomForestClassifier(**self.params)
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray = None, y_val: np.ndarray = None) -> Dict[str, Any]:
        """Train Random Forest model"""
        self.logger.info("Starting Random Forest training...")
        self.performance_monitor.start_timer("rf_training")
        
        # Train the model
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        # Get feature importance
        self.feature_importance = self.model.feature_importances_
        
        # Cross-validation score
        cv_scores = cross_val_score(self.model, X_train, y_train, cv=5, scoring='accuracy')
        
        self.performance_monitor.end_timer("rf_training")
        
        training_results = {
            'cv_mean_score': cv_scores.mean(),
            'cv_std_score': cv_scores.std(),
            'feature_importance': self.feature_importance.tolist(),
            'n_estimators': self.model.n_estimators,
            'max_depth': self.model.max_depth
        }
        
        self.training_history = training_results
        self.logger.info(f"Random Forest training completed. CV Score: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
        
        return training_results
    
    def optimize_hyperparameters(self, X_train: np.ndarray, y_train: np.ndarray) -> Dict[str, Any]:
        """Optimize hyperparameters using GridSearchCV"""
        self.logger.info("Starting hyperparameter optimization...")
        
        param_grid = {
            'n_estimators': [50, 100, 200],
            'max_depth': [10, 20, 30, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        
        grid_search = GridSearchCV(
            RandomForestClassifier(random_state=42, n_jobs=-1),
            param_grid, cv=3, scoring='accuracy', n_jobs=-1, verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        # Update model with best parameters
        self.model = grid_search.best_estimator_
        self.params.update(grid_search.best_params_)
        
        optimization_results = {
            'best_params': grid_search.best_params_,
            'best_score': grid_search.best_score_,
            'cv_results': grid_search.cv_results_
        }
        
        self.logger.info(f"Hyperparameter optimization completed. Best score: {grid_search.best_score_:.4f}")
        return optimization_results

class XGBoostModel(BaseMLModel):
    """XGBoost classifier for threat detection"""
    
    def __init__(self, **params):
        super().__init__("XGBoost")
        self.params = {**ML_MODEL_PARAMS['xgboost'], **params}
        self.model = xgb.XGBClassifier(**self.params)
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray = None, y_val: np.ndarray = None) -> Dict[str, Any]:
        """Train XGBoost model with label remapping"""
        self.logger.info("Starting XGBoost training...")
        self.performance_monitor.start_timer("xgb_training")
        
        # Handle non-consecutive labels by remapping
        unique_labels = np.unique(y_train)
        self.label_mapping = {old_label: new_label for new_label, old_label in enumerate(unique_labels)}
        self.reverse_mapping = {new_label: old_label for old_label, new_label in self.label_mapping.items()}
        
        # Remap labels to consecutive integers starting from 0
        y_train_mapped = np.array([self.label_mapping[label] for label in y_train])
        y_val_mapped = None
        if X_val is not None and y_val is not None:
            y_val_mapped = np.array([self.label_mapping[label] for label in y_val])
        
        # Prepare validation data if provided
        eval_set = [(X_val, y_val_mapped)] if X_val is not None and y_val_mapped is not None else None
        
        # Train the model
        self.model.fit(
            X_train, y_train_mapped,
            eval_set=eval_set,
            eval_metric='mlogloss',
            verbose=False
        )
        self.is_trained = True
        
        # Get feature importance
        self.feature_importance = self.model.feature_importances_
        
        # Cross-validation score
        cv_scores = cross_val_score(self.model, X_train, y_train_mapped, cv=5, scoring='accuracy')
        
        self.performance_monitor.end_timer("xgb_training")
        
        training_results = {
            'cv_mean_score': cv_scores.mean(),
            'cv_std_score': cv_scores.std(),
            'feature_importance': self.feature_importance.tolist(),
            'n_estimators': self.model.n_estimators,
            'max_depth': self.model.max_depth,
            'learning_rate': self.model.learning_rate,
            'label_mapping': self.label_mapping,
            'num_classes': len(unique_labels)
        }
        
        self.training_history = training_results
        self.logger.info(f"XGBoost training completed. CV Score: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
        
        return training_results
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions with label remapping"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        predictions = self.model.predict(X)
        
        # Remap predictions back to original labels
        if hasattr(self, 'reverse_mapping'):
            predictions = np.array([self.reverse_mapping[pred] for pred in predictions])
        
        return predictions
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        if hasattr(self.model, 'predict_proba'):
            return self.model.predict_proba(X)
        else:
            raise ValueError("Model does not support probability predictions")
    
    def optimize_hyperparameters(self, X_train: np.ndarray, y_train: np.ndarray) -> Dict[str, Any]:
        """Optimize hyperparameters using GridSearchCV"""
        self.logger.info("Starting XGBoost hyperparameter optimization...")
        
        param_grid = {
            'n_estimators': [50, 100, 200],
            'max_depth': [3, 6, 9],
            'learning_rate': [0.01, 0.1, 0.2],
            'subsample': [0.8, 0.9, 1.0],
            'colsample_bytree': [0.8, 0.9, 1.0]
        }
        
        grid_search = GridSearchCV(
            xgb.XGBClassifier(random_state=42, n_jobs=-1),
            param_grid, cv=3, scoring='accuracy', n_jobs=-1, verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        # Update model with best parameters
        self.model = grid_search.best_estimator_
        self.params.update(grid_search.best_params_)
        
        optimization_results = {
            'best_params': grid_search.best_params_,
            'best_score': grid_search.best_score_,
            'cv_results': grid_search.cv_results_
        }
        
        self.logger.info(f"XGBoost hyperparameter optimization completed. Best score: {grid_search.best_score_:.4f}")
        return optimization_results

class IsolationForestModel(BaseMLModel):
    """Isolation Forest for anomaly detection"""
    
    def __init__(self, **params):
        super().__init__("IsolationForest")
        self.params = {**ML_MODEL_PARAMS['isolation_forest'], **params}
        self.model = IsolationForest(**self.params)
        self.threshold = None
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray = None, y_val: np.ndarray = None) -> Dict[str, Any]:
        """Train Isolation Forest model"""
        self.logger.info("Starting Isolation Forest training...")
        self.performance_monitor.start_timer("if_training")
        
        # For Isolation Forest, we only use normal data (label 0)
        normal_mask = y_train == 0
        X_normal = X_train[normal_mask]
        
        if len(X_normal) == 0:
            raise ValueError("No normal samples found for Isolation Forest training")
        
        # Train the model on normal data only
        self.model.fit(X_normal)
        self.is_trained = True
        
        # Calculate threshold based on training data
        scores = self.model.decision_function(X_normal)
        self.threshold = np.percentile(scores, 10)  # Bottom 10% as threshold
        
        self.performance_monitor.end_timer("if_training")
        
        training_results = {
            'n_normal_samples': len(X_normal),
            'threshold': self.threshold,
            'contamination': self.model.contamination,
            'n_estimators': self.model.n_estimators
        }
        
        self.training_history = training_results
        self.logger.info(f"Isolation Forest training completed on {len(X_normal)} normal samples")
        
        return training_results
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions (1 for normal, -1 for anomaly)"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        predictions = self.model.predict(X)
        # Convert -1 (anomaly) to 1, 1 (normal) to 0 for consistency
        return np.where(predictions == -1, 1, 0)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly probabilities"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        scores = self.model.decision_function(X)
        # Convert scores to probabilities (lower scores = higher anomaly probability)
        probabilities = 1 / (1 + np.exp(scores))
        
        # Create probability matrix [normal_prob, anomaly_prob]
        prob_matrix = np.column_stack([1 - probabilities, probabilities])
        return prob_matrix
    
    def get_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Get raw anomaly scores"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        return self.model.decision_function(X)

class EnsembleModel:
    """Ensemble model combining multiple ML models"""
    
    def __init__(self, models: List[BaseMLModel], weights: List[float] = None):
        self.models = models
        self.weights = weights or [1.0 / len(models)] * len(models)
        self.is_trained = False
        self.logger = Logger("EnsembleModel")
        
        if len(self.weights) != len(self.models):
            raise ValueError("Number of weights must match number of models")
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray = None, y_val: np.ndarray = None) -> Dict[str, Any]:
        """Train all models in the ensemble"""
        self.logger.info("Starting ensemble training...")
        
        training_results = {}
        
        for i, model in enumerate(self.models):
            self.logger.info(f"Training model {i+1}/{len(self.models)}: {model.model_name}")
            try:
                result = model.train(X_train, y_train, X_val, y_val)
                training_results[model.model_name] = result
            except Exception as e:
                self.logger.error(f"Error training {model.model_name}: {e}")
                raise
        
        self.is_trained = True
        self.logger.info("Ensemble training completed successfully")
        
        return training_results
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make ensemble predictions using weighted voting"""
        if not self.is_trained:
            raise ValueError("Ensemble must be trained before making predictions")
        
        predictions = []
        for model in self.models:
            pred = model.predict(X)
            predictions.append(pred)
        
        # Weighted voting
        weighted_predictions = np.zeros_like(predictions[0], dtype=float)
        for pred, weight in zip(predictions, self.weights):
            weighted_predictions += pred * weight
        
        # Convert to final predictions
        final_predictions = np.round(weighted_predictions).astype(int)
        return final_predictions
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Make ensemble probability predictions"""
        if not self.is_trained:
            raise ValueError("Ensemble must be trained before making predictions")
        
        probabilities = []
        for model in self.models:
            if hasattr(model, 'predict_proba'):
                prob = model.predict_proba(X)
                probabilities.append(prob)
            else:
                # Convert predictions to probabilities
                pred = model.predict(X)
                prob = np.column_stack([1 - pred, pred])
                probabilities.append(prob)
        
        # Weighted average of probabilities
        weighted_probs = np.zeros_like(probabilities[0], dtype=float)
        for prob, weight in zip(probabilities, self.weights):
            weighted_probs += prob * weight
        
        return weighted_probs
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Evaluate ensemble performance"""
        if not self.is_trained:
            raise ValueError("Ensemble must be trained before evaluation")
        
        y_pred = self.predict(X_test)
        y_prob = self.predict_proba(X_test)
        
        evaluator = ModelEvaluator()
        evaluation_results = evaluator.evaluate_classification_model(y_test, y_pred, y_prob)
        
        # Individual model evaluations
        individual_results = {}
        for model in self.models:
            try:
                individual_results[model.model_name] = model.evaluate(X_test, y_test)
            except Exception as e:
                self.logger.error(f"Error evaluating {model.model_name}: {e}")
        
        evaluation_results['individual_models'] = individual_results
        
        return evaluation_results
    
    def save_ensemble(self, filepath: str):
        """Save ensemble model"""
        if not self.is_trained:
            raise ValueError("Ensemble must be trained before saving")
        
        ensemble_data = {
            'models': self.models,
            'weights': self.weights,
            'is_trained': self.is_trained
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(ensemble_data, f)
        
        self.logger.info(f"Ensemble model saved to {filepath}")

def create_ml_models() -> Dict[str, BaseMLModel]:
    """Create and return all ML models"""
    models = {
        'random_forest': RandomForestModel(),
        'xgboost': XGBoostModel(),
        'isolation_forest': IsolationForestModel()
    }
    return models

def train_all_models(X_train: np.ndarray, y_train: np.ndarray, 
                    X_val: np.ndarray, y_val: np.ndarray) -> Dict[str, BaseMLModel]:
    """Train all ML models"""
    models = create_ml_models()
    logger = Logger("MLTraining")
    
    logger.info("Starting training of all ML models...")
    
    for name, model in models.items():
        try:
            logger.info(f"Training {name}...")
            model.train(X_train, y_train, X_val, y_val)
            logger.info(f"{name} training completed successfully")
        except Exception as e:
            logger.error(f"Error training {name}: {e}")
            raise
    
    logger.info("All ML models trained successfully")
    return models

if __name__ == "__main__":
    # Example usage
    from data.preprocess import CICIDS2017Preprocessor
    
    # Load and preprocess data
    preprocessor = CICIDS2017Preprocessor()
    processed_data = preprocessor.load_processed_data()
    
    if processed_data:
        # Train models
        models = train_all_models(
            processed_data['X_train'], processed_data['y_train'],
            processed_data['X_val'], processed_data['y_val']
        )
        
        # Evaluate models
        for name, model in models.items():
            results = model.evaluate(processed_data['X_test'], processed_data['y_test'])
            print(f"\n{name} Results:")
            print(f"Accuracy: {results['accuracy']:.4f}")
            if results['roc_auc']:
                print(f"ROC AUC: {results['roc_auc']:.4f}")



