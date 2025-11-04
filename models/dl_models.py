"""
Deep Learning Models for Cybersecurity Threat Detection

This module implements LSTM and Autoencoder models for detecting cybersecurity threats
in network traffic data using deep learning approaches.
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models, callbacks
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.utils import to_categorical
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import joblib
import pickle
from typing import Dict, List, Tuple, Any, Optional
import warnings
warnings.filterwarnings('ignore')

from utils.helpers import ModelEvaluator, ModelManager, Logger, PerformanceMonitor, DataProcessor
from config.config import DL_MODEL_CONFIG, MODEL_CONFIG

class BaseDLModel:
    """Base class for deep learning models"""
    
    def __init__(self, model_name: str, logger: Logger = None):
        self.model_name = model_name
        self.model = None
        self.is_trained = False
        self.logger = logger or Logger(f"{model_name}_model")
        self.performance_monitor = PerformanceMonitor()
        self.training_history = {}
        self.scaler = StandardScaler()
    
    def build_model(self, input_shape: Tuple[int, ...]) -> keras.Model:
        """Build the model architecture"""
        raise NotImplementedError("Subclasses must implement build_model method")
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray = None, y_val: np.ndarray = None) -> Dict[str, Any]:
        """Train the model"""
        raise NotImplementedError("Subclasses must implement train method")
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        return self.model.predict(X, verbose=0)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        return self.model.predict(X, verbose=0)
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Evaluate model performance"""
        if not self.is_trained:
            raise ValueError("Model must be trained before evaluation")
        
        y_pred_proba = self.predict_proba(X_test)
        y_pred = np.argmax(y_pred_proba, axis=1)
        
        evaluator = ModelEvaluator()
        evaluation_results = evaluator.evaluate_classification_model(
            y_test, y_pred, y_pred_proba
        )
        
        self.logger.info(f"{self.model_name} evaluation completed")
        return evaluation_results
    
    def save_model(self, filepath: str):
        """Save trained model"""
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        # Save Keras model
        self.model.save(filepath)
        
        # Save additional metadata
        metadata = {
            'model_name': self.model_name,
            'is_trained': self.is_trained,
            'training_history': self.training_history,
            'scaler': self.scaler
        }
        
        metadata_path = filepath.replace('.h5', '_metadata.pkl')
        with open(metadata_path, 'wb') as f:
            pickle.dump(metadata, f)
        
        self.logger.info(f"{self.model_name} saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load trained model"""
        # Load Keras model
        self.model = keras.models.load_model(filepath)
        
        # Load metadata
        metadata_path = filepath.replace('.h5', '_metadata.pkl')
        try:
            with open(metadata_path, 'rb') as f:
                metadata = pickle.load(f)
            
            self.is_trained = metadata.get('is_trained', False)
            self.training_history = metadata.get('training_history', {})
            self.scaler = metadata.get('scaler', StandardScaler())
        except FileNotFoundError:
            self.logger.warning("Metadata file not found, using default values")
        
        self.logger.info(f"{self.model_name} loaded from {filepath}")

class LSTMModel(BaseDLModel):
    """LSTM model for sequence-based threat detection"""
    
    def __init__(self, **params):
        super().__init__("LSTM")
        self.params = {**DL_MODEL_CONFIG['lstm'], **params}
        self.sequence_length = self.params['sequence_length']
        self.lstm_units = self.params['lstm_units']
        self.dropout_rate = self.params['dropout_rate']
        self.epochs = self.params['epochs']
        self.batch_size = self.params['batch_size']
    
    def build_model(self, input_shape: Tuple[int, ...]) -> keras.Model:
        """Build LSTM model architecture"""
        model = keras.Sequential([
            layers.LSTM(self.lstm_units[0], return_sequences=True, input_shape=input_shape),
            layers.Dropout(self.dropout_rate),
            
            layers.LSTM(self.lstm_units[1], return_sequences=False),
            layers.Dropout(self.dropout_rate),
            
            layers.Dense(64, activation='relu'),
            layers.Dropout(self.dropout_rate),
            
            layers.Dense(32, activation='relu'),
            layers.Dropout(self.dropout_rate),
            
            layers.Dense(15, activation='softmax')  # 15 attack types + benign
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def prepare_sequences(self, X: np.ndarray, y: np.ndarray = None) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare data sequences for LSTM"""
        data_processor = DataProcessor()
        X_sequences = data_processor.create_sequences(X, self.sequence_length)
        
        if y is not None:
            # Adjust labels for sequence data
            y_sequences = y[self.sequence_length - 1:]
            y_sequences = to_categorical(y_sequences, num_classes=15)
            return X_sequences, y_sequences
        else:
            return X_sequences, None
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray = None, y_val: np.ndarray = None) -> Dict[str, Any]:
        """Train LSTM model"""
        self.logger.info("Starting LSTM training...")
        self.performance_monitor.start_timer("lstm_training")
        
        # Prepare sequence data
        X_train_seq, y_train_seq = self.prepare_sequences(X_train, y_train)
        X_val_seq, y_val_seq = None, None
        
        if X_val is not None and y_val is not None:
            X_val_seq, y_val_seq = self.prepare_sequences(X_val, y_val)
        
        # Build model
        input_shape = (X_train_seq.shape[1], X_train_seq.shape[2])
        self.model = self.build_model(input_shape)
        
        # Print model summary
        self.model.summary()
        
        # Define callbacks
        callbacks_list = [
            callbacks.EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            ),
            callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=0.0001
            )
        ]
        
        # Train the model
        history = self.model.fit(
            X_train_seq, y_train_seq,
            epochs=self.epochs,
            batch_size=self.batch_size,
            validation_data=(X_val_seq, y_val_seq) if X_val_seq is not None else None,
            validation_split=self.params['validation_split'] if X_val_seq is None else None,
            callbacks=callbacks_list,
            verbose=1
        )
        
        self.is_trained = True
        self.training_history = history.history
        
        self.performance_monitor.end_timer("lstm_training")
        
        training_results = {
            'final_accuracy': history.history['accuracy'][-1],
            'final_val_accuracy': history.history.get('val_accuracy', [0])[-1],
            'final_loss': history.history['loss'][-1],
            'final_val_loss': history.history.get('val_loss', [0])[-1],
            'epochs_trained': len(history.history['loss']),
            'sequence_length': self.sequence_length
        }
        
        self.logger.info(f"LSTM training completed. Final accuracy: {training_results['final_accuracy']:.4f}")
        
        return training_results
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        X_seq, _ = self.prepare_sequences(X)
        y_pred_proba = self.model.predict(X_seq, verbose=0)
        return np.argmax(y_pred_proba, axis=1)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        X_seq, _ = self.prepare_sequences(X)
        return self.model.predict(X_seq, verbose=0)

class AutoencoderModel(BaseDLModel):
    """Autoencoder model for anomaly detection"""
    
    def __init__(self, **params):
        super().__init__("Autoencoder")
        self.params = {**DL_MODEL_CONFIG['autoencoder'], **params}
        self.encoding_dim = self.params['encoding_dim']
        self.hidden_layers = self.params['hidden_layers']
        self.epochs = self.params['epochs']
        self.batch_size = self.params['batch_size']
        self.reconstruction_threshold = self.params['reconstruction_threshold']
        self.threshold = None
    
    def build_model(self, input_shape: Tuple[int, ...]) -> keras.Model:
        """Build autoencoder model architecture"""
        input_dim = input_shape[0]
        
        # Encoder
        encoder_input = layers.Input(shape=(input_dim,))
        encoded = encoder_input
        
        for hidden_dim in self.hidden_layers:
            encoded = layers.Dense(hidden_dim, activation='relu')(encoded)
            encoded = layers.Dropout(0.2)(encoded)
        
        encoded = layers.Dense(self.encoding_dim, activation='relu')(encoded)
        
        # Decoder
        decoded = encoded
        for hidden_dim in reversed(self.hidden_layers):
            decoded = layers.Dense(hidden_dim, activation='relu')(decoded)
            decoded = layers.Dropout(0.2)(decoded)
        
        decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)
        
        # Autoencoder model
        autoencoder = keras.Model(encoder_input, decoded)
        
        # Encoder model (for feature extraction)
        encoder = keras.Model(encoder_input, encoded)
        
        autoencoder.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='mse',
            metrics=['mae']
        )
        
        return autoencoder, encoder
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray = None, y_val: np.ndarray = None) -> Dict[str, Any]:
        """Train autoencoder model"""
        self.logger.info("Starting Autoencoder training...")
        self.performance_monitor.start_timer("autoencoder_training")
        
        # Normalize data
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = None
        if X_val is not None:
            X_val_scaled = self.scaler.transform(X_val)
        
        # Build model
        input_shape = (X_train_scaled.shape[1],)
        self.model, self.encoder = self.build_model(input_shape)
        
        # Print model summary
        self.model.summary()
        
        # Define callbacks
        callbacks_list = [
            callbacks.EarlyStopping(
                monitor='val_loss',
                patience=15,
                restore_best_weights=True
            ),
            callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=0.0001
            )
        ]
        
        # Train the model
        history = self.model.fit(
            X_train_scaled, X_train_scaled,  # Autoencoder learns to reconstruct input
            epochs=self.epochs,
            batch_size=self.batch_size,
            validation_data=(X_val_scaled, X_val_scaled) if X_val_scaled is not None else None,
            validation_split=self.params['validation_split'] if X_val_scaled is None else None,
            callbacks=callbacks_list,
            verbose=1
        )
        
        self.is_trained = True
        self.training_history = history.history
        
        # Calculate reconstruction threshold
        train_reconstructions = self.model.predict(X_train_scaled, verbose=0)
        train_mse = np.mean(np.square(X_train_scaled - train_reconstructions), axis=1)
        self.threshold = np.percentile(train_mse, 95)  # 95th percentile as threshold
        
        self.performance_monitor.end_timer("autoencoder_training")
        
        training_results = {
            'final_loss': history.history['loss'][-1],
            'final_val_loss': history.history.get('val_loss', [0])[-1],
            'final_mae': history.history['mae'][-1],
            'final_val_mae': history.history.get('val_mae', [0])[-1],
            'epochs_trained': len(history.history['loss']),
            'reconstruction_threshold': self.threshold,
            'encoding_dim': self.encoding_dim
        }
        
        self.logger.info(f"Autoencoder training completed. Final loss: {training_results['final_loss']:.6f}")
        
        return training_results
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions (0 for normal, 1 for anomaly)"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        X_scaled = self.scaler.transform(X)
        reconstructions = self.model.predict(X_scaled, verbose=0)
        
        # Calculate reconstruction error
        mse = np.mean(np.square(X_scaled - reconstructions), axis=1)
        
        # Classify as anomaly if reconstruction error > threshold
        predictions = (mse > self.threshold).astype(int)
        return predictions
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly probabilities"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        X_scaled = self.scaler.transform(X)
        reconstructions = self.model.predict(X_scaled, verbose=0)
        
        # Calculate reconstruction error
        mse = np.mean(np.square(X_scaled - reconstructions), axis=1)
        
        # Convert MSE to probabilities (higher MSE = higher anomaly probability)
        # Normalize MSE to [0, 1] range
        max_mse = np.max(mse)
        min_mse = np.min(mse)
        if max_mse > min_mse:
            normalized_mse = (mse - min_mse) / (max_mse - min_mse)
        else:
            normalized_mse = np.zeros_like(mse)
        
        # Create probability matrix [normal_prob, anomaly_prob]
        prob_matrix = np.column_stack([1 - normalized_mse, normalized_mse])
        return prob_matrix
    
    def get_reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        """Get reconstruction errors for input data"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        X_scaled = self.scaler.transform(X)
        reconstructions = self.model.predict(X_scaled, verbose=0)
        mse = np.mean(np.square(X_scaled - reconstructions), axis=1)
        return mse
    
    def get_encoded_features(self, X: np.ndarray) -> np.ndarray:
        """Get encoded features from the encoder"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        X_scaled = self.scaler.transform(X)
        encoded_features = self.encoder.predict(X_scaled, verbose=0)
        return encoded_features

class DeepLearningEnsemble:
    """Ensemble of deep learning models"""
    
    def __init__(self, models: List[BaseDLModel], weights: List[float] = None):
        self.models = models
        self.weights = weights or [1.0 / len(models)] * len(models)
        self.is_trained = False
        self.logger = Logger("DLEnsemble")
        
        if len(self.weights) != len(self.models):
            raise ValueError("Number of weights must match number of models")
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray = None, y_val: np.ndarray = None) -> Dict[str, Any]:
        """Train all models in the ensemble"""
        self.logger.info("Starting deep learning ensemble training...")
        
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
        self.logger.info("Deep learning ensemble training completed successfully")
        
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
            prob = model.predict_proba(X)
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

def create_dl_models() -> Dict[str, BaseDLModel]:
    """Create and return all deep learning models"""
    models = {
        'lstm': LSTMModel(),
        'autoencoder': AutoencoderModel()
    }
    return models

def train_all_dl_models(X_train: np.ndarray, y_train: np.ndarray, 
                       X_val: np.ndarray, y_val: np.ndarray) -> Dict[str, BaseDLModel]:
    """Train all deep learning models"""
    models = create_dl_models()
    logger = Logger("DLTraining")
    
    logger.info("Starting training of all deep learning models...")
    
    for name, model in models.items():
        try:
            logger.info(f"Training {name}...")
            model.train(X_train, y_train, X_val, y_val)
            logger.info(f"{name} training completed successfully")
        except Exception as e:
            logger.error(f"Error training {name}: {e}")
            raise
    
    logger.info("All deep learning models trained successfully")
    return models

if __name__ == "__main__":
    # Example usage
    from data.preprocess import CICIDS2017Preprocessor
    
    # Load and preprocess data
    preprocessor = CICIDS2017Preprocessor()
    processed_data = preprocessor.load_processed_data()
    
    if processed_data:
        # Train models
        models = train_all_dl_models(
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



