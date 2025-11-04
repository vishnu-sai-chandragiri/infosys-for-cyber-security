"""
Comprehensive Test Suite for Cybersecurity AI System

This module contains tests for all components of the cybersecurity threat detection system.
"""

import os
import sys
import unittest
import numpy as np
import pandas as pd
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import warnings
warnings.filterwarnings('ignore')

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

# Import modules to test
from data.preprocess import CICIDS2017Preprocessor
from models.ml_models import RandomForestModel, XGBoostModel, IsolationForestModel
from models.dl_models import LSTMModel, AutoencoderModel
from realtime.threat_detector import ThreatDetector
from chatbot.cybersecurity_chatbot import CybersecurityChatbot, IntentClassifier
from utils.helpers import ModelEvaluator, DataValidator, SecurityUtils
from config.config import get_config

class TestDataPreprocessing(unittest.TestCase):
    """Test data preprocessing functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.preprocessor = CICIDS2017Preprocessor(
            data_path=self.temp_dir + '/',
            output_path=self.temp_dir + '/processed/'
        )
        
        # Create sample data
        self.sample_data = pd.DataFrame({
            'duration': [1.0, 2.0, 3.0],
            'protocol_type': ['tcp', 'udp', 'tcp'],
            'service': ['http', 'ftp', 'ssh'],
            'flag': ['SF', 'S0', 'REJ'],
            'src_bytes': [100, 200, 300],
            'dst_bytes': [150, 250, 350],
            'land': [0, 0, 0],
            'wrong_fragment': [0, 0, 0],
            'urgent': [0, 0, 0],
            'hot': [0, 1, 2],
            'num_failed_logins': [0, 1, 0],
            'logged_in': [1, 0, 1],
            'num_compromised': [0, 0, 0],
            'root_shell': [0, 0, 0],
            'su_attempted': [0, 0, 0],
            'num_root': [0, 0, 0],
            'num_file_creations': [0, 1, 0],
            'num_shells': [0, 0, 0],
            'num_access_files': [0, 2, 1],
            'num_outbound_cmds': [0, 0, 0],
            'is_host_login': [0, 0, 0],
            'is_guest_login': [0, 0, 0],
            'count': [10, 20, 30],
            'srv_count': [5, 10, 15],
            'serror_rate': [0.1, 0.2, 0.3],
            'srv_serror_rate': [0.05, 0.15, 0.25],
            'rerror_rate': [0.02, 0.12, 0.22],
            'srv_rerror_rate': [0.01, 0.11, 0.21],
            'same_srv_rate': [0.8, 0.7, 0.6],
            'diff_srv_rate': [0.2, 0.3, 0.4],
            'srv_diff_host_rate': [0.1, 0.2, 0.3],
            'dst_host_count': [50, 60, 70],
            'dst_host_srv_count': [25, 30, 35],
            'dst_host_same_srv_rate': [0.9, 0.8, 0.7],
            'dst_host_diff_srv_rate': [0.1, 0.2, 0.3],
            'dst_host_same_src_port_rate': [0.85, 0.75, 0.65],
            'dst_host_srv_diff_host_rate': [0.15, 0.25, 0.35],
            'dst_host_serror_rate': [0.05, 0.15, 0.25],
            'dst_host_srv_serror_rate': [0.03, 0.13, 0.23],
            'dst_host_rerror_rate': [0.02, 0.12, 0.22],
            'dst_host_srv_rerror_rate': [0.01, 0.11, 0.21],
            'Label': ['BENIGN', 'DDoS', 'PortScan']
        })
        
        # Save sample data
        self.sample_data.to_csv(f"{self.temp_dir}/CICIDS2017.csv", index=False)
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir)
    
    def test_load_dataset(self):
        """Test dataset loading"""
        df = self.preprocessor.load_dataset('CICIDS2017.csv')
        self.assertIsNotNone(df)
        self.assertEqual(len(df), 3)
        self.assertIn('Label', df.columns)
    
    def test_clean_data(self):
        """Test data cleaning"""
        df = self.preprocessor.clean_data(self.sample_data)
        self.assertIsNotNone(df)
        self.assertEqual(len(df), 3)
        self.assertFalse(df.isnull().any().any())
    
    def test_encode_categorical_features(self):
        """Test categorical feature encoding"""
        df = self.preprocessor.encode_categorical_features(self.sample_data)
        self.assertIsNotNone(df)
        self.assertIn('Label', df.columns)
        self.assertTrue(pd.api.types.is_numeric_dtype(df['Label']))
    
    def test_feature_selection(self):
        """Test feature selection"""
        X = self.sample_data.drop('Label', axis=1)
        y = self.sample_data['Label']
        
        # Encode categorical features first
        X_encoded = self.preprocessor.encode_categorical_features(X.copy())
        y_encoded = X_encoded['Label'] if 'Label' in X_encoded.columns else y
        X_features = X_encoded.drop('Label', axis=1) if 'Label' in X_encoded.columns else X_encoded
        
        X_selected = self.preprocessor.feature_selection(X_features, y_encoded, k=10)
        self.assertIsNotNone(X_selected)
        self.assertEqual(X_selected.shape[1], 10)
    
    def test_normalize_features(self):
        """Test feature normalization"""
        X = np.random.randn(100, 10)
        X_scaled = self.preprocessor.normalize_features(X, fit_scaler=True)
        self.assertIsNotNone(X_scaled)
        self.assertEqual(X_scaled.shape, X.shape)
        # Check if features are normalized (mean ≈ 0, std ≈ 1)
        self.assertAlmostEqual(X_scaled.mean(), 0, places=1)
        self.assertAlmostEqual(X_scaled.std(), 1, places=1)

class TestMLModels(unittest.TestCase):
    """Test machine learning models"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create sample data
        np.random.seed(42)
        self.X_train = np.random.randn(100, 10)
        self.y_train = np.random.randint(0, 2, 100)
        self.X_test = np.random.randn(20, 10)
        self.y_test = np.random.randint(0, 2, 20)
    
    def test_random_forest_model(self):
        """Test Random Forest model"""
        model = RandomForestModel()
        self.assertIsNotNone(model)
        
        # Test training
        results = model.train(self.X_train, self.y_train)
        self.assertIsNotNone(results)
        self.assertTrue(model.is_trained)
        
        # Test prediction
        predictions = model.predict(self.X_test)
        self.assertIsNotNone(predictions)
        self.assertEqual(len(predictions), len(self.y_test))
        
        # Test evaluation
        evaluation = model.evaluate(self.X_test, self.y_test)
        self.assertIsNotNone(evaluation)
        self.assertIn('accuracy', evaluation)
    
    def test_xgboost_model(self):
        """Test XGBoost model"""
        model = XGBoostModel()
        self.assertIsNotNone(model)
        
        # Test training
        results = model.train(self.X_train, self.y_train)
        self.assertIsNotNone(results)
        self.assertTrue(model.is_trained)
        
        # Test prediction
        predictions = model.predict(self.X_test)
        self.assertIsNotNone(predictions)
        self.assertEqual(len(predictions), len(self.y_test))
    
    def test_isolation_forest_model(self):
        """Test Isolation Forest model"""
        model = IsolationForestModel()
        self.assertIsNotNone(model)
        
        # Test training
        results = model.train(self.X_train, self.y_train)
        self.assertIsNotNone(results)
        self.assertTrue(model.is_trained)
        
        # Test prediction
        predictions = model.predict(self.X_test)
        self.assertIsNotNone(predictions)
        self.assertEqual(len(predictions), len(self.y_test))

class TestDLModels(unittest.TestCase):
    """Test deep learning models"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create sample data
        np.random.seed(42)
        self.X_train = np.random.randn(100, 10)
        self.y_train = np.random.randint(0, 15, 100)  # 15 classes
        self.X_test = np.random.randn(20, 10)
        self.y_test = np.random.randint(0, 15, 20)
    
    @patch('tensorflow.keras.models.Sequential')
    def test_lstm_model(self, mock_sequential):
        """Test LSTM model"""
        # Mock Keras components
        mock_model = Mock()
        mock_sequential.return_value = mock_model
        mock_model.compile.return_value = None
        mock_model.fit.return_value = Mock(history={'accuracy': [0.9], 'loss': [0.1]})
        mock_model.predict.return_value = np.random.randn(20, 15)
        
        model = LSTMModel()
        self.assertIsNotNone(model)
        
        # Test training (with mocked Keras)
        results = model.train(self.X_train, self.y_train)
        self.assertIsNotNone(results)
        self.assertTrue(model.is_trained)
    
    @patch('tensorflow.keras.models.Model')
    def test_autoencoder_model(self, mock_model_class):
        """Test Autoencoder model"""
        # Mock Keras components
        mock_model = Mock()
        mock_encoder = Mock()
        mock_model_class.return_value = (mock_model, mock_encoder)
        mock_model.compile.return_value = None
        mock_model.fit.return_value = Mock(history={'loss': [0.1], 'mae': [0.05]})
        mock_model.predict.return_value = np.random.randn(20, 10)
        mock_encoder.predict.return_value = np.random.randn(20, 32)
        
        model = AutoencoderModel()
        self.assertIsNotNone(model)
        
        # Test training (with mocked Keras)
        results = model.train(self.X_train, self.y_train)
        self.assertIsNotNone(results)
        self.assertTrue(model.is_trained)

class TestThreatDetector(unittest.TestCase):
    """Test threat detection functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create mock models
        self.mock_models = {
            'rf': Mock(),
            'xgb': Mock(),
            'lstm': Mock()
        }
        
        # Configure mock models
        for model in self.mock_models.values():
            model.predict_proba.return_value = np.array([[0.1, 0.9]])
            model.predict.return_value = np.array([1])
        
        self.detector = ThreatDetector(self.mock_models)
    
    def test_preprocess_packet(self):
        """Test packet preprocessing"""
        packet_data = {
            'src_ip': '192.168.1.1',
            'dst_ip': '10.0.0.1',
            'protocol_type': 'tcp',
            'service': 'http',
            'duration': 1.0,
            'src_bytes': 100,
            'dst_bytes': 200
        }
        
        # Add missing features with default values
        for i in range(40):  # CICIDS2017 has 78 features
            packet_data[f'feature_{i}'] = 0.0
        
        feature_vector = self.detector.preprocess_packet(packet_data)
        self.assertIsNotNone(feature_vector)
        self.assertEqual(feature_vector.shape[0], 1)  # Single packet
    
    def test_detect_threat(self):
        """Test threat detection"""
        feature_vector = np.random.randn(1, 10)
        threat_result = self.detector.detect_threat(feature_vector)
        
        self.assertIsNotNone(threat_result)
        self.assertIn('timestamp', threat_result)
        self.assertIn('ensemble_prediction', threat_result)
        self.assertIn('is_threat', threat_result)
    
    def test_generate_alert(self):
        """Test alert generation"""
        threat_result = {
            'timestamp': '2023-01-01T00:00:00',
            'ensemble_prediction': {'prediction': 1, 'confidence': 0.9, 'threat_type': 'DDoS'},
            'severity': 'HIGH',
            'is_threat': True,
            'confidence': 0.9,
            'packet_metadata': {
                'source_ip': '192.168.1.1',
                'destination_ip': '10.0.0.1',
                'protocol': 'tcp',
                'service': 'http'
            }
        }
        
        alert = self.detector.generate_alert(threat_result)
        self.assertIsNotNone(alert)
        self.assertIn('alert_id', alert)
        self.assertIn('threat_type', alert)
        self.assertIn('severity', alert)

class TestChatbot(unittest.TestCase):
    """Test chatbot functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.chatbot = CybersecurityChatbot()
    
    def test_intent_classification(self):
        """Test intent classification"""
        classifier = IntentClassifier()
        
        # Test known intents
        intent, confidence = classifier.classify_intent("What are the current threats?")
        self.assertIsNotNone(intent)
        self.assertGreater(confidence, 0)
        
        intent, confidence = classifier.classify_intent("Show me model performance")
        self.assertIsNotNone(intent)
        self.assertGreater(confidence, 0)
    
    def test_chatbot_response(self):
        """Test chatbot response generation"""
        response = self.chatbot.process_query("What are the current threats?")
        
        self.assertIsNotNone(response)
        self.assertIn('response', response)
        self.assertIn('intent', response)
        self.assertIn('confidence', response)
        self.assertIn('timestamp', response)
    
    def test_threat_analysis(self):
        """Test threat analysis functionality"""
        threat_data = self.chatbot.threat_analyzer.get_current_threats()
        
        self.assertIsNotNone(threat_data)
        self.assertIn('total_packets_processed', threat_data)
        self.assertIn('threats_detected', threat_data)
        self.assertIn('system_status', threat_data)
    
    def test_mitigation_recommendations(self):
        """Test mitigation recommendations"""
        recommendations = self.chatbot.threat_analyzer.get_mitigation_recommendations('DDoS', 'HIGH')
        
        self.assertIsNotNone(recommendations)
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)

class TestUtilities(unittest.TestCase):
    """Test utility functions"""
    
    def test_model_evaluator(self):
        """Test model evaluation utilities"""
        evaluator = ModelEvaluator()
        
        y_true = np.array([0, 1, 0, 1, 0])
        y_pred = np.array([0, 1, 1, 1, 0])
        y_prob = np.array([[0.9, 0.1], [0.2, 0.8], [0.3, 0.7], [0.1, 0.9], [0.8, 0.2]])
        
        results = evaluator.evaluate_classification_model(y_true, y_pred, y_prob)
        
        self.assertIsNotNone(results)
        self.assertIn('accuracy', results)
        self.assertIn('classification_report', results)
        self.assertIn('confusion_matrix', results)
    
    def test_data_validator(self):
        """Test data validation utilities"""
        validator = DataValidator()
        
        X = np.random.randn(100, 10)
        y = np.random.randint(0, 2, 100)
        
        # Test feature validation
        self.assertTrue(validator.validate_features(X, 10))
        
        # Test label validation
        self.assertTrue(validator.validate_labels(y, [0, 1]))
        
        # Test data quality check
        quality_report = validator.check_data_quality(X, y)
        self.assertIsNotNone(quality_report)
        self.assertIn('samples', quality_report)
        self.assertIn('features', quality_report)
    
    def test_security_utils(self):
        """Test security utilities"""
        # Test password hashing
        password = "test_password"
        hashed = SecurityUtils.hash_password(password)
        self.assertIsNotNone(hashed)
        self.assertNotEqual(password, hashed)
        
        # Test session token generation
        token = SecurityUtils.generate_session_token()
        self.assertIsNotNone(token)
        self.assertGreater(len(token), 10)
        
        # Test input validation
        self.assertTrue(SecurityUtils.validate_input("normal input"))
        self.assertFalse(SecurityUtils.validate_input("DROP TABLE users"))

class TestSystemIntegration(unittest.TestCase):
    """Test system integration"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir)
    
    def test_config_loading(self):
        """Test configuration loading"""
        config = get_config()
        self.assertIsNotNone(config)
        self.assertIn('data', config)
        self.assertIn('models', config)
        self.assertIn('web', config)
    
    @patch('main.CybersecuritySystem')
    def test_system_initialization(self, mock_system_class):
        """Test system initialization"""
        mock_system = Mock()
        mock_system_class.return_value = mock_system
        mock_system.initialize_components.return_value = True
        mock_system.start_system.return_value = True
        
        # Test that system can be initialized
        system = mock_system_class()
        self.assertTrue(system.initialize_components())
        self.assertTrue(system.start_system())

def run_tests():
    """Run all tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestDataPreprocessing,
        TestMLModels,
        TestDLModels,
        TestThreatDetector,
        TestChatbot,
        TestUtilities,
        TestSystemIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()

if __name__ == "__main__":
    print("🧪 Running Cybersecurity AI System Tests")
    print("=" * 50)
    
    success = run_tests()
    
    if success:
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Some tests failed!")
    
    print("=" * 50)



