"""
Configuration settings for the cybersecurity threat detection system
"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
REALTIME_DIR = BASE_DIR / "realtime"
CHATBOT_DIR = BASE_DIR / "chatbot"
WEB_DIR = BASE_DIR / "web"
UTILS_DIR = BASE_DIR / "utils"

# Data configuration
DATA_CONFIG = {
    'raw_data_path': DATA_DIR / "raw",
    'processed_data_path': DATA_DIR / "processed",
    'dataset_filename': 'CICIDS2017.csv',
    'processed_filename': 'processed_data.pkl',
    'feature_selection_k': 50,
    'test_size': 0.2,
    'val_size': 0.2,
    'random_state': 42
}

# Model configuration
MODEL_CONFIG = {
    'models_dir': MODELS_DIR,
    'saved_models_dir': MODELS_DIR / "saved",
    'model_metrics_dir': MODELS_DIR / "metrics",
    'ensemble_model_name': 'ensemble_model.pkl',
    'individual_models': {
        'random_forest': 'rf_model.pkl',
        'xgboost': 'xgb_model.pkl',
        'isolation_forest': 'if_model.pkl',
        'lstm': 'lstm_model.h5',
        'autoencoder': 'autoencoder_model.h5'
    }
}

# ML Model hyperparameters
ML_MODEL_PARAMS = {
    'random_forest': {
        'n_estimators': 100,
        'max_depth': 20,
        'min_samples_split': 5,
        'min_samples_leaf': 2,
        'random_state': 42,
        'n_jobs': -1
    },
    'xgboost': {
        'n_estimators': 100,
        'max_depth': 6,
        'learning_rate': 0.1,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'random_state': 42,
        'n_jobs': -1
    },
    'isolation_forest': {
        'n_estimators': 100,
        'contamination': 0.1,
        'random_state': 42,
        'n_jobs': -1
    }
}

# Deep Learning model configuration
DL_MODEL_CONFIG = {
    'lstm': {
        'sequence_length': 10,
        'lstm_units': [64, 32],
        'dropout_rate': 0.2,
        'epochs': 50,
        'batch_size': 32,
        'validation_split': 0.2
    },
    'autoencoder': {
        'encoding_dim': 32,
        'hidden_layers': [64, 32],
        'epochs': 100,
        'batch_size': 32,
        'validation_split': 0.2,
        'reconstruction_threshold': 0.1
    }
}

# Real-time detection configuration
REALTIME_CONFIG = {
    'kafka_bootstrap_servers': ['localhost:9092'],
    'kafka_topic': 'network_traffic',
    'redis_host': 'localhost',
    'redis_port': 6379,
    'redis_db': 0,
    'detection_interval': 1.0,  # seconds
    'alert_threshold': 0.8,
    'max_queue_size': 1000
}

# Chatbot configuration
CHATBOT_CONFIG = {
    'model_name': 'microsoft/DialoGPT-medium',
    'max_length': 512,
    'temperature': 0.7,
    'top_p': 0.9,
    'response_timeout': 30,
    'context_window': 5,
    'intent_threshold': 0.7
}

# Web application configuration
WEB_CONFIG = {
    'host': '0.0.0.0',
    'port': 5000,
    'debug': False,
    'secret_key': 'cybersecurity_ai_system_secret_key_2023',
    'static_folder': WEB_DIR / 'static',
    'template_folder': WEB_DIR / 'templates'
}

# Database configuration
DATABASE_CONFIG = {
    'sqlite_path': BASE_DIR / 'cybersecurity_system.db',
    'threats_table': 'threats',
    'alerts_table': 'alerts',
    'chat_logs_table': 'chat_logs',
    'model_metrics_table': 'model_metrics'
}

# Security configuration
SECURITY_CONFIG = {
    'jwt_secret': 'cybersecurity_jwt_secret_2023',
    'jwt_expiration': 3600,  # 1 hour
    'password_min_length': 8,
    'max_login_attempts': 5,
    'lockout_duration': 300,  # 5 minutes
    'encryption_key': b'cybersecurity_encryption_key_2023_32bytes'
}

# Logging configuration
LOGGING_CONFIG = {
    'log_level': 'INFO',
    'log_file': BASE_DIR / 'logs' / 'cybersecurity_system.log',
    'max_log_size': 10 * 1024 * 1024,  # 10MB
    'backup_count': 5,
    'log_format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
}

# Performance monitoring
PERFORMANCE_CONFIG = {
    'metrics_interval': 60,  # seconds
    'model_retrain_interval': 24 * 3600,  # 24 hours
    'data_retention_days': 30,
    'max_concurrent_requests': 100,
    'request_timeout': 30
}

# Attack type mappings (from CICIDS2017)
ATTACK_TYPES = {
    0: 'BENIGN',
    1: 'DDoS',
    2: 'PortScan',
    3: 'Bot',
    4: 'Infiltration',
    5: 'Web Attack - Brute Force',
    6: 'Web Attack - XSS',
    7: 'Web Attack - Sql Injection',
    8: 'FTP-Patator',
    9: 'SSH-Patator',
    10: 'DoS Hulk',
    11: 'DoS GoldenEye',
    12: 'DoS slowloris',
    13: 'DoS Slowhttptest',
    14: 'Heartbleed'
}

# Threat severity levels
THREAT_SEVERITY = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4
}

# Alert types
ALERT_TYPES = {
    'THREAT_DETECTED': 'threat_detected',
    'MODEL_ANOMALY': 'model_anomaly',
    'SYSTEM_ERROR': 'system_error',
    'PERFORMANCE_ISSUE': 'performance_issue'
}

def get_config():
    """Get complete configuration dictionary"""
    return {
        'data': DATA_CONFIG,
        'models': MODEL_CONFIG,
        'ml_params': ML_MODEL_PARAMS,
        'dl_config': DL_MODEL_CONFIG,
        'realtime': REALTIME_CONFIG,
        'chatbot': CHATBOT_CONFIG,
        'web': WEB_CONFIG,
        'database': DATABASE_CONFIG,
        'security': SECURITY_CONFIG,
        'logging': LOGGING_CONFIG,
        'performance': PERFORMANCE_CONFIG,
        'attack_types': ATTACK_TYPES,
        'threat_severity': THREAT_SEVERITY,
        'alert_types': ALERT_TYPES
    }

def create_directories():
    """Create necessary directories"""
    directories = [
        DATA_DIR / "raw",
        DATA_DIR / "processed",
        MODELS_DIR / "saved",
        MODELS_DIR / "metrics",
        BASE_DIR / "logs",
        WEB_DIR / "static",
        WEB_DIR / "templates"
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    
    print("All necessary directories created successfully")

if __name__ == "__main__":
    create_directories()
    print("Configuration loaded successfully")



