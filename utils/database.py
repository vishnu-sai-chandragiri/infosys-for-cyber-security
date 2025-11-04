"""
Database utilities for the cybersecurity threat detection system

This module provides database connection and management functionality
for storing threat data, chat history, user information, and system metrics.
"""

import sqlite3
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import logging

from config.config import DATABASE_CONFIG, get_config

class DatabaseManager:
    """Manages database connections and operations"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.config = get_config()
        self.db_path = db_path or str(self.config['database']['sqlite_path'])
        self.logger = logging.getLogger(__name__)
        
        # Ensure database directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database tables if they don't exist"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create users table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        first_name TEXT NOT NULL,
                        last_name TEXT NOT NULL,
                        organization TEXT,
                        role TEXT NOT NULL,
                        is_active BOOLEAN DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create chat_history table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS chat_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id TEXT NOT NULL,
                        user_input TEXT NOT NULL,
                        bot_response TEXT NOT NULL,
                        intent TEXT,
                        confidence REAL,
                        processing_time REAL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
                
                # Create threats table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        threat_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        source_ip TEXT,
                        destination_ip TEXT,
                        confidence REAL,
                        description TEXT,
                        mitigation_actions TEXT,
                        status TEXT DEFAULT 'active',
                        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        resolved_at TIMESTAMP,
                        created_by TEXT,
                        FOREIGN KEY (created_by) REFERENCES users (id)
                    )
                ''')
                
                # Create alerts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_id TEXT UNIQUE NOT NULL,
                        threat_id INTEGER,
                        alert_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        message TEXT NOT NULL,
                        source_ip TEXT,
                        destination_ip TEXT,
                        confidence REAL,
                        status TEXT DEFAULT 'active',
                        acknowledged_by TEXT,
                        acknowledged_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        resolved_at TIMESTAMP,
                        FOREIGN KEY (threat_id) REFERENCES threats (id),
                        FOREIGN KEY (acknowledged_by) REFERENCES users (id)
                    )
                ''')
                
                # Create model_metrics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS model_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        model_name TEXT NOT NULL,
                        metric_type TEXT NOT NULL,
                        metric_value REAL NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        additional_data TEXT
                    )
                ''')
                
                # Create system_logs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS system_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        log_level TEXT NOT NULL,
                        component TEXT NOT NULL,
                        message TEXT NOT NULL,
                        additional_data TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_chat_history_user_id ON chat_history(user_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_chat_history_timestamp ON chat_history(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_model_metrics_timestamp ON model_metrics(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_logs_timestamp ON system_logs(timestamp)')
                
                conn.commit()
                self.logger.info("Database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise
    
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        return conn
    
    # User management methods
    def create_user(self, user_data: Dict[str, Any]) -> bool:
        """Create a new user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Hash password
                password_hash = hashlib.sha256(user_data['password'].encode()).hexdigest()
                
                cursor.execute('''
                    INSERT INTO users (id, email, password_hash, first_name, last_name, 
                                     organization, role, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_data['id'],
                    user_data['email'].lower(),
                    password_hash,
                    user_data['firstName'],
                    user_data['lastName'],
                    user_data.get('organization', ''),
                    user_data['role'],
                    1
                ))
                
                conn.commit()
                self.logger.info(f"User created: {user_data['email']}")
                return True
                
        except sqlite3.IntegrityError:
            self.logger.error(f"User already exists: {user_data['email']}")
            return False
        except Exception as e:
            self.logger.error(f"Error creating user: {e}")
            return False
    
    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user and return user data"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                
                cursor.execute('''
                    SELECT id, email, first_name, last_name, organization, role, is_active
                    FROM users 
                    WHERE email = ? AND password_hash = ? AND is_active = 1
                ''', (email.lower(), password_hash))
                
                user = cursor.fetchone()
                
                if user:
                    # Update last login
                    cursor.execute('''
                        UPDATE users SET last_login = CURRENT_TIMESTAMP 
                        WHERE id = ?
                    ''', (user['id'],))
                    conn.commit()
                    
                    return {
                        'id': user['id'],
                        'email': user['email'],
                        'firstName': user['first_name'],
                        'lastName': user['last_name'],
                        'organization': user['organization'],
                        'role': user['role']
                    }
                
                return None
                
        except Exception as e:
            self.logger.error(f"Error authenticating user: {e}")
            return None
    
    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, email, first_name, last_name, organization, role, 
                           is_active, created_at, last_login
                    FROM users WHERE id = ?
                ''', (user_id,))
                
                user = cursor.fetchone()
                if user:
                    return {
                        'id': user['id'],
                        'email': user['email'],
                        'firstName': user['first_name'],
                        'lastName': user['last_name'],
                        'organization': user['organization'],
                        'role': user['role'],
                        'isActive': bool(user['is_active']),
                        'createdAt': user['created_at'],
                        'lastLogin': user['last_login']
                    }
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting user: {e}")
            return None
    
    # Chat history methods
    def save_chat_message(self, user_id: str, user_input: str, bot_response: str, 
                         intent: str = None, confidence: float = None, 
                         processing_time: float = None) -> bool:
        """Save chat message to history"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO chat_history (user_id, user_input, bot_response, 
                                            intent, confidence, processing_time)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, user_input, bot_response, intent, confidence, processing_time))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error saving chat message: {e}")
            return False
    
    def get_chat_history(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get chat history for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT user_input, bot_response, intent, confidence, 
                           processing_time, timestamp
                    FROM chat_history 
                    WHERE user_id = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (user_id, limit))
                
                history = []
                for row in cursor.fetchall():
                    history.append({
                        'user_input': row['user_input'],
                        'bot_response': row['bot_response'],
                        'intent': row['intent'],
                        'confidence': row['confidence'],
                        'processing_time': row['processing_time'],
                        'timestamp': row['timestamp']
                    })
                
                return history[::-1]  # Reverse to get chronological order
                
        except Exception as e:
            self.logger.error(f"Error getting chat history: {e}")
            return []
    
    def clear_chat_history(self, user_id: str) -> bool:
        """Clear chat history for a user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM chat_history WHERE user_id = ?', (user_id,))
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error clearing chat history: {e}")
            return False
    
    # Threat management methods
    def save_threat(self, threat_data: Dict[str, Any]) -> int:
        """Save threat detection result"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO threats (threat_type, severity, source_ip, destination_ip,
                                       confidence, description, mitigation_actions, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    threat_data['threat_type'],
                    threat_data['severity'],
                    threat_data.get('source_ip'),
                    threat_data.get('destination_ip'),
                    threat_data.get('confidence'),
                    threat_data.get('description'),
                    json.dumps(threat_data.get('mitigation_actions', [])),
                    threat_data.get('created_by')
                ))
                
                threat_id = cursor.lastrowid
                conn.commit()
                return threat_id
                
        except Exception as e:
            self.logger.error(f"Error saving threat: {e}")
            return None
    
    def get_recent_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent threats"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, threat_type, severity, source_ip, destination_ip,
                           confidence, description, status, detected_at, resolved_at
                    FROM threats 
                    ORDER BY detected_at DESC 
                    LIMIT ?
                ''', (limit,))
                
                threats = []
                for row in cursor.fetchall():
                    threats.append({
                        'id': row['id'],
                        'threat_type': row['threat_type'],
                        'severity': row['severity'],
                        'source_ip': row['source_ip'],
                        'destination_ip': row['destination_ip'],
                        'confidence': row['confidence'],
                        'description': row['description'],
                        'status': row['status'],
                        'detected_at': row['detected_at'],
                        'resolved_at': row['resolved_at']
                    })
                
                return threats
                
        except Exception as e:
            self.logger.error(f"Error getting recent threats: {e}")
            return []
    
    # Alert management methods
    def save_alert(self, alert_data: Dict[str, Any]) -> int:
        """Save alert"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO alerts (alert_id, threat_id, alert_type, severity, message,
                                      source_ip, destination_ip, confidence, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert_data['alert_id'],
                    alert_data.get('threat_id'),
                    alert_data['alert_type'],
                    alert_data['severity'],
                    alert_data['message'],
                    alert_data.get('source_ip'),
                    alert_data.get('destination_ip'),
                    alert_data.get('confidence'),
                    alert_data.get('status', 'active')
                ))
                
                alert_id = cursor.lastrowid
                conn.commit()
                return alert_id
                
        except Exception as e:
            self.logger.error(f"Error saving alert: {e}")
            return None
    
    def get_active_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get active alerts"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT alert_id, threat_id, alert_type, severity, message,
                           source_ip, destination_ip, confidence, status, created_at
                    FROM alerts 
                    WHERE status = 'active'
                    ORDER BY created_at DESC 
                    LIMIT ?
                ''', (limit,))
                
                alerts = []
                for row in cursor.fetchall():
                    alerts.append({
                        'alert_id': row['alert_id'],
                        'threat_id': row['threat_id'],
                        'alert_type': row['alert_type'],
                        'severity': row['severity'],
                        'message': row['message'],
                        'source_ip': row['source_ip'],
                        'destination_ip': row['destination_ip'],
                        'confidence': row['confidence'],
                        'status': row['status'],
                        'created_at': row['created_at']
                    })
                
                return alerts
                
        except Exception as e:
            self.logger.error(f"Error getting active alerts: {e}")
            return []
    
    # Model metrics methods
    def save_model_metric(self, model_name: str, metric_type: str, 
                         metric_value: float, additional_data: Dict = None) -> bool:
        """Save model performance metric"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO model_metrics (model_name, metric_type, metric_value, additional_data)
                    VALUES (?, ?, ?, ?)
                ''', (model_name, metric_type, metric_value, 
                      json.dumps(additional_data) if additional_data else None))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error saving model metric: {e}")
            return False
    
    def get_model_metrics(self, model_name: str = None, 
                         metric_type: str = None, 
                         hours: int = 24) -> List[Dict[str, Any]]:
        """Get model metrics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                query = '''
                    SELECT model_name, metric_type, metric_value, additional_data, timestamp
                    FROM model_metrics 
                    WHERE timestamp >= datetime('now', '-{} hours')
                '''.format(hours)
                
                params = []
                if model_name:
                    query += ' AND model_name = ?'
                    params.append(model_name)
                
                if metric_type:
                    query += ' AND metric_type = ?'
                    params.append(metric_type)
                
                query += ' ORDER BY timestamp DESC'
                
                cursor.execute(query, params)
                
                metrics = []
                for row in cursor.fetchall():
                    metrics.append({
                        'model_name': row['model_name'],
                        'metric_type': row['metric_type'],
                        'metric_value': row['metric_value'],
                        'additional_data': json.loads(row['additional_data']) if row['additional_data'] else None,
                        'timestamp': row['timestamp']
                    })
                
                return metrics
                
        except Exception as e:
            self.logger.error(f"Error getting model metrics: {e}")
            return []
    
    # System logging methods
    def log_system_event(self, log_level: str, component: str, 
                        message: str, additional_data: Dict = None) -> bool:
        """Log system event"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO system_logs (log_level, component, message, additional_data)
                    VALUES (?, ?, ?, ?)
                ''', (log_level, component, message, 
                      json.dumps(additional_data) if additional_data else None))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error logging system event: {e}")
            return False
    
    def get_system_logs(self, log_level: str = None, component: str = None, 
                       hours: int = 24) -> List[Dict[str, Any]]:
        """Get system logs"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                query = '''
                    SELECT log_level, component, message, additional_data, timestamp
                    FROM system_logs 
                    WHERE timestamp >= datetime('now', '-{} hours')
                '''.format(hours)
                
                params = []
                if log_level:
                    query += ' AND log_level = ?'
                    params.append(log_level)
                
                if component:
                    query += ' AND component = ?'
                    params.append(component)
                
                query += ' ORDER BY timestamp DESC'
                
                cursor.execute(query, params)
                
                logs = []
                for row in cursor.fetchall():
                    logs.append({
                        'log_level': row['log_level'],
                        'component': row['component'],
                        'message': row['message'],
                        'additional_data': json.loads(row['additional_data']) if row['additional_data'] else None,
                        'timestamp': row['timestamp']
                    })
                
                return logs
                
        except Exception as e:
            self.logger.error(f"Error getting system logs: {e}")
            return []
    
    # Statistics methods
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Count records in each table
                tables = ['users', 'chat_history', 'threats', 'alerts', 'model_metrics', 'system_logs']
                for table in tables:
                    cursor.execute(f'SELECT COUNT(*) FROM {table}')
                    stats[f'{table}_count'] = cursor.fetchone()[0]
                
                # Get recent activity
                cursor.execute('''
                    SELECT COUNT(*) FROM chat_history 
                    WHERE timestamp >= datetime('now', '-24 hours')
                ''')
                stats['recent_chats'] = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT COUNT(*) FROM threats 
                    WHERE detected_at >= datetime('now', '-24 hours')
                ''')
                stats['recent_threats'] = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT COUNT(*) FROM alerts 
                    WHERE created_at >= datetime('now', '-24 hours')
                ''')
                stats['recent_alerts'] = cursor.fetchone()[0]
                
                return stats
                
        except Exception as e:
            self.logger.error(f"Error getting database stats: {e}")
            return {}
    
    def cleanup_old_data(self, days: int = 30) -> bool:
        """Clean up old data"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Clean up old chat history (keep last 30 days)
                cursor.execute('''
                    DELETE FROM chat_history 
                    WHERE timestamp < datetime('now', '-{} days')
                '''.format(days))
                
                # Clean up old system logs (keep last 7 days)
                cursor.execute('''
                    DELETE FROM system_logs 
                    WHERE timestamp < datetime('now', '-7 days')
                ''')
                
                # Clean up old model metrics (keep last 90 days)
                cursor.execute('''
                    DELETE FROM model_metrics 
                    WHERE timestamp < datetime('now', '-90 days')
                ''')
                
                conn.commit()
                self.logger.info(f"Cleaned up data older than {days} days")
                return True
                
        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}")
            return False

# Global database instance
db_manager = None

def get_database() -> DatabaseManager:
    """Get global database manager instance"""
    global db_manager
    if db_manager is None:
        db_manager = DatabaseManager()
    return db_manager

def initialize_database():
    """Initialize database with demo data"""
    db = get_database()
    
    # Create demo user if it doesn't exist
    demo_user = {
        'id': 'demo_user',
        'email': 'demo@cybersecurity.com',
        'password': 'demo123',
        'firstName': 'Demo',
        'lastName': 'User',
        'organization': 'Cybersecurity Demo',
        'role': 'security_analyst'
    }
    
    # Check if demo user exists
    existing_user = db.get_user_by_id('demo_user')
    if not existing_user:
        db.create_user(demo_user)
        print("Demo user created successfully")
    
    return db

if __name__ == "__main__":
    # Initialize database
    db = initialize_database()
    print("Database initialized successfully")
    
    # Print database stats
    stats = db.get_database_stats()
    print("Database Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

