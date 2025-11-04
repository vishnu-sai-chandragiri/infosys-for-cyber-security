"""
Web Application for Cybersecurity Threat Detection System

This module implements a Flask-based web application with real-time dashboard,
chatbot interface, and threat monitoring capabilities.
"""

import os
import sys
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import warnings
warnings.filterwarnings('ignore')

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
import numpy as np
import pandas as pd

# Import our modules
from utils.helpers import Logger, PerformanceMonitor
from utils.database import get_database, initialize_database
from config.config import WEB_CONFIG, get_config
from chatbot.cybersecurity_chatbot import create_chatbot
from realtime.threat_detector import create_threat_detector
from models.ml_models import create_ml_models
from models.dl_models import create_dl_models

class WebApplication:
    """Main web application class"""
    
    def __init__(self):
        self.app = Flask(__name__, 
                        static_folder='static', 
                        template_folder='templates')
        self.app.config['SECRET_KEY'] = WEB_CONFIG['secret_key']
        
        # Initialize SocketIO for real-time updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self.cors = CORS(self.app)
        
        # Initialize components
        self.logger = Logger("WebApplication")
        self.performance_monitor = PerformanceMonitor()
        self.config = get_config()
        
        # Initialize database
        self.db = initialize_database()
        
        # Initialize AI components
        self.chatbot = None
        self.threat_detector = None
        self.models = {}
        
        # Real-time data
        self.realtime_data = {
            'threats': [],
            'alerts': [],
            'stats': {},
            'last_update': None
        }
        
        # WebSocket rooms
        self.active_rooms = set()
        
        self._initialize_components()
        self._setup_routes()
        self._setup_websocket_handlers()
    
    def _initialize_components(self):
        """Initialize AI components"""
        try:
            # Load models (in production, these would be loaded from saved files)
            self.logger.info("Loading AI models...")
            ml_models = create_ml_models()
            dl_models = create_dl_models()
            self.models = {**ml_models, **dl_models}
            
            # Initialize threat detector
            self.threat_detector = create_threat_detector(self.models)
            
            # Initialize chatbot
            self.chatbot = create_chatbot(self.threat_detector)
            
            self.logger.info("AI components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing AI components: {e}")
            self.logger.info("Running in demo mode without AI components")
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            """Main dashboard page"""
            return render_template('dashboard.html')
        
        @self.app.route('/chatbot')
        def chatbot_page():
            """Chatbot interface page"""
            return render_template('chatbot.html')
        
        @self.app.route('/threats')
        def threats_page():
            """Threat monitoring page"""
            return render_template('threats.html')
        
        @self.app.route('/models')
        def models_page():
            """Model performance page"""
            return render_template('models.html')
        
        @self.app.route('/login')
        def login():
            """Login page"""
            return render_template('login.html')
        
        @self.app.route('/signup')
        def signup():
            """Signup page"""
            return render_template('signup.html')
        
        @self.app.route('/logout')
        def logout():
            """Logout and redirect to login"""
            return redirect(url_for('login'))
        
        @self.app.route('/profile')
        def profile():
            """User profile page"""
            return render_template('profile.html')

        @self.app.route('/status')
        def status():
            """System status page"""
            return render_template('status.html')
        
        @self.app.route('/settings')
        def settings():
            """System settings page"""
            return render_template('settings.html')
        
        @self.app.route('/api/status')
        def api_status():
            """API endpoint for system status"""
            try:
                status = {
                    'system_status': 'active',
                    'timestamp': datetime.now().isoformat(),
                    'components': {
                        'threat_detector': self.threat_detector is not None,
                        'chatbot': self.chatbot is not None,
                        'models': len(self.models) > 0
                    },
                    'realtime_data': self.realtime_data
                }
                return jsonify(status)
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats')
        def api_threats():
            """API endpoint for current threats"""
            try:
                if self.threat_detector:
                    stats = self.threat_detector.get_detection_stats()
                    alerts = self.threat_detector.get_alerts(limit=50)
                else:
                    # Mock data for demo
                    stats = {
                        'total_packets': 1250,
                        'threats_detected': 3,
                        'false_positives': 1,
                        'is_running': True,
                        'last_detection': datetime.now().isoformat()
                    }
                    alerts = [
                        {
                            'alert_id': 'ALERT_001',
                            'threat_type': 'DDoS',
                            'severity': 'HIGH',
                            'timestamp': datetime.now().isoformat(),
                            'source_ip': '192.168.1.100',
                            'confidence': 0.95
                        },
                        {
                            'alert_id': 'ALERT_002',
                            'threat_type': 'PortScan',
                            'severity': 'MEDIUM',
                            'timestamp': (datetime.now() - timedelta(minutes=5)).isoformat(),
                            'source_ip': '10.0.0.50',
                            'confidence': 0.87
                        }
                    ]
                
                return jsonify({
                    'stats': stats,
                    'alerts': alerts,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/models/performance')
        def api_model_performance():
            """API endpoint for model performance"""
            try:
                if self.chatbot:
                    performance = self.chatbot.model_analyzer.get_model_performance()
                else:
                    # Mock data
                    performance = {
                        'overall_accuracy': 0.95,
                        'detection_rate': 0.92,
                        'false_positive_rate': 0.03,
                        'models': {
                            'Random Forest': {'accuracy': 0.94, 'precision': 0.93, 'recall': 0.91, 'f1_score': 0.92},
                            'XGBoost': {'accuracy': 0.96, 'precision': 0.95, 'recall': 0.94, 'f1_score': 0.94},
                            'LSTM': {'accuracy': 0.93, 'precision': 0.92, 'recall': 0.90, 'f1_score': 0.91},
                            'Autoencoder': {'accuracy': 0.89, 'precision': 0.88, 'recall': 0.87, 'f1_score': 0.87}
                        }
                    }
                
                return jsonify(performance)
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/chat', methods=['POST'])
        def api_chat():
            """API endpoint for chatbot interaction"""
            try:
                data = request.get_json()
                user_input = data.get('message', '')
                user_id = data.get('user_id', 'anonymous')
                
                if not user_input:
                    return jsonify({'error': 'No message provided'}), 400
                
                if self.chatbot:
                    response = self.chatbot.process_query(user_input, user_id)
                else:
                    # Mock response
                    response = {
                        'response': "I'm currently in demo mode. Please initialize the AI components for full functionality.",
                        'intent': 'demo',
                        'confidence': 0.0,
                        'timestamp': datetime.now().isoformat(),
                        'processing_time': 0.001
                    }
                
                return jsonify(response)
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/chat/history', methods=['GET'])
        def api_chat_history():
            """API endpoint to get chat history"""
            try:
                user_id = request.args.get('user_id', 'anonymous')
                limit = int(request.args.get('limit', 10))
                
                # Get chat history from database
                history = self.db.get_chat_history(user_id, limit)
                
                return jsonify({'history': history})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/chat/clear', methods=['POST'])
        def api_clear_chat():
            """API endpoint to clear chat history"""
            try:
                data = request.get_json()
                user_id = data.get('user_id', 'anonymous')
                
                # Clear chat history from database
                success = self.db.clear_chat_history(user_id)
                
                if success:
                    return jsonify({'message': 'Chat history cleared successfully'})
                else:
                    return jsonify({'error': 'Failed to clear chat history'}), 500
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/auth/login', methods=['POST'])
        def api_login():
            """API endpoint for user login"""
            try:
                data = request.get_json()
                email = data.get('email', '').lower()
                password = data.get('password', '')
                remember_me = data.get('rememberMe', False)
                
                if not email or not password:
                    return jsonify({'success': False, 'message': 'Email and password are required'}), 400
                
                # Authenticate user using database
                user_info = self.db.authenticate_user(email, password)
                
                if user_info:
                    # Generate a simple token (in production, use JWT)
                    import hashlib
                    import time
                    token_data = f"{email}:{time.time()}:{self.app.config['SECRET_KEY']}"
                    token = hashlib.sha256(token_data.encode()).hexdigest()
                    
                    # Store session
                    session['user_id'] = user_info['id']
                    session['user_info'] = user_info
                    session['token'] = token
                    
                    return jsonify({
                        'success': True,
                        'message': 'Login successful',
                        'token': token,
                        'user': user_info
                    })
                
                return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
                
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/auth/signup', methods=['POST'])
        def api_signup():
            """API endpoint for user registration"""
            try:
                data = request.get_json()
                
                # Validate required fields
                required_fields = ['firstName', 'lastName', 'email', 'password', 'role']
                for field in required_fields:
                    if not data.get(field):
                        return jsonify({'success': False, 'message': f'{field} is required'}), 400
                
                email = data.get('email', '').lower()
                password = data.get('password', '')
                
                # Basic email validation
                if '@' not in email or '.' not in email:
                    return jsonify({'success': False, 'message': 'Invalid email format'}), 400
                
                # Password strength validation
                if len(password) < 8:
                    return jsonify({'success': False, 'message': 'Password must be at least 8 characters long'}), 400
                
                # Create user in database
                user_info = {
                    'id': f"user_{int(time.time())}",
                    'email': email,
                    'password': password,
                    'firstName': data.get('firstName'),
                    'lastName': data.get('lastName'),
                    'role': data.get('role'),
                    'organization': data.get('organization', '')
                }
                
                success = self.db.create_user(user_info)
                
                if success:
                    return jsonify({
                        'success': True,
                        'message': 'Account created successfully. Please login.',
                        'user': {
                            'id': user_info['id'],
                            'email': user_info['email'],
                            'firstName': user_info['firstName'],
                            'lastName': user_info['lastName'],
                            'role': user_info['role'],
                            'organization': user_info['organization']
                        }
                    })
                else:
                    return jsonify({'success': False, 'message': 'Email already exists or registration failed'}), 400
                
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/auth/logout', methods=['POST'])
        def api_logout():
            """API endpoint for user logout"""
            try:
                # Clear session
                session.clear()
                
                return jsonify({'success': True, 'message': 'Logged out successfully'})
                
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)}), 500
        
        @self.app.route('/api/export/report', methods=['POST'])
        def api_export_report():
            """API endpoint to export security report"""
            try:
                data = request.get_json()
                report_type = data.get('type', 'threats')
                date_range = data.get('date_range', '7d')
                
                # Generate report data
                if report_type == 'threats':
                    threats = self.db.get_recent_threats(limit=1000)
                    alerts = self.db.get_active_alerts(limit=1000)
                    
                    report_data = {
                        'report_type': 'Threat Analysis Report',
                        'generated_at': datetime.now().isoformat(),
                        'date_range': date_range,
                        'summary': {
                            'total_threats': len(threats),
                            'active_alerts': len(alerts),
                            'threat_types': {}
                        },
                        'threats': threats,
                        'alerts': alerts
                    }
                    
                    # Count threat types
                    for threat in threats:
                        threat_type = threat['threat_type']
                        report_data['summary']['threat_types'][threat_type] = report_data['summary']['threat_types'].get(threat_type, 0) + 1
                
                elif report_type == 'performance':
                    metrics = self.db.get_model_metrics(hours=24*7)  # Last 7 days
                    report_data = {
                        'report_type': 'Performance Analysis Report',
                        'generated_at': datetime.now().isoformat(),
                        'date_range': date_range,
                        'metrics': metrics
                    }
                
                else:
                    return jsonify({'error': 'Invalid report type'}), 400
                
                return jsonify({
                    'success': True,
                    'message': 'Report generated successfully',
                    'data': report_data
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats/simulate', methods=['POST'])
        def api_simulate_threats():
            """API endpoint to simulate threats for testing"""
            try:
                data = request.get_json()
                num_packets = data.get('num_packets', 50)
                
                # Start threat simulation in background
                def run_simulation():
                    try:
                        from realtime.threat_detector import ThreatDetector
                        from models.ml_models import create_ml_models
                        from models.dl_models import create_dl_models
                        
                        # Create models (simplified for demo)
                        ml_models = create_ml_models()
                        dl_models = create_dl_models()
                        all_models = {**ml_models, **dl_models}
                        
                        detector = ThreatDetector(all_models)
                        detector.simulate_traffic(num_packets)
                        
                    except Exception as e:
                        print(f"Simulation error: {e}")
                
                # Run simulation in background thread
                import threading
                thread = threading.Thread(target=run_simulation)
                thread.daemon = True
                thread.start()
                
                return jsonify({
                    'success': True,
                    'message': f'Started simulating {num_packets} packets with threats',
                    'simulation_id': f"SIM_{int(time.time())}"
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/threats/recent', methods=['GET'])
        def api_get_recent_threats():
            """API endpoint to get recent threats"""
            try:
                limit = int(request.args.get('limit', 20))
                threats = self.db.get_recent_threats(limit=limit)
                
                return jsonify({
                    'success': True,
                    'threats': threats,
                    'total': len(threats)
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/realtime/start', methods=['POST'])
        def api_start_realtime():
            """API endpoint to start real-time detection"""
            try:
                # Start real-time threat feed
                if hasattr(self, 'threat_detector') and self.threat_detector:
                    self.threat_detector.start_realtime_feed()
                
                return jsonify({
                    'success': True,
                    'message': 'Real-time threat feed started successfully'
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/realtime/stop', methods=['POST'])
        def api_stop_realtime():
            """API endpoint to stop real-time detection"""
            try:
                # Stop real-time threat feed
                if hasattr(self, 'threat_detector') and self.threat_detector:
                    self.threat_detector.stop_realtime_feed()
                
                return jsonify({
                    'success': True,
                    'message': 'Real-time threat feed stopped successfully'
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/prediction/start', methods=['POST'])
        def api_start_prediction():
            """API endpoint to start real-time threat prediction"""
            try:
                # Start real-time threat prediction
                if hasattr(self, 'threat_predictor') and self.threat_predictor:
                    self.threat_predictor.start_prediction_service()
                
                return jsonify({
                    'success': True,
                    'message': 'Real-time threat prediction started successfully'
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/prediction/stop', methods=['POST'])
        def api_stop_prediction():
            """API endpoint to stop real-time threat prediction"""
            try:
                # Stop real-time threat prediction
                if hasattr(self, 'threat_predictor') and self.threat_predictor:
                    self.threat_predictor.stop_prediction_service()
                
                return jsonify({
                    'success': True,
                    'message': 'Real-time threat prediction stopped successfully'
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/prediction/status', methods=['GET'])
        def api_prediction_status():
            """API endpoint to get prediction service status"""
            try:
                if hasattr(self, 'threat_predictor') and self.threat_predictor:
                    status = self.threat_predictor.get_prediction_status()
                else:
                    status = {
                        'is_running': False,
                        'total_packets': 0,
                        'predictions_made': 0,
                        'threats_detected': 0,
                        'queue_size': 0,
                        'alert_queue_size': 0,
                        'last_prediction': None
                    }
                
                return jsonify({
                    'success': True,
                    'status': status
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/prediction/alerts', methods=['GET'])
        def api_get_prediction_alerts():
            """API endpoint to get recent prediction alerts"""
            try:
                limit = int(request.args.get('limit', 10))
                
                if hasattr(self, 'threat_predictor') and self.threat_predictor:
                    alerts = self.threat_predictor.get_recent_alerts(limit=limit)
                else:
                    alerts = []
                
                return jsonify({
                    'success': True,
                    'alerts': alerts,
                    'total': len(alerts)
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/realtime/status', methods=['GET'])
        def api_realtime_status():
            """API endpoint to get real-time detection status"""
            try:
                status = {
                    'detection_active': False,
                    'prediction_active': False,
                    'packets_processed': 0,
                    'threats_detected': 0,
                    'active_alerts': 0
                }
                
                # Get real-time detection status
                if hasattr(self, 'threat_detector') and self.threat_detector:
                    realtime_status = self.threat_detector.get_realtime_status()
                    status.update(realtime_status)
                
                # Get prediction status
                if hasattr(self, 'threat_predictor') and self.threat_predictor:
                    prediction_status = self.threat_predictor.get_prediction_status()
                    status['prediction_active'] = prediction_status.get('active', False)
                
                return jsonify({
                    'success': True,
                    'status': status
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/realtime/simulate', methods=['POST'])
        def api_simulate_traffic():
            """API endpoint to simulate network traffic"""
            try:
                data = request.get_json()
                num_packets = data.get('num_packets', 50)
                
                if self.threat_detector:
                    # Start simulation in background thread
                    def simulate():
                        self.threat_detector.simulate_traffic(num_packets)
                    
                    thread = threading.Thread(target=simulate)
                    thread.daemon = True
                    thread.start()
                    
                    return jsonify({'status': 'started', 'message': f'Simulating {num_packets} packets'})
                else:
                    return jsonify({'error': 'Threat detector not available'}), 400
            except Exception as e:
                return jsonify({'error': str(e)}), 500
    
    def _setup_websocket_handlers(self):
        """Setup WebSocket event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            self.logger.info(f"Client connected: {request.sid}")
            emit('status', {'message': 'Connected to cybersecurity system'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            self.logger.info(f"Client disconnected: {request.sid}")
        
        @self.socketio.on('join_room')
        def handle_join_room(data):
            """Handle joining a room"""
            room = data.get('room', 'default')
            join_room(room)
            self.active_rooms.add(room)
            emit('status', {'message': f'Joined room: {room}'})
        
        @self.socketio.on('leave_room')
        def handle_leave_room(data):
            """Handle leaving a room"""
            room = data.get('room', 'default')
            leave_room(room)
            if room in self.active_rooms:
                self.active_rooms.remove(room)
            emit('status', {'message': f'Left room: {room}'})
        
        @self.socketio.on('chat_message')
        def handle_chat_message(data):
            """Handle chat messages via WebSocket"""
            try:
                message = data.get('message', '')
                user_id = data.get('user_id', 'anonymous')
                
                if self.chatbot:
                    response = self.chatbot.process_query(message, user_id)
                else:
                    response = {
                        'response': "Demo mode: AI chatbot not available",
                        'intent': 'demo',
                        'confidence': 0.0,
                        'timestamp': datetime.now().isoformat()
                    }
                
                emit('chat_response', response)
            except Exception as e:
                emit('error', {'message': str(e)})
        
        @self.socketio.on('request_threats')
        def handle_request_threats():
            """Handle real-time threat data requests"""
            try:
                if self.threat_detector:
                    stats = self.threat_detector.get_detection_stats()
                    alerts = self.threat_detector.get_alerts(limit=10)
                else:
                    # Mock data
                    stats = {
                        'total_packets': 1250,
                        'threats_detected': 3,
                        'is_running': True
                    }
                    alerts = []
                
                emit('threats_update', {
                    'stats': stats,
                    'alerts': alerts,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                emit('error', {'message': str(e)})
    
    def _update_realtime_data(self):
        """Update real-time data and broadcast to clients"""
        try:
            if self.threat_detector:
                stats = self.threat_detector.get_detection_stats()
                alerts = self.threat_detector.get_alerts(limit=20)
            else:
                # Mock data for demo
                stats = {
                    'total_packets': np.random.randint(1000, 2000),
                    'threats_detected': np.random.randint(0, 5),
                    'is_running': True,
                    'last_detection': datetime.now().isoformat()
                }
                alerts = []
            
            self.realtime_data = {
                'threats': alerts,
                'stats': stats,
                'last_update': datetime.now().isoformat()
            }
            
            # Broadcast to all active rooms
            for room in self.active_rooms:
                self.socketio.emit('realtime_update', self.realtime_data, room=room)
            
        except Exception as e:
            self.logger.error(f"Error updating real-time data: {e}")
    
    def start_realtime_updates(self):
        """Start real-time data updates"""
        def update_loop():
            while True:
                self._update_realtime_data()
                time.sleep(5)  # Update every 5 seconds
        
        update_thread = threading.Thread(target=update_loop)
        update_thread.daemon = True
        update_thread.start()
        self.logger.info("Real-time updates started")
    
    def run(self, debug=False, host=None, port=None):
        """Run the web application"""
        host = host or WEB_CONFIG['host']
        port = port or WEB_CONFIG['port']
        debug = debug or WEB_CONFIG['debug']
        
        self.logger.info(f"Starting web application on {host}:{port}")
        
        # Start real-time updates
        self.start_realtime_updates()
        
        # Run the application
        self.socketio.run(self.app, host=host, port=port, debug=debug)

def create_web_app() -> WebApplication:
    """Create and return web application instance"""
    return WebApplication()

if __name__ == "__main__":
    # Create and run web application
    web_app = create_web_app()
    web_app.run(debug=True)



