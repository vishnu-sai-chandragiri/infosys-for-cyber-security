"""
Real-time Threat Detection Pipeline

This module implements a real-time threat detection system that processes
network traffic data and detects cybersecurity threats using trained ML/DL models.
"""

import numpy as np
import pandas as pd
import json
import time
import threading
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
import warnings
warnings.filterwarnings('ignore')

# Kafka and Redis for real-time processing
try:
    from kafka import KafkaConsumer, KafkaProducer
    from kafka.errors import KafkaError
    import redis
except ImportError:
    print("Warning: Kafka and Redis dependencies not installed. Real-time features will be limited.")
    KafkaConsumer = None
    KafkaProducer = None
    redis = None

from utils.helpers import Logger, PerformanceMonitor, format_threat_alert, calculate_threat_score
from config.config import REALTIME_CONFIG, ATTACK_TYPES, THREAT_SEVERITY, ALERT_TYPES

class ThreatDetector:
    """Main threat detection class"""
    
    def __init__(self, models: Dict[str, Any], feature_selector=None, scaler=None):
        self.models = models
        self.feature_selector = feature_selector
        self.scaler = scaler
        self.logger = Logger("ThreatDetector")
        self.performance_monitor = PerformanceMonitor()
        
        # Detection configuration
        self.alert_threshold = REALTIME_CONFIG['alert_threshold']
        self.detection_interval = REALTIME_CONFIG['detection_interval']
        self.max_queue_size = REALTIME_CONFIG['max_queue_size']
        
        # Data queues and buffers
        self.data_queue = queue.Queue(maxsize=self.max_queue_size)
        self.alert_queue = queue.Queue()
        self.detection_buffer = []
        
        # Statistics
        self.detection_stats = {
            'total_packets': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'processing_time': 0,
            'last_detection': None
        }
        
        # Real-time components
        self.kafka_consumer = None
        self.kafka_producer = None
        self.redis_client = None
        self.detection_thread = None
        self.is_running = False
        
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize Kafka and Redis components"""
        try:
            # Initialize Kafka consumer
            if KafkaConsumer:
                self.kafka_consumer = KafkaConsumer(
                    REALTIME_CONFIG['kafka_topic'],
                    bootstrap_servers=REALTIME_CONFIG['kafka_bootstrap_servers'],
                    value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                    auto_offset_reset='latest',
                    enable_auto_commit=True
                )
            
            # Initialize Kafka producer
            if KafkaProducer:
                self.kafka_producer = KafkaProducer(
                    bootstrap_servers=REALTIME_CONFIG['kafka_bootstrap_servers'],
                    value_serializer=lambda x: json.dumps(x).encode('utf-8')
                )
            
            # Initialize Redis client
            if redis:
                self.redis_client = redis.Redis(
                    host=REALTIME_CONFIG['redis_host'],
                    port=REALTIME_CONFIG['redis_port'],
                    db=REALTIME_CONFIG['redis_db'],
                    decode_responses=True
                )
            
            self.logger.info("Real-time components initialized successfully")
            
        except Exception as e:
            self.logger.warning(f"Could not initialize real-time components: {e}")
            self.logger.info("Running in simulation mode")
    
    def preprocess_packet(self, packet_data: Dict[str, Any]) -> np.ndarray:
        """Preprocess a single network packet for model input"""
        try:
            # Convert packet data to feature vector
            features = []
            
            # Extract numerical features
            numerical_features = [
                'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
                'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
                'num_failed_logins', 'logged_in', 'num_compromised',
                'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
                'num_shells', 'num_access_files', 'num_outbound_cmds',
                'is_host_login', 'is_guest_login', 'count', 'srv_count',
                'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
                'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
                'dst_host_srv_rerror_rate'
            ]
            
            for feature in numerical_features:
                if feature in packet_data:
                    features.append(float(packet_data[feature]))
                else:
                    features.append(0.0)  # Default value for missing features
            
            # Convert to numpy array and reshape
            feature_vector = np.array(features).reshape(1, -1)
            
            # Apply feature selection if available
            if self.feature_selector:
                feature_vector = self.feature_selector.transform(feature_vector)
            
            # Apply scaling if available
            if self.scaler:
                feature_vector = self.scaler.transform(feature_vector)
            
            return feature_vector
            
        except Exception as e:
            self.logger.error(f"Error preprocessing packet: {e}")
            return None
    
    def detect_threat(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """Detect threats using ensemble of models"""
        try:
            threat_results = {}
            
            # Get predictions from all models
            for model_name, model in self.models.items():
                try:
                    if hasattr(model, 'predict_proba'):
                        probabilities = model.predict_proba(feature_vector)
                        prediction = np.argmax(probabilities)
                        confidence = np.max(probabilities)
                    else:
                        prediction = model.predict(feature_vector)[0]
                        confidence = 0.5  # Default confidence
                    
                    threat_results[model_name] = {
                        'prediction': int(prediction),
                        'confidence': float(confidence),
                        'threat_type': ATTACK_TYPES.get(prediction, 'Unknown')
                    }
                    
                except Exception as e:
                    self.logger.error(f"Error with model {model_name}: {e}")
                    threat_results[model_name] = {
                        'prediction': 0,
                        'confidence': 0.0,
                        'threat_type': 'BENIGN'
                    }
            
            # Calculate ensemble prediction
            ensemble_prediction = self._calculate_ensemble_prediction(threat_results)
            
            # Determine threat severity
            severity = self._determine_threat_severity(ensemble_prediction)
            
            return {
                'timestamp': datetime.now().isoformat(),
                'ensemble_prediction': ensemble_prediction,
                'individual_predictions': threat_results,
                'severity': severity,
                'is_threat': ensemble_prediction['prediction'] != 0,
                'confidence': ensemble_prediction['confidence']
            }
            
        except Exception as e:
            self.logger.error(f"Error in threat detection: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'ensemble_prediction': {'prediction': 0, 'confidence': 0.0, 'threat_type': 'BENIGN'},
                'individual_predictions': {},
                'severity': 'LOW',
                'is_threat': False,
                'confidence': 0.0
            }
    
    def _calculate_ensemble_prediction(self, individual_predictions: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate ensemble prediction from individual model predictions"""
        predictions = []
        confidences = []
        
        for model_name, result in individual_predictions.items():
            predictions.append(result['prediction'])
            confidences.append(result['confidence'])
        
        # Weighted voting (equal weights for now)
        weights = [1.0 / len(predictions)] * len(predictions)
        
        # Calculate weighted prediction
        weighted_prediction = sum(pred * weight for pred, weight in zip(predictions, weights))
        final_prediction = int(round(weighted_prediction))
        
        # Calculate weighted confidence
        weighted_confidence = sum(conf * weight for conf, weight in zip(confidences, weights))
        
        return {
            'prediction': final_prediction,
            'confidence': weighted_confidence,
            'threat_type': ATTACK_TYPES.get(final_prediction, 'Unknown')
        }
    
    def _determine_threat_severity(self, prediction: Dict[str, Any]) -> str:
        """Determine threat severity based on prediction"""
        threat_type = prediction['threat_type']
        confidence = prediction['confidence']
        
        # High severity threats
        high_severity = ['DDoS', 'Infiltration', 'Web Attack - Sql Injection', 'Heartbleed']
        medium_severity = ['PortScan', 'Bot', 'Web Attack - Brute Force', 'Web Attack - XSS']
        
        if threat_type in high_severity and confidence > 0.8:
            return 'CRITICAL'
        elif threat_type in high_severity and confidence > 0.6:
            return 'HIGH'
        elif threat_type in medium_severity and confidence > 0.7:
            return 'MEDIUM'
        elif prediction['prediction'] != 0 and confidence > 0.5:
            return 'LOW'
        else:
            return 'LOW'
    
    def process_packet(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single network packet"""
        start_time = time.time()
        
        try:
            # Preprocess packet
            feature_vector = self.preprocess_packet(packet_data)
            if feature_vector is None:
                return None
            
            # Detect threats
            threat_result = self.detect_threat(feature_vector)
            
            # Update statistics
            self.detection_stats['total_packets'] += 1
            if threat_result['is_threat']:
                self.detection_stats['threats_detected'] += 1
            self.detection_stats['last_detection'] = datetime.now().isoformat()
            
            # Calculate processing time
            processing_time = time.time() - start_time
            self.detection_stats['processing_time'] = processing_time
            
            # Add packet metadata to result
            threat_result['packet_metadata'] = {
                'source_ip': packet_data.get('src_ip', 'Unknown'),
                'destination_ip': packet_data.get('dst_ip', 'Unknown'),
                'protocol': packet_data.get('protocol_type', 'Unknown'),
                'service': packet_data.get('service', 'Unknown'),
                'processing_time': processing_time
            }
            
            return threat_result
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
            return None
    
    def generate_alert(self, threat_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate alert for detected threat"""
        if not threat_result['is_threat'] or threat_result['confidence'] < self.alert_threshold:
            return None
        
        alert = {
            'alert_id': f"ALERT_{int(time.time())}_{threat_result['packet_metadata']['source_ip']}",
            'timestamp': threat_result['timestamp'],
            'alert_type': ALERT_TYPES['THREAT_DETECTED'],
            'threat_type': threat_result['ensemble_prediction']['threat_type'],
            'severity': threat_result['severity'],
            'confidence': threat_result['confidence'],
            'source_ip': threat_result['packet_metadata']['source_ip'],
            'destination_ip': threat_result['packet_metadata']['destination_ip'],
            'protocol': threat_result['packet_metadata']['protocol'],
            'service': threat_result['packet_metadata']['service'],
            'recommended_actions': self._get_recommended_actions(threat_result),
            'alert_message': format_threat_alert(threat_result)
        }
        
        return alert
    
    def _get_recommended_actions(self, threat_result: Dict[str, Any]) -> List[str]:
        """Get recommended actions based on threat type and severity"""
        threat_type = threat_result['ensemble_prediction']['threat_type']
        severity = threat_result['severity']
        
        actions = []
        
        if severity in ['HIGH', 'CRITICAL']:
            actions.extend([
                "Block source IP immediately",
                "Notify security team",
                "Initiate incident response"
            ])
        
        if threat_type == 'DDoS':
            actions.extend([
                "Enable DDoS protection",
                "Rate limit connections",
                "Monitor network bandwidth"
            ])
        elif threat_type == 'PortScan':
            actions.extend([
                "Block scanning IP",
                "Monitor for further scanning",
                "Check firewall rules"
            ])
        elif 'Web Attack' in threat_type:
            actions.extend([
                "Block malicious requests",
                "Review web application logs",
                "Update WAF rules"
            ])
        elif threat_type == 'Bot':
            actions.extend([
                "Block bot traffic",
                "Update bot detection rules",
                "Monitor for botnet activity"
            ])
        
        return actions
    
    def _detection_worker(self):
        """Worker thread for continuous threat detection"""
        self.logger.info("Threat detection worker started")
        
        while self.is_running:
            try:
                # Get packet from queue
                packet_data = self.data_queue.get(timeout=1.0)
                
                # Process packet
                threat_result = self.process_packet(packet_data)
                
                if threat_result:
                    # Generate alert if threat detected
                    alert = self.generate_alert(threat_result)
                    
                    if alert:
                        # Add to alert queue
                        self.alert_queue.put(alert)
                        
                        # Publish to Kafka if available
                        if self.kafka_producer:
                            try:
                                self.kafka_producer.send('threat_alerts', alert)
                            except Exception as e:
                                self.logger.error(f"Error publishing alert to Kafka: {e}")
                        
                        # Store in Redis if available
                        if self.redis_client:
                            try:
                                alert_key = f"alert:{alert['alert_id']}"
                                self.redis_client.setex(alert_key, 3600, json.dumps(alert))  # 1 hour TTL
                            except Exception as e:
                                self.logger.error(f"Error storing alert in Redis: {e}")
                        
                        self.logger.warning(f"🚨 THREAT DETECTED: {alert['threat_type']} - {alert['severity']}")
                
                self.data_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in detection worker: {e}")
                time.sleep(1)
    
    def start_detection(self):
        """Start real-time threat detection"""
        if self.is_running:
            self.logger.warning("Detection is already running")
            return
        
        self.is_running = True
        self.detection_thread = threading.Thread(target=self._detection_worker)
        self.detection_thread.daemon = True
        self.detection_thread.start()
        
        self.logger.info("Real-time threat detection started")
    
    def stop_detection(self):
        """Stop real-time threat detection"""
        if not self.is_running:
            self.logger.warning("Detection is not running")
            return
        
        self.is_running = False
        
        if self.detection_thread:
            self.detection_thread.join(timeout=5)
        
        self.logger.info("Real-time threat detection stopped")
    
    def add_packet(self, packet_data: Dict[str, Any]):
        """Add packet to detection queue"""
        try:
            self.data_queue.put_nowait(packet_data)
        except queue.Full:
            self.logger.warning("Detection queue is full, dropping packet")
    
    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        alerts = []
        
        try:
            while not self.alert_queue.empty() and len(alerts) < limit:
                alert = self.alert_queue.get_nowait()
                alerts.append(alert)
        except queue.Empty:
            pass
        
        return alerts
    
    def get_detection_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return {
            **self.detection_stats,
            'queue_size': self.data_queue.qsize(),
            'alert_queue_size': self.alert_queue.qsize(),
            'is_running': self.is_running
        }
    
    def simulate_traffic(self, num_packets: int = 100):
        """Simulate network traffic for testing"""
        self.logger.info(f"Simulating {num_packets} network packets...")
        
        # Generate random packet data
        for i in range(num_packets):
            packet_data = {
                'src_ip': f"192.168.1.{np.random.randint(1, 255)}",
                'dst_ip': f"10.0.0.{np.random.randint(1, 255)}",
                'protocol_type': np.random.choice(['tcp', 'udp', 'icmp']),
                'service': np.random.choice(['http', 'ftp', 'ssh', 'smtp', 'dns']),
                'duration': np.random.uniform(0, 100),
                'src_bytes': np.random.randint(0, 10000),
                'dst_bytes': np.random.randint(0, 10000),
                'flag': np.random.choice(['SF', 'S0', 'REJ', 'RSTR']),
                'land': 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': np.random.randint(0, 10),
                'num_failed_logins': np.random.randint(0, 5),
                'logged_in': np.random.randint(0, 2),
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': 0,
                'num_file_creations': np.random.randint(0, 5),
                'num_shells': 0,
                'num_access_files': np.random.randint(0, 10),
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': np.random.randint(1, 100),
                'srv_count': np.random.randint(1, 50),
                'serror_rate': np.random.uniform(0, 1),
                'srv_serror_rate': np.random.uniform(0, 1),
                'rerror_rate': np.random.uniform(0, 1),
                'srv_rerror_rate': np.random.uniform(0, 1),
                'same_srv_rate': np.random.uniform(0, 1),
                'diff_srv_rate': np.random.uniform(0, 1),
                'srv_diff_host_rate': np.random.uniform(0, 1),
                'dst_host_count': np.random.randint(1, 100),
                'dst_host_srv_count': np.random.randint(1, 50),
                'dst_host_same_srv_rate': np.random.uniform(0, 1),
                'dst_host_diff_srv_rate': np.random.uniform(0, 1),
                'dst_host_same_src_port_rate': np.random.uniform(0, 1),
                'dst_host_srv_diff_host_rate': np.random.uniform(0, 1),
                'dst_host_serror_rate': np.random.uniform(0, 1),
                'dst_host_srv_serror_rate': np.random.uniform(0, 1),
                'dst_host_rerror_rate': np.random.uniform(0, 1),
                'dst_host_srv_rerror_rate': np.random.uniform(0, 1)
            }
            
            self.add_packet(packet_data)
            
            # Simulate threats with higher probability
            if np.random.random() < 0.15:  # 15% chance of threat
                threat_type = np.random.choice(['DDoS', 'PortScan', 'Bot', 'Web Attack'])
                self._simulate_threat(packet_data, threat_type)
            
            time.sleep(0.05)  # Faster simulation
        
        self.logger.info("Traffic simulation completed")
    
    def _simulate_threat(self, packet_data: Dict, threat_type: str):
        """Simulate a specific type of threat"""
        threat_data = {
            'threat_type': threat_type,
            'source_ip': packet_data['src_ip'],
            'destination_ip': packet_data['dst_ip'],
            'confidence': np.random.uniform(0.7, 0.95),
            'timestamp': datetime.now().isoformat(),
            'severity': self._get_threat_severity(threat_type),
            'description': self._get_threat_description(threat_type),
            'mitigation_actions': self._get_mitigation_actions(threat_type)
        }
        
        # Save to database
        try:
            from utils.database import get_database
            db = get_database()
            threat_id = db.save_threat(threat_data)
            
            # Create alert
            alert_data = {
                'alert_id': f"ALERT_{int(time.time())}_{np.random.randint(1000, 9999)}",
                'threat_id': threat_id,
                'alert_type': 'THREAT_DETECTED',
                'severity': threat_data['severity'],
                'message': f"{threat_type} attack detected from {packet_data['src_ip']}",
                'source_ip': packet_data['src_ip'],
                'destination_ip': packet_data['dst_ip'],
                'confidence': threat_data['confidence']
            }
            
            db.save_alert(alert_data)
            
        except Exception as e:
            self.logger.error(f"Error saving simulated threat: {e}")
    
    def _get_threat_severity(self, threat_type: str) -> str:
        """Get severity level for threat type"""
        severity_map = {
            'DDoS': 'HIGH',
            'PortScan': 'MEDIUM', 
            'Bot': 'MEDIUM',
            'Web Attack': 'HIGH'
        }
        return severity_map.get(threat_type, 'LOW')
    
    def _get_threat_description(self, threat_type: str) -> str:
        """Get description for threat type"""
        descriptions = {
            'DDoS': 'Distributed Denial of Service attack detected',
            'PortScan': 'Port scanning activity detected',
            'Bot': 'Automated bot traffic detected',
            'Web Attack': 'Web application attack detected'
        }
        return descriptions.get(threat_type, 'Unknown threat detected')
    
    def _get_mitigation_actions(self, threat_type: str) -> List[str]:
        """Get mitigation actions for threat type"""
        actions = {
            'DDoS': ['Enable DDoS protection', 'Rate limiting', 'Traffic filtering'],
            'PortScan': ['Block scanning IP', 'Firewall rules', 'Intrusion detection'],
            'Bot': ['Bot detection', 'CAPTCHA', 'Rate limiting'],
            'Web Attack': ['WAF rules', 'Input validation', 'Security patches']
        }
        return actions.get(threat_type, ['Review logs', 'Contact security team'])
    
    def start_realtime_feed(self):
        """Start real-time threat feed without external dependencies"""
        self.logger.info("Starting real-time threat feed...")
        self.is_running = True
        
        # Start detection thread
        self.detection_thread = threading.Thread(target=self._realtime_detection_loop)
        self.detection_thread.daemon = True
        self.detection_thread.start()
        
        self.logger.info("Real-time threat feed started successfully")
    
    def stop_realtime_feed(self):
        """Stop real-time threat feed"""
        self.logger.info("Stopping real-time threat feed...")
        self.is_running = False
        
        if self.detection_thread:
            self.detection_thread.join(timeout=5)
        
        self.logger.info("Real-time threat feed stopped")
    
    def _realtime_detection_loop(self):
        """Main real-time detection loop"""
        while self.is_running:
            try:
                # Generate simulated real-time data
                self._generate_realtime_data()
                
                # Process any queued data
                self._process_queued_data()
                
                # Update statistics
                self._update_detection_stats()
                
                # Sleep for detection interval
                time.sleep(self.detection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in real-time detection loop: {e}")
                time.sleep(5)  # Wait before retrying
    
    def _generate_realtime_data(self):
        """Generate simulated real-time network data"""
        # Simulate packet arrival
        packet_data = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            'dst_ip': f"10.0.0.{np.random.randint(1, 255)}",
            'protocol': np.random.choice(['tcp', 'udp', 'icmp']),
            'service': np.random.choice(['http', 'ftp', 'ssh', 'smtp', 'dns']),
            'duration': np.random.uniform(0, 100),
            'src_bytes': np.random.randint(0, 10000),
            'dst_bytes': np.random.randint(0, 10000),
            'flag': np.random.choice(['SF', 'S0', 'REJ', 'RSTR']),
            'count': np.random.randint(1, 100),
            'srv_count': np.random.randint(1, 50),
            'serror_rate': np.random.uniform(0, 1),
            'srv_serror_rate': np.random.uniform(0, 1),
            'rerror_rate': np.random.uniform(0, 1),
            'srv_rerror_rate': np.random.uniform(0, 1),
            'same_srv_rate': np.random.uniform(0, 1),
            'diff_srv_rate': np.random.uniform(0, 1),
            'srv_diff_host_rate': np.random.uniform(0, 1),
            'dst_host_count': np.random.randint(1, 100),
            'dst_host_srv_count': np.random.randint(1, 50),
            'dst_host_same_srv_rate': np.random.uniform(0, 1),
            'dst_host_diff_srv_rate': np.random.uniform(0, 1),
            'dst_host_same_src_port_rate': np.random.uniform(0, 1),
            'dst_host_srv_diff_host_rate': np.random.uniform(0, 1),
            'dst_host_serror_rate': np.random.uniform(0, 1),
            'dst_host_srv_serror_rate': np.random.uniform(0, 1),
            'dst_host_rerror_rate': np.random.uniform(0, 1),
            'dst_host_srv_rerror_rate': np.random.uniform(0, 1)
        }
        
        # Add to processing queue
        try:
            self.data_queue.put_nowait(packet_data)
        except queue.Full:
            self.logger.warning("Data queue is full, dropping packet")
        
        # Occasionally generate threats
        if np.random.random() < 0.05:  # 5% chance of threat
            threat_type = np.random.choice(['DDoS', 'PortScan', 'Bot', 'Web Attack'])
            self._simulate_threat(packet_data, threat_type)
    
    def _process_queued_data(self):
        """Process queued data for threat detection"""
        processed_count = 0
        max_process = 10  # Process max 10 packets per cycle
        
        while processed_count < max_process and not self.data_queue.empty():
            try:
                packet_data = self.data_queue.get_nowait()
                
                # Simulate threat detection
                if self._detect_threat(packet_data):
                    self.detection_stats['threats_detected'] += 1
                    
                    # Generate alert
                    alert = self._create_alert(packet_data)
                    self.alert_queue.put_nowait(alert)
                
                self.detection_stats['total_packets'] += 1
                processed_count += 1
                
            except queue.Empty:
                break
            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")
    
    def _detect_threat(self, packet_data: Dict) -> bool:
        """Simulate threat detection"""
        # Simple heuristic-based detection
        threat_indicators = 0
        
        # Check for suspicious patterns
        if packet_data.get('serror_rate', 0) > 0.8:
            threat_indicators += 1
        
        if packet_data.get('dst_host_serror_rate', 0) > 0.7:
            threat_indicators += 1
        
        if packet_data.get('count', 0) > 50:
            threat_indicators += 1
        
        if packet_data.get('dst_host_count', 0) > 80:
            threat_indicators += 1
        
        # Detect threat if multiple indicators present
        return threat_indicators >= 2
    
    def _create_alert(self, packet_data: Dict) -> Dict:
        """Create threat alert"""
        threat_types = ['DDoS', 'PortScan', 'Bot', 'Web Attack']
        severities = ['HIGH', 'MEDIUM', 'LOW']
        
        return {
            'alert_id': f"ALERT_{int(time.time())}_{np.random.randint(1000, 9999)}",
            'threat_type': np.random.choice(threat_types),
            'severity': np.random.choice(severities),
            'source_ip': packet_data['src_ip'],
            'destination_ip': packet_data['dst_ip'],
            'timestamp': packet_data['timestamp'],
            'confidence': np.random.uniform(0.7, 0.95),
            'description': f"Suspicious activity detected from {packet_data['src_ip']}"
        }
    
    def _update_detection_stats(self):
        """Update detection statistics"""
        self.detection_stats['last_detection'] = datetime.now().isoformat()
        self.detection_stats['processing_time'] = time.time()
    
    def get_realtime_status(self) -> Dict:
        """Get real-time detection status"""
        return {
            'is_running': self.is_running,
            'total_packets': self.detection_stats['total_packets'],
            'threats_detected': self.detection_stats['threats_detected'],
            'queue_size': self.data_queue.qsize(),
            'alert_queue_size': self.alert_queue.qsize(),
            'last_detection': self.detection_stats['last_detection']
        }

def create_threat_detector(models: Dict[str, Any], feature_selector=None, scaler=None) -> ThreatDetector:
    """Create and return a threat detector instance"""
    return ThreatDetector(models, feature_selector, scaler)

if __name__ == "__main__":
    # Example usage
    from models.ml_models import create_ml_models
    from models.dl_models import create_dl_models
    
    # Load trained models (this would normally load from saved files)
    print("Loading models...")
    ml_models = create_ml_models()
    dl_models = create_dl_models()
    
    # Combine all models
    all_models = {**ml_models, **dl_models}
    
    # Create threat detector
    detector = create_threat_detector(all_models)
    
    # Start detection
    detector.start_detection()
    
    # Simulate traffic
    detector.simulate_traffic(50)
    
    # Wait for processing
    time.sleep(10)
    
    # Get results
    alerts = detector.get_alerts()
    stats = detector.get_detection_stats()
    
    print(f"\nDetection Statistics:")
    print(f"Total packets processed: {stats['total_packets']}")
    print(f"Threats detected: {stats['threats_detected']}")
    print(f"Alerts generated: {len(alerts)}")
    
    # Stop detection
    detector.stop_detection()



