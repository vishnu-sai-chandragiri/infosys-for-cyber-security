"""
Real-Time Threat Prediction Service

This module provides real-time threat prediction capabilities
for the cybersecurity AI system.
"""

import numpy as np
import pandas as pd
import time
import threading
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
import warnings
warnings.filterwarnings('ignore')

from utils.helpers import Logger, PerformanceMonitor
from config.config import REALTIME_CONFIG

class RealTimeThreatPredictor:
    """Real-time threat prediction service"""
    
    def __init__(self, models: Dict[str, Any], feature_selector=None, scaler=None):
        self.models = models
        self.feature_selector = feature_selector
        self.scaler = scaler
        self.logger = Logger("RealTimeThreatPredictor")
        self.performance_monitor = PerformanceMonitor()
        
        # Prediction configuration
        self.prediction_interval = REALTIME_CONFIG.get('prediction_interval', 1.0)
        self.batch_size = REALTIME_CONFIG.get('batch_size', 100)
        self.confidence_threshold = REALTIME_CONFIG.get('confidence_threshold', 0.7)
        
        # Data queues and buffers
        self.packet_queue = queue.Queue(maxsize=1000)
        self.prediction_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        
        # Statistics
        self.prediction_stats = {
            'total_packets': 0,
            'predictions_made': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'processing_time': 0,
            'last_prediction': None
        }
        
        # Real-time components
        self.prediction_thread = None
        self.is_running = False
        
        # Threat patterns for prediction
        self.threat_patterns = {
            'DDoS': {
                'indicators': ['high_packet_rate', 'multiple_sources', 'large_packet_size'],
                'thresholds': {'packet_rate': 1000, 'source_count': 50, 'packet_size': 1500}
            },
            'PortScan': {
                'indicators': ['multiple_ports', 'sequential_ports', 'low_response_rate'],
                'thresholds': {'port_count': 20, 'response_rate': 0.1}
            },
            'Bot': {
                'indicators': ['regular_intervals', 'similar_payloads', 'high_frequency'],
                'thresholds': {'interval_variance': 0.1, 'payload_similarity': 0.8}
            },
            'Web Attack': {
                'indicators': ['suspicious_payloads', 'sql_patterns', 'xss_patterns'],
                'thresholds': {'payload_length': 1000, 'pattern_match': 0.7}
            }
        }
        
        self.logger.info("Real-time threat predictor initialized")
    
    def start_prediction_service(self):
        """Start the real-time prediction service"""
        if self.is_running:
            self.logger.warning("Prediction service is already running")
            return
        
        self.logger.info("Starting real-time threat prediction service...")
        self.is_running = True
        
        # Start prediction thread
        self.prediction_thread = threading.Thread(target=self._prediction_loop)
        self.prediction_thread.daemon = True
        self.prediction_thread.start()
        
        self.logger.info("Real-time threat prediction service started")
    
    def stop_prediction_service(self):
        """Stop the real-time prediction service"""
        if not self.is_running:
            self.logger.warning("Prediction service is not running")
            return
        
        self.logger.info("Stopping real-time threat prediction service...")
        self.is_running = False
        
        if self.prediction_thread:
            self.prediction_thread.join(timeout=5)
        
        self.logger.info("Real-time threat prediction service stopped")
    
    def add_packet(self, packet_data: Dict[str, Any]):
        """Add packet data for prediction"""
        try:
            self.packet_queue.put_nowait(packet_data)
            self.prediction_stats['total_packets'] += 1
        except queue.Full:
            self.logger.warning("Packet queue is full, dropping packet")
    
    def _prediction_loop(self):
        """Main prediction loop"""
        while self.is_running:
            try:
                # Process packets in batches
                self._process_packet_batch()
                
                # Update statistics
                self._update_prediction_stats()
                
                # Sleep for prediction interval
                time.sleep(self.prediction_interval)
                
            except Exception as e:
                self.logger.error(f"Error in prediction loop: {e}")
                time.sleep(5)  # Wait before retrying
    
    def _process_packet_batch(self):
        """Process a batch of packets for prediction"""
        batch_packets = []
        
        # Collect packets for batch processing
        while len(batch_packets) < self.batch_size and not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get_nowait()
                batch_packets.append(packet)
            except queue.Empty:
                break
        
        if not batch_packets:
            return
        
        # Process batch
        predictions = self._predict_batch(batch_packets)
        
        # Generate alerts for high-confidence threats
        for packet, prediction in zip(batch_packets, predictions):
            if prediction['confidence'] > self.confidence_threshold:
                alert = self._create_threat_alert(packet, prediction)
                self.alert_queue.put_nowait(alert)
                self.prediction_stats['threats_detected'] += 1
    
    def _predict_batch(self, packets: List[Dict]) -> List[Dict]:
        """Predict threats for a batch of packets"""
        predictions = []
        
        for packet in packets:
            try:
                # Extract features
                features = self._extract_features(packet)
                
                # Make prediction using ensemble of models
                prediction = self._ensemble_predict(features)
                
                # Add pattern-based analysis
                pattern_analysis = self._analyze_threat_patterns(packet)
                
                # Combine predictions
                final_prediction = self._combine_predictions(prediction, pattern_analysis)
                
                predictions.append(final_prediction)
                self.prediction_stats['predictions_made'] += 1
                
            except Exception as e:
                self.logger.error(f"Error predicting packet: {e}")
                predictions.append({
                    'threat_type': 'Unknown',
                    'confidence': 0.0,
                    'severity': 'LOW',
                    'description': 'Prediction failed'
                })
        
        return predictions
    
    def _extract_features(self, packet: Dict) -> np.ndarray:
        """Extract features from packet data"""
        # Convert packet to feature vector
        features = []
        
        # Basic features
        features.extend([
            packet.get('duration', 0),
            packet.get('src_bytes', 0),
            packet.get('dst_bytes', 0),
            packet.get('count', 0),
            packet.get('srv_count', 0),
            packet.get('serror_rate', 0),
            packet.get('srv_serror_rate', 0),
            packet.get('rerror_rate', 0),
            packet.get('srv_rerror_rate', 0),
            packet.get('same_srv_rate', 0),
            packet.get('diff_srv_rate', 0),
            packet.get('srv_diff_host_rate', 0),
            packet.get('dst_host_count', 0),
            packet.get('dst_host_srv_count', 0),
            packet.get('dst_host_same_srv_rate', 0),
            packet.get('dst_host_diff_srv_rate', 0),
            packet.get('dst_host_same_src_port_rate', 0),
            packet.get('dst_host_srv_diff_host_rate', 0),
            packet.get('dst_host_serror_rate', 0),
            packet.get('dst_host_srv_serror_rate', 0),
            packet.get('dst_host_rerror_rate', 0),
            packet.get('dst_host_srv_rerror_rate', 0)
        ])
        
        # Protocol encoding
        protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
        features.append(protocol_map.get(packet.get('protocol', 'tcp'), 0))
        
        # Service encoding
        service_map = {'http': 0, 'ftp': 1, 'ssh': 2, 'smtp': 3, 'dns': 4}
        features.append(service_map.get(packet.get('service', 'http'), 0))
        
        # Flag encoding
        flag_map = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3}
        features.append(flag_map.get(packet.get('flag', 'SF'), 0))
        
        return np.array(features).reshape(1, -1)
    
    def _ensemble_predict(self, features: np.ndarray) -> Dict:
        """Make prediction using ensemble of models"""
        predictions = []
        confidences = []
        
        # Use available models for prediction
        for model_name, model in self.models.items():
            try:
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(features)[0]
                    pred_class = np.argmax(proba)
                    confidence = np.max(proba)
                    
                    predictions.append(pred_class)
                    confidences.append(confidence)
                else:
                    pred = model.predict(features)[0]
                    predictions.append(pred)
                    confidences.append(0.8)  # Default confidence
                    
            except Exception as e:
                self.logger.warning(f"Model {model_name} prediction failed: {e}")
                continue
        
        if not predictions:
            return {
                'threat_type': 'Unknown',
                'confidence': 0.0,
                'severity': 'LOW',
                'description': 'No models available'
            }
        
        # Ensemble prediction (majority vote)
        threat_type_id = max(set(predictions), key=predictions.count)
        avg_confidence = np.mean(confidences)
        
        # Map threat type ID to name
        threat_types = ['BENIGN', 'DDoS', 'PortScan', 'Bot', 'Infiltration', 
                       'Web Attack', 'FTP-Patator', 'SSH-Patator', 'DoS', 'Heartbleed']
        
        threat_type = threat_types[threat_type_id] if threat_type_id < len(threat_types) else 'Unknown'
        
        return {
            'threat_type': threat_type,
            'confidence': avg_confidence,
            'severity': self._determine_severity(threat_type, avg_confidence),
            'description': f'Predicted {threat_type} with {avg_confidence:.2f} confidence'
        }
    
    def _analyze_threat_patterns(self, packet: Dict) -> Dict:
        """Analyze packet for known threat patterns"""
        pattern_scores = {}
        
        for threat_type, pattern in self.threat_patterns.items():
            score = 0
            indicators = pattern['indicators']
            thresholds = pattern['thresholds']
            
            # Analyze each indicator
            for indicator in indicators:
                if indicator == 'high_packet_rate':
                    if packet.get('count', 0) > thresholds.get('packet_rate', 1000):
                        score += 0.3
                
                elif indicator == 'multiple_sources':
                    if packet.get('dst_host_count', 0) > thresholds.get('source_count', 50):
                        score += 0.3
                
                elif indicator == 'large_packet_size':
                    if packet.get('src_bytes', 0) > thresholds.get('packet_size', 1500):
                        score += 0.2
                
                elif indicator == 'multiple_ports':
                    if packet.get('srv_count', 0) > thresholds.get('port_count', 20):
                        score += 0.4
                
                elif indicator == 'low_response_rate':
                    if packet.get('serror_rate', 0) > thresholds.get('response_rate', 0.1):
                        score += 0.3
            
            pattern_scores[threat_type] = score
        
        # Find highest scoring pattern
        if pattern_scores:
            best_pattern = max(pattern_scores.items(), key=lambda x: x[1])
            if best_pattern[1] > 0.5:
                return {
                    'threat_type': best_pattern[0],
                    'confidence': best_pattern[1],
                    'severity': self._determine_severity(best_pattern[0], best_pattern[1]),
                    'description': f'Pattern analysis suggests {best_pattern[0]}'
                }
        
        return {
            'threat_type': 'BENIGN',
            'confidence': 0.1,
            'severity': 'LOW',
            'description': 'No suspicious patterns detected'
        }
    
    def _combine_predictions(self, ml_prediction: Dict, pattern_prediction: Dict) -> Dict:
        """Combine ML and pattern-based predictions"""
        # Weight ML prediction more heavily
        ml_weight = 0.7
        pattern_weight = 0.3
        
        # Combine confidences
        combined_confidence = (ml_prediction['confidence'] * ml_weight + 
                             pattern_prediction['confidence'] * pattern_weight)
        
        # Choose threat type based on higher confidence
        if ml_prediction['confidence'] > pattern_prediction['confidence']:
            threat_type = ml_prediction['threat_type']
            description = ml_prediction['description']
        else:
            threat_type = pattern_prediction['threat_type']
            description = pattern_prediction['description']
        
        return {
            'threat_type': threat_type,
            'confidence': combined_confidence,
            'severity': self._determine_severity(threat_type, combined_confidence),
            'description': description,
            'ml_prediction': ml_prediction,
            'pattern_prediction': pattern_prediction
        }
    
    def _determine_severity(self, threat_type: str, confidence: float) -> str:
        """Determine threat severity based on type and confidence"""
        high_severity_types = ['DDoS', 'Infiltration', 'Web Attack']
        medium_severity_types = ['PortScan', 'Bot', 'FTP-Patator', 'SSH-Patator']
        
        if threat_type in high_severity_types and confidence > 0.8:
            return 'HIGH'
        elif threat_type in high_severity_types or confidence > 0.6:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _create_threat_alert(self, packet: Dict, prediction: Dict) -> Dict:
        """Create threat alert from prediction"""
        return {
            'alert_id': f"ALERT_{int(time.time())}_{np.random.randint(1000, 9999)}",
            'threat_type': prediction['threat_type'],
            'severity': prediction['severity'],
            'confidence': prediction['confidence'],
            'source_ip': packet.get('src_ip', 'Unknown'),
            'destination_ip': packet.get('dst_ip', 'Unknown'),
            'timestamp': datetime.now().isoformat(),
            'description': prediction['description'],
            'packet_data': packet,
            'prediction_details': prediction
        }
    
    def _update_prediction_stats(self):
        """Update prediction statistics"""
        self.prediction_stats['last_prediction'] = datetime.now().isoformat()
        self.prediction_stats['processing_time'] = time.time()
    
    def get_prediction_status(self) -> Dict:
        """Get current prediction service status"""
        return {
            'is_running': self.is_running,
            'total_packets': self.prediction_stats['total_packets'],
            'predictions_made': self.prediction_stats['predictions_made'],
            'threats_detected': self.prediction_stats['threats_detected'],
            'queue_size': self.packet_queue.qsize(),
            'alert_queue_size': self.alert_queue.qsize(),
            'last_prediction': self.prediction_stats['last_prediction']
        }
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """Get recent threat alerts"""
        alerts = []
        
        # Collect alerts from queue
        while not self.alert_queue.empty() and len(alerts) < limit:
            try:
                alert = self.alert_queue.get_nowait()
                alerts.append(alert)
            except queue.Empty:
                break
        
        return alerts

def create_threat_predictor(models: Dict[str, Any], feature_selector=None, scaler=None) -> RealTimeThreatPredictor:
    """Create and return a real-time threat predictor instance"""
    return RealTimeThreatPredictor(models, feature_selector, scaler)
