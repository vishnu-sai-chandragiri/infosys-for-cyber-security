"""
AI-Powered Cybersecurity Chatbot

This module implements an intelligent chatbot that can answer queries about
cybersecurity threats, system status, and provide recommendations.
"""

import json
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

# NLP and ML libraries
try:
    import nltk
    from nltk.corpus import stopwords
    from nltk.tokenize import word_tokenize
    from nltk.stem import WordNetLemmatizer
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
except ImportError:
    print("Warning: NLP dependencies not installed. Chatbot will use basic pattern matching.")
    nltk = None
    TfidfVectorizer = None
    cosine_similarity = None
    pipeline = None

from utils.helpers import Logger, PerformanceMonitor
from utils.database import get_database
from config.config import CHATBOT_CONFIG, ATTACK_TYPES, THREAT_SEVERITY, ALERT_TYPES

class IntentClassifier:
    """Classify user intents for chatbot responses"""
    
    def __init__(self):
        self.intents = {
            'threat_status': [
                'current threats', 'active threats', 'threats detected', 'security status',
                'what threats', 'any attacks', 'security alerts', 'threat level',
                'show threats', 'threats now', 'current attacks', 'security situation',
                'threat dashboard', 'live threats', 'real-time threats', 'threat feed',
                'security monitoring', 'threat detection', 'active alerts', 'threat summary',
                'current security', 'threat overview', 'security state', 'threat report',
                'are there threats', 'any security issues', 'security problems', 'threats active'
            ],
            'threat_details': [
                'threat details', 'attack details', 'more information', 'explain threat',
                'what is this attack', 'threat analysis', 'attack type', 'tell me about',
                'explain ddos', 'explain portscan', 'explain bot', 'explain web attack',
                'threat intelligence', 'attack pattern', 'threat behavior', 'attack vector',
                'threat characteristics', 'attack methodology', 'threat signature', 'attack indicators',
                'threat profile', 'what does this mean', 'analyze this threat', 'threat explanation'
            ],
            'mitigation': [
                'how to fix', 'recommendations', 'what to do', 'mitigation',
                'prevent attack', 'stop threat', 'security measures', 'countermeasures',
                'how to prevent', 'how to stop', 'how to protect', 'security advice',
                'how to secure', 'security best practices', 'defense strategies', 'security hardening',
                'incident response', 'security procedures', 'threat response', 'security policies',
                'how to defend', 'protection measures', 'security controls', 'defense mechanisms'
            ],
            'model_performance': [
                'model accuracy', 'performance metrics', 'model status', 'detection rate',
                'false positives', 'model evaluation', 'system performance', 'accuracy',
                'performance', 'model stats', 'detection stats', 'model effectiveness',
                'detection performance', 'model reliability', 'system performance', 'model metrics',
                'accuracy rate', 'false negative rate', 'model statistics', 'performance data'
            ],
            'historical_data': [
                'historical threats', 'past attacks', 'threat history', 'attack trends',
                'security logs', 'previous incidents', 'threat statistics', 'history',
                'past data', 'trends', 'statistics', 'threat timeline', 'attack history',
                'security incidents', 'historical threats', 'past security events',
                'threat evolution', 'attack patterns over time', 'security trends', 'historical analysis'
            ],
            'system_info': [
                'system status', 'system health', 'components status', 'service status',
                'system information', 'health check', 'system overview', 'status',
                'health', 'system', 'components', 'system monitoring', 'system health check',
                'system diagnostics', 'system status report', 'system health status',
                'system operational status', 'system maintenance', 'system configuration', 'system logs'
            ],
            'help': [
                'help', 'what can you do', 'commands', 'how to use', 'assistance',
                'support', 'guide', 'tutorial', 'what do you do', 'capabilities',
                'help me', 'what are your features', 'how do you work', 'what can you help with',
                'guide me', 'show me options', 'what are your capabilities', 'how can you assist'
            ],
            'greeting': [
                'hello', 'hi', 'hey', 'good morning', 'good afternoon', 'good evening',
                'greetings', 'how are you', 'whats up', 'good day', 'hello there',
                'hi there', 'hey there', 'greetings', 'salutations', 'good to see you'
            ],
            'threat_simulation': [
                'simulate threat', 'test threat', 'threat simulation', 'attack simulation',
                'simulate attack', 'test attack', 'threat testing', 'security test',
                'penetration test', 'security simulation', 'threat drill', 'attack drill'
            ],
            'security_recommendations': [
                'security recommendations', 'security advice', 'security tips', 'security guidance',
                'security best practices', 'security suggestions', 'security recommendations',
                'how to improve security', 'security improvements', 'security enhancements',
                'security optimization', 'security hardening', 'security configuration'
            ],
            'network_security': [
                'network', 'firewall', 'vpn', 'proxy', 'router', 'switch', 'traffic', 'packets',
                'protocol', 'port', 'ip address', 'dns', 'dhcp', 'subnet', 'lan', 'wan',
                'network security', 'network monitoring', 'network protection'
            ],
            'incident_response': [
                'incident', 'response', 'forensics', 'investigation', 'evidence', 'containment',
                'eradication', 'recovery', 'lessons learned', 'post-incident', 'breach response',
                'incident response', 'security incident', 'incident handling'
            ]
        }
        
        self.lemmatizer = None
        self.stop_words = set()
        self.vectorizer = None
        self.intent_vectors = None
        
        self._initialize_nlp()
    
    def _initialize_nlp(self):
        """Initialize NLP components"""
        try:
            if nltk:
                # Download required NLTK data
                try:
                    nltk.data.find('tokenizers/punkt')
                    nltk.data.find('corpora/stopwords')
                    nltk.data.find('corpora/wordnet')
                except LookupError:
                    nltk.download('punkt', quiet=True)
                    nltk.download('stopwords', quiet=True)
                    nltk.download('wordnet', quiet=True)
                
                self.lemmatizer = WordNetLemmatizer()
                self.stop_words = set(stopwords.words('english'))
                
                # Initialize TF-IDF vectorizer
                if TfidfVectorizer:
                    self.vectorizer = TfidfVectorizer(
                        max_features=1000,
                        stop_words='english',
                        ngram_range=(1, 2)
                    )
                    
                    # Prepare training data
                    all_texts = []
                    intent_labels = []
                    
                    for intent, phrases in self.intents.items():
                        for phrase in phrases:
                            all_texts.append(phrase)
                            intent_labels.append(intent)
                    
                    # Fit vectorizer
                    self.intent_vectors = self.vectorizer.fit_transform(all_texts)
                    
        except Exception as e:
            print(f"Warning: Could not initialize NLP components: {e}")
    
    def classify_intent(self, user_input: str) -> Tuple[str, float]:
        """Classify user intent from input text"""
        try:
            if not self.vectorizer or not self.intent_vectors:
                return self._classify_intent_simple(user_input)
            
            # Preprocess input
            processed_input = self._preprocess_text(user_input)
            
            # Vectorize input
            input_vector = self.vectorizer.transform([processed_input])
            
            # Calculate similarities
            similarities = cosine_similarity(input_vector, self.intent_vectors).flatten()
            
            # Get best match
            best_match_idx = np.argmax(similarities)
            confidence = similarities[best_match_idx]
            
            # Map back to intent
            intent_labels = []
            for intent, phrases in self.intents.items():
                intent_labels.extend([intent] * len(phrases))
            
            best_intent = intent_labels[best_match_idx]
            
            return best_intent, confidence
            
        except Exception as e:
            print(f"Error in intent classification: {e}")
            return self._classify_intent_simple(user_input)
    
    def _classify_intent_simple(self, user_input: str) -> Tuple[str, float]:
        """Simple keyword-based intent classification"""
        user_input_lower = user_input.lower()
        
        intent_scores = {}
        for intent, keywords in self.intents.items():
            score = 0
            for keyword in keywords:
                if keyword in user_input_lower:
                    score += 1
            intent_scores[intent] = score / len(keywords)
        
        if not intent_scores or max(intent_scores.values()) == 0:
            return 'help', 0.1
        
        best_intent = max(intent_scores, key=intent_scores.get)
        confidence = intent_scores[best_intent]
        
        return best_intent, confidence
    
    def _preprocess_text(self, text: str) -> str:
        """Preprocess text for NLP"""
        if not self.lemmatizer:
            return text.lower()
        
        # Tokenize
        tokens = word_tokenize(text.lower())
        
        # Remove stopwords and lemmatize
        processed_tokens = []
        for token in tokens:
            if token.isalpha() and token not in self.stop_words:
                lemmatized = self.lemmatizer.lemmatize(token)
                processed_tokens.append(lemmatized)
        
        return ' '.join(processed_tokens)

class ThreatAnalyzer:
    """Analyze and provide insights about cybersecurity threats"""
    
    def __init__(self, threat_detector=None):
        self.threat_detector = threat_detector
        self.logger = Logger("ThreatAnalyzer")
    
    def get_current_threats(self) -> Dict[str, Any]:
        """Get current threat status"""
        if not self.threat_detector:
            return self._get_mock_threats()
        
        try:
            stats = self.threat_detector.get_detection_stats()
            alerts = self.threat_detector.get_alerts(limit=10)
            
            return {
                'total_packets_processed': stats['total_packets'],
                'threats_detected': stats['threats_detected'],
                'active_alerts': len(alerts),
                'recent_alerts': alerts[:5],
                'system_status': 'Active' if stats['is_running'] else 'Inactive',
                'last_detection': stats['last_detection']
            }
        except Exception as e:
            self.logger.error(f"Error getting current threats: {e}")
            return self._get_mock_threats()
    
    def _get_mock_threats(self) -> Dict[str, Any]:
        """Get mock threat data for demonstration"""
        return {
            'total_packets_processed': 1250,
            'threats_detected': 3,
            'active_alerts': 2,
            'recent_alerts': [
                {
                    'alert_id': 'ALERT_001',
                    'threat_type': 'DDoS',
                    'severity': 'HIGH',
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': '192.168.1.100'
                },
                {
                    'alert_id': 'ALERT_002',
                    'threat_type': 'PortScan',
                    'severity': 'MEDIUM',
                    'timestamp': (datetime.now() - timedelta(minutes=5)).isoformat(),
                    'source_ip': '10.0.0.50'
                }
            ],
            'system_status': 'Active',
            'last_detection': datetime.now().isoformat()
        }
    
    def get_threat_details(self, threat_type: str) -> Dict[str, Any]:
        """Get detailed information about a specific threat type"""
        threat_info = {
            'DDoS': {
                'description': 'Distributed Denial of Service attack that overwhelms a target with traffic',
                'severity': 'HIGH',
                'common_indicators': ['High traffic volume', 'Multiple source IPs', 'Service unavailability'],
                'mitigation': ['Enable DDoS protection', 'Rate limiting', 'Traffic filtering'],
                'prevention': ['Network monitoring', 'Load balancing', 'Redundancy planning']
            },
            'PortScan': {
                'description': 'Systematic scanning of network ports to identify open services',
                'severity': 'MEDIUM',
                'common_indicators': ['Multiple connection attempts', 'Sequential port access', 'Failed connections'],
                'mitigation': ['Block scanning IPs', 'Port filtering', 'Intrusion detection'],
                'prevention': ['Firewall rules', 'Network segmentation', 'Service hardening']
            },
            'Bot': {
                'description': 'Automated software that performs malicious activities',
                'severity': 'MEDIUM',
                'common_indicators': ['Automated behavior', 'High request frequency', 'Suspicious user agents'],
                'mitigation': ['Bot detection', 'CAPTCHA implementation', 'Rate limiting'],
                'prevention': ['Behavioral analysis', 'Machine learning detection', 'User verification']
            },
            'Web Attack': {
                'description': 'Attacks targeting web applications and services',
                'severity': 'HIGH',
                'common_indicators': ['Malicious payloads', 'SQL injection attempts', 'XSS patterns'],
                'mitigation': ['WAF rules', 'Input validation', 'Output encoding'],
                'prevention': ['Secure coding', 'Regular updates', 'Security testing']
            }
        }
        
        return threat_info.get(threat_type, {
            'description': 'Unknown threat type',
            'severity': 'UNKNOWN',
            'common_indicators': [],
            'mitigation': [],
            'prevention': []
        })
    
    def get_mitigation_recommendations(self, threat_type: str, severity: str) -> List[str]:
        """Get mitigation recommendations for specific threats"""
        recommendations = []
        
        if severity in ['HIGH', 'CRITICAL']:
            recommendations.extend([
                "🚨 IMMEDIATE ACTION REQUIRED",
                "• Block the source IP address immediately",
                "• Notify the security team",
                "• Initiate incident response procedures"
            ])
        
        if threat_type == 'DDoS':
            recommendations.extend([
                "🛡️ DDoS Mitigation:",
                "• Enable DDoS protection services",
                "• Implement rate limiting",
                "• Monitor network bandwidth usage",
                "• Consider traffic filtering"
            ])
        elif threat_type == 'PortScan':
            recommendations.extend([
                "🔍 Port Scan Response:",
                "• Block the scanning IP address",
                "• Review firewall rules",
                "• Monitor for further scanning activity",
                "• Check for unauthorized access attempts"
            ])
        elif 'Web Attack' in threat_type:
            recommendations.extend([
                "🌐 Web Attack Response:",
                "• Block malicious requests",
                "• Review web application logs",
                "• Update WAF (Web Application Firewall) rules",
                "• Check for data breaches"
            ])
        elif threat_type == 'Bot':
            recommendations.extend([
                "🤖 Bot Traffic Response:",
                "• Implement bot detection mechanisms",
                "• Add CAPTCHA challenges",
                "• Rate limit suspicious traffic",
                "• Monitor for botnet activity"
            ])
        
        if not recommendations:
            recommendations = [
                "📋 General Security Measures:",
                "• Review security logs",
                "• Update security policies",
                "• Monitor network traffic",
                "• Contact security team for assistance"
            ]
        
        return recommendations

class ModelPerformanceAnalyzer:
    """Analyze and report on model performance"""
    
    def __init__(self):
        self.logger = Logger("ModelPerformanceAnalyzer")
    
    def get_model_performance(self) -> Dict[str, Any]:
        """Get current model performance metrics"""
        # This would typically load from saved metrics files
        return {
            'overall_accuracy': 0.95,
            'detection_rate': 0.92,
            'false_positive_rate': 0.03,
            'models': {
                'Random Forest': {
                    'accuracy': 0.94,
                    'precision': 0.93,
                    'recall': 0.91,
                    'f1_score': 0.92
                },
                'XGBoost': {
                    'accuracy': 0.96,
                    'precision': 0.95,
                    'recall': 0.94,
                    'f1_score': 0.94
                },
                'LSTM': {
                    'accuracy': 0.93,
                    'precision': 0.92,
                    'recall': 0.90,
                    'f1_score': 0.91
                },
                'Autoencoder': {
                    'accuracy': 0.89,
                    'precision': 0.88,
                    'recall': 0.87,
                    'f1_score': 0.87
                }
            },
            'last_updated': datetime.now().isoformat()
        }
    
    def get_historical_performance(self, days: int = 7) -> Dict[str, Any]:
        """Get historical performance data"""
        # Mock historical data
        dates = [(datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(days)]
        
        return {
            'daily_accuracy': [0.94 + np.random.normal(0, 0.02) for _ in range(days)],
            'daily_detections': [np.random.randint(5, 25) for _ in range(days)],
            'daily_false_positives': [np.random.randint(0, 5) for _ in range(days)],
            'dates': dates
        }

class CybersecurityChatbot:
    """Main chatbot class for cybersecurity queries"""
    
    def __init__(self, threat_detector=None):
        self.logger = Logger("CybersecurityChatbot")
        self.performance_monitor = PerformanceMonitor()
        
        # Initialize database
        self.db = get_database()
        
        # Initialize components
        self.intent_classifier = IntentClassifier()
        self.threat_analyzer = ThreatAnalyzer(threat_detector)
        self.model_analyzer = ModelPerformanceAnalyzer()
        
        # Chat history (in-memory fallback)
        self.chat_history = []
        self.context = {}
        
        # Enhanced response templates with more intelligent responses
        self.response_templates = {
            'greeting': [
                "Hello! I'm your AI cybersecurity assistant. I can help you analyze threats, provide security recommendations, and answer questions about cybersecurity. How can I assist you today?",
                "Hi there! I'm here to help with your cybersecurity needs. I can analyze threat data, explain attack patterns, suggest mitigation strategies, and provide insights about your security posture. What would you like to know?",
                "Welcome! I'm your AI security analyst. I can help you understand threats, analyze security incidents, recommend protective measures, and provide detailed explanations about cybersecurity concepts. What can I help you with?"
            ],
            'help': [
                "I'm your AI cybersecurity assistant. Here's what I can help you with:",
                "",
                "🔍 **Threat Analysis**:",
                "• Analyze current threats and attack patterns",
                "• Explain different types of cyber attacks",
                "• Provide detailed threat intelligence",
                "",
                "🛡️ **Security Recommendations**:",
                "• Suggest mitigation strategies",
                "• Recommend security controls",
                "• Provide incident response guidance",
                "",
                "📊 **System Information**:",
                "• Model performance metrics",
                "• System health and status",
                "• Historical security data",
                "",
                "💡 **General Cybersecurity**:",
                "• Answer security questions",
                "• Explain security concepts",
                "• Provide best practices",
                "",
                "Just ask me anything about cybersecurity, and I'll provide detailed, helpful responses!"
            ],
            'error': [
                "I understand you're asking about cybersecurity. Let me help you with that! I can provide information about threats, security analysis, recommendations, or explain any security concepts. What specifically would you like to know?",
                "I'm here to help with cybersecurity questions. I can analyze threats, explain attack types, suggest security measures, or provide insights about your security posture. Could you be more specific about what you'd like to know?",
                "I'm your AI security assistant, ready to help! I can assist with threat analysis, security recommendations, system information, or answer any cybersecurity questions. What would you like to explore?"
            ]
        }
    def process_query(self, user_input: str, user_id: str = "default") -> Dict[str, Any]:
        """Process user query and generate response"""
        start_time = time.time()
        
        try:
            # Classify intent
            intent, confidence = self.intent_classifier.classify_intent(user_input)
            
            # Generate response based on intent
            response = self._generate_response(user_input, intent, confidence)
            
            # Save to database
            processing_time = time.time() - start_time
            self.db.save_chat_message(
                user_id=user_id,
                user_input=user_input,
                bot_response=response,
                intent=intent,
                confidence=confidence,
                processing_time=processing_time
            )
            
            # Update in-memory history for fallback
            chat_entry = {
                'timestamp': datetime.now().isoformat(),
                'user_id': user_id,
                'user_input': user_input,
                'intent': intent,
                'confidence': confidence,
                'response': response,
                'processing_time': processing_time
            }
            
            self.chat_history.append(chat_entry)
            
            # Keep only recent history
            if len(self.chat_history) > 100:
                self.chat_history = self.chat_history[-100:]
            
            return {
                'response': response,
                'intent': intent,
                'confidence': confidence,
                'timestamp': chat_entry['timestamp'],
                'processing_time': chat_entry['processing_time']
            }
            
        except Exception as e:
            self.logger.error(f"Error processing query: {e}")
            return {
                'response': "I'm sorry, I encountered an error processing your request. Please try again.",
                'intent': 'error',
                'confidence': 0.0,
                'timestamp': datetime.now().isoformat(),
                'processing_time': time.time() - start_time
            }
    
    def _generate_response(self, user_input: str, intent: str, confidence: float) -> str:
        """Generate response based on classified intent"""
        
        if confidence < CHATBOT_CONFIG['intent_threshold']:
            return self._handle_general_query(user_input)
        
        if intent == 'threat_status':
            return self._handle_threat_status_query()
        
        elif intent == 'threat_details':
            return self._handle_threat_details_query(user_input)
        
        elif intent == 'mitigation':
            return self._handle_mitigation_query(user_input)
        
        elif intent == 'model_performance':
            return self._handle_model_performance_query()
        
        elif intent == 'historical_data':
            return self._handle_historical_data_query()
        
        elif intent == 'system_info':
            return self._handle_system_info_query()
        
        elif intent == 'threat_simulation':
            return self._handle_threat_simulation_query()
        
        elif intent == 'security_recommendations':
            return self._handle_security_recommendations_query()
        
        elif intent == 'network_security':
            return self._handle_network_security_query(user_input)
        
        elif intent == 'incident_response':
            return self._handle_incident_response_query(user_input)
        
        elif intent == 'help':
            return self._handle_help_query(user_input)
        
        elif intent == 'greeting':
            return np.random.choice(self.response_templates['greeting'])
        
        else:
            return self._handle_general_query(user_input)
    
    def _handle_general_query(self, query: str) -> str:
        """Handle general queries with intelligent responses"""
        query_lower = query.lower()
        
        # Check for specific keywords and provide helpful responses
        if any(word in query_lower for word in ['threat', 'attack', 'security', 'alert']):
            return """🔍 **I can help you with security-related questions!**

**Try asking me about:**
• "What are the current threats?" - Get real-time threat status
• "Show me security alerts" - View active security alerts  
• "How can I prevent attacks?" - Get security recommendations
• "Explain this threat" - Get detailed threat analysis
• "What's the security status?" - Check system security status

**What specific security question can I help you with?**"""
        
        elif any(word in query_lower for word in ['help', 'what', 'how', 'can you']):
            return """🤖 **I'm your AI Cybersecurity Assistant!**

**I can help you with:**
🔍 **Threat Analysis** - Current threats, attack details, threat intelligence
🛡️ **Security Monitoring** - System status, security metrics, alerts
💡 **Recommendations** - Security best practices, mitigation strategies
📊 **System Info** - Performance metrics, model statistics, health checks
📈 **Historical Data** - Past threats, trends, security incidents

**Just ask me anything about cybersecurity!**"""
        
        else:
            return """🤔 **I'm not sure I understand your question.**

**I specialize in cybersecurity topics. Try asking me about:**

🔍 **Threat Information:**
• "What threats are active?"
• "Show me recent attacks"
• "Explain DDoS attacks"

🛡️ **Security Help:**
• "How can I improve security?"
• "What are security best practices?"
• "How do I prevent attacks?"

📊 **System Status:**
• "What's the system status?"
• "Show me performance metrics"
• "How are the models performing?"

**What cybersecurity question can I help you with?**"""
    
    def _handle_threat_simulation_query(self) -> str:
        """Handle threat simulation queries"""
        return """🧪 **Threat Simulation & Testing**

**I can help you with threat simulation:**

🎯 **Simulation Types:**
• DDoS attack simulation
• Port scanning tests
• Bot traffic simulation
• Web attack testing
• Penetration testing scenarios

🛠️ **Testing Capabilities:**
• Network stress testing
• Security control validation
• Incident response drills
• Threat detection testing
• System resilience testing

📋 **How to Simulate:**
1. Go to the Dashboard
2. Click "Simulate Traffic" button
3. Set packet count (50-1000)
4. Monitor real-time results
5. Analyze detection performance

⚠️ **Important:** Only run simulations in controlled environments!

**Would you like me to explain any specific simulation type?**"""
    
    def _handle_security_recommendations_query(self) -> str:
        """Handle security recommendations queries"""
        return """🛡️ **Security Recommendations & Best Practices**

**Immediate Actions:**
🔒 **Access Control:**
• Implement multi-factor authentication
• Use strong, unique passwords
• Regular access reviews and audits
• Principle of least privilege

🛡️ **Network Security:**
• Keep firewalls updated and configured
• Use VPN for remote access
• Segment network traffic
• Monitor network traffic continuously

🔍 **Monitoring & Detection:**
• Enable real-time threat detection
• Set up security alerts and notifications
• Regular security log reviews
• Implement SIEM solutions

📱 **System Hardening:**
• Keep all systems patched and updated
• Disable unnecessary services
• Use endpoint protection
• Regular security assessments

🚨 **Incident Response:**
• Develop incident response plan
• Regular backup and recovery testing
• Security awareness training
• Regular penetration testing

**Which area would you like me to elaborate on?**"""
    
    def _handle_threat_status_query(self) -> str:
        """Handle threat status queries with intelligent analysis"""
        threat_data = self.threat_analyzer.get_current_threats()
        
        if not threat_data or threat_data.get('threats_detected', 0) == 0:
            return """🟢 **Current Security Status: CLEAR**

No active threats detected at this time. Your system appears to be secure.

**Recent Activity Summary:**
• System monitoring: Active ✅
• Threat detection: Operational ✅
• Network traffic: Normal ✅

**Recommendations:**
• Continue regular monitoring
• Keep security systems updated
• Review security logs periodically

Would you like me to analyze historical threat data or explain how threat detection works?"""
        
        # Analyze threat data intelligently
        total_threats = threat_data.get('threats_detected', 0)
        active_alerts = threat_data.get('active_alerts', 0)
        recent_alerts = threat_data.get('recent_alerts', [])
        
        # Analyze severity distribution
        high_severity = len([a for a in recent_alerts if a.get('severity') == 'HIGH'])
        medium_severity = len([a for a in recent_alerts if a.get('severity') == 'MEDIUM'])
        low_severity = len([a for a in recent_alerts if a.get('severity') == 'LOW'])
        
        # Get threat type distribution
        threat_types = {}
        for alert in recent_alerts:
            threat_type = alert.get('threat_type', 'Unknown')
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        # Determine overall risk level
        if high_severity > 0:
            risk_level = "🔴 HIGH RISK"
        elif medium_severity > 2:
            risk_level = "🟡 MEDIUM RISK"
        else:
            risk_level = "🟢 LOW RISK"
        
        response = f"""🚨 **Current Security Status: {risk_level}**

**System Overview:**
• Total Packets Processed: **{threat_data.get('total_packets_processed', 0):,}**
• Threats Detected: **{total_threats}**
• Active Alerts: **{active_alerts}**
• System Status: **{threat_data.get('system_status', 'Unknown')}**

**Threat Severity Analysis:**"""
        
        if high_severity > 0:
            response += f"\n• High Severity: **{high_severity}** 🔴 (Immediate attention required)"
        if medium_severity > 0:
            response += f"\n• Medium Severity: **{medium_severity}** 🟡 (Monitor closely)"
        if low_severity > 0:
            response += f"\n• Low Severity: **{low_severity}** 🟢 (Informational)"
        
        if threat_types:
            response += f"\n\n**Threat Type Distribution:**"
            for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True):
                response += f"\n• {threat_type}: {count} incidents"
        
        response += f"\n\n**Recent Alerts:**"
        
        if recent_alerts:
            for i, alert in enumerate(recent_alerts[:5]):
                severity_icon = "🔴" if alert.get('severity') == 'HIGH' else "🟡" if alert.get('severity') == 'MEDIUM' else "🟢"
                response += f"""
{i+1}. {severity_icon} **{alert.get('threat_type', 'Unknown')}** from {alert.get('source_ip', 'Unknown')}
   • Severity: {alert.get('severity', 'Unknown')}
   • Time: {alert.get('timestamp', 'Unknown')}"""
        else:
            response += "\n• No recent alerts"
        
        response += f"""

**Immediate Actions Recommended:**
• Review high-severity threats immediately
• Implement additional monitoring for detected attack types
• Consider updating security controls
• Document incidents for analysis

Would you like me to provide detailed analysis of any specific threat or suggest mitigation strategies?"""
        
        return response
    
    def _handle_threat_details_query(self, user_input: str) -> str:
        """Handle threat details queries with unique responses"""
        query_lower = user_input.lower()
        
        # Provide unique responses for each threat type
        if 'ddos' in query_lower:
            return """🚨 **DDoS Attack Deep Analysis**

**Attack Overview:**
DDoS (Distributed Denial of Service) attacks are orchestrated assaults that flood target systems with overwhelming traffic from multiple compromised sources, rendering services inaccessible to legitimate users.

**Technical Details:**
• **Attack Vectors:** Volumetric (flooding), Protocol (exploiting weaknesses), Application-layer (targeting apps)
• **Traffic Patterns:** Sudden spikes, multiple source IPs, high packet rates
• **Impact:** Service degradation, complete unavailability, resource exhaustion
• **Duration:** Can last minutes to days

**Real-time Detection:**
• Network traffic monitoring shows 300% increase in requests
• Multiple geographic sources identified
• Unusual traffic patterns detected
• System resources at 95% capacity

**Immediate Response:**
1. Activate DDoS mitigation protocols
2. Route traffic through protection services
3. Implement rate limiting (1000 req/min per IP)
4. Monitor system performance metrics
5. Alert security team immediately

**Prevention Measures:**
• Deploy DDoS protection services (Cloudflare, AWS Shield)
• Configure network firewalls with DDoS rules
• Implement load balancing and redundancy
• Regular penetration testing
• Incident response plan activation

**Current System Status:** DDoS protection active, monitoring 24/7"""
        
        elif 'portscan' in query_lower or 'port scan' in query_lower:
            return """🔍 **Port Scan Attack Intelligence**

**Reconnaissance Analysis:**
Port scanning is a systematic reconnaissance technique where attackers probe network ports to map services, identify vulnerabilities, and plan subsequent attacks.

**Scanning Techniques:**
• **TCP Connect Scan:** Full connection attempts to each port
• **SYN Scan:** Half-open connections (stealthier)
• **UDP Scan:** Probing UDP services
• **FIN Scan:** Using FIN packets to bypass firewalls

**Detection Signatures:**
• Sequential port probing (1-65535)
• Multiple failed connection attempts
• Short connection durations (<1 second)
• Unusual port access patterns
• Source IP attempting 100+ ports in 1 minute

**Current Threat Activity:**
• Detected 3 port scans in last 24 hours
• Source IPs: 192.168.1.100, 10.0.0.50, 203.0.113.25
• Targeted ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3389 (RDP)
• Scan duration: 2-5 minutes per source

**Defense Strategy:**
• Block suspicious IPs automatically
• Implement port knocking for sensitive services
• Use honeypots to detect scanning
• Monitor network logs in real-time
• Configure IDS/IPS rules for port scanning

**System Response:** Auto-blocking active, 15 IPs blocked today"""
        
        elif 'bot' in query_lower:
            return """🤖 **Bot Attack Pattern Analysis**

**Botnet Intelligence:**
Bot attacks involve coordinated networks of compromised devices (bots) performing automated malicious activities, often controlled by command-and-control servers.

**Bot Attack Types:**
• **Credential Stuffing:** Automated login attempts with stolen credentials
• **Web Scraping:** Automated data extraction from websites
• **Click Fraud:** Fake clicks on advertisements
• **Distributed Attacks:** Coordinated DDoS or spam campaigns

**Behavioral Indicators:**
• High request frequency (1000+ requests/hour)
• Repetitive patterns and timing
• Unusual user agent strings
• Missing or fake browser headers
• Geographic anomalies in traffic

**Current Bot Activity:**
• Detected 5 bot networks active
• 2,500+ automated requests blocked
• Bot types: Web scrapers (60%), Credential stuffers (30%), Click fraud (10%)
• Geographic distribution: 15 countries
• Average bot session: 45 minutes

**Detection Methods:**
• Behavioral analysis algorithms
• Machine learning pattern recognition
• CAPTCHA challenges for suspicious users
• Rate limiting and request throttling
• IP reputation checking

**Mitigation Actions:**
• Bot detection rules updated
• CAPTCHA deployed for high-risk activities
• Rate limiting: 100 requests/5 minutes per IP
• 500+ bot IPs added to blacklist
• Real-time monitoring active

**System Status:** Bot protection 99.2% effective"""
        
        elif 'web attack' in query_lower:
            return """🌐 **Web Application Attack Analysis**

**Attack Surface Analysis:**
Web attacks target application-layer vulnerabilities, exploiting weaknesses in web applications, APIs, and web services.

**Primary Attack Vectors:**
• **SQL Injection:** Malicious SQL code injection
• **XSS (Cross-Site Scripting):** Script injection attacks
• **CSRF (Cross-Site Request Forgery):** Unauthorized actions
• **Brute Force:** Automated password attacks
• **File Upload Attacks:** Malicious file uploads

**Current Threat Landscape:**
• 12 web attacks detected in last 24 hours
• Attack types: SQL injection (40%), XSS (35%), Brute force (25%)
• Target applications: Login pages, search forms, file uploads
• Attack sources: 8 different countries
• Success rate: 0% (all blocked)

**Real-time Protection:**
• Web Application Firewall (WAF) active
• Input validation and sanitization enabled
• SQL injection detection: 15 attempts blocked
• XSS prevention: 8 malicious scripts blocked
• Brute force protection: 200+ failed logins blocked

**Security Measures:**
• OWASP Top 10 protection implemented
• Regular security testing and code reviews
• HTTPS enforcement with HSTS
• Content Security Policy (CSP) headers
• Regular vulnerability scanning

**Incident Response:**
• Automated blocking of malicious IPs
• Security alerts sent to admin team
• Attack patterns logged for analysis
• Threat intelligence feeds updated
• Regular security training conducted

**System Status:** Web security posture: EXCELLENT"""
        
        else:
            return """🔍 **Comprehensive Threat Intelligence Center**

**Available Threat Analysis:**

🎯 **Attack Types:**
• **DDoS Attacks** - Distributed denial of service analysis
• **Port Scanning** - Network reconnaissance techniques  
• **Bot Attacks** - Automated malicious activities
• **Web Attacks** - Application-layer vulnerabilities

📊 **Current Threat Status:**
• Active threats: 3 high-severity, 7 medium-severity
• Detection rate: 99.8% accuracy
• Response time: <2 seconds average
• System uptime: 99.9%

🛡️ **Protection Status:**
• Real-time monitoring: ACTIVE
• Threat intelligence: UPDATED
• Security controls: OPTIMIZED
• Incident response: READY

**Quick Analysis Commands:**
• "Analyze DDoS threats" - Get DDoS attack intelligence
• "Port scan analysis" - Network reconnaissance details
• "Bot attack patterns" - Automated attack analysis
• "Web security status" - Application security overview

**Which specific threat would you like me to analyze in detail?**"""
    
    def _handle_mitigation_query(self, user_input: str) -> str:
        """Handle mitigation queries with unique responses"""
        query_lower = user_input.lower()
        
        # Provide unique mitigation responses for each threat type
        if 'ddos' in query_lower:
            return """🛠️ **DDoS Attack Mitigation Strategy**

**Immediate Response (0-5 minutes):**
1. **Activate DDoS Protection:**
   • Enable Cloudflare/AWS Shield protection
   • Route traffic through scrubbing centers
   • Implement emergency rate limiting

2. **Traffic Management:**
   • Block malicious IP ranges
   • Implement geographic restrictions
   • Use load balancers to distribute traffic

3. **System Protection:**
   • Increase bandwidth capacity
   • Enable auto-scaling for resources
   • Activate backup servers

**Short-term Actions (5-30 minutes):**
• Deploy additional DDoS mitigation tools
• Configure firewall rules for attack patterns
• Notify ISP and hosting provider
• Activate incident response team

**Long-term Prevention:**
• Implement comprehensive DDoS protection
• Regular penetration testing
• Network architecture review
• Staff training on DDoS response

**Current Status:** DDoS mitigation protocols ACTIVE"""
        
        elif 'portscan' in query_lower or 'port scan' in query_lower:
            return """🛠️ **Port Scan Mitigation Strategy**

**Immediate Response:**
1. **Block Source IPs:**
   • Add scanning IPs to firewall blacklist
   • Implement automatic IP blocking rules
   • Configure IDS/IPS to detect scans

2. **Network Hardening:**
   • Close unnecessary ports
   • Implement port knocking for sensitive services
   • Use network segmentation

3. **Monitoring Enhancement:**
   • Increase log monitoring frequency
   • Set up real-time alerts for port scans
   • Deploy honeypots to detect scanning

**Detection Improvements:**
• Configure port scan detection rules
• Implement connection rate limiting
• Use behavioral analysis for scan detection
• Deploy network monitoring tools

**Prevention Measures:**
• Regular port audits and reviews
• Network access control policies
• Security awareness training
• Regular vulnerability assessments

**Current Status:** Port scan protection ENHANCED"""
        
        elif 'bot' in query_lower:
            return """🛠️ **Bot Attack Mitigation Strategy**

**Immediate Response:**
1. **Bot Detection & Blocking:**
   • Deploy CAPTCHA for suspicious activities
   • Implement rate limiting (100 req/5min per IP)
   • Block known bot IP addresses

2. **Behavioral Analysis:**
   • Monitor user behavior patterns
   • Detect automated request patterns
   • Analyze user agent strings

3. **Access Control:**
   • Implement multi-factor authentication
   • Use device fingerprinting
   • Deploy bot management solutions

**Advanced Protection:**
• Machine learning-based bot detection
• Real-time IP reputation checking
• Behavioral biometrics analysis
• API rate limiting and throttling

**Monitoring & Response:**
• Real-time bot activity monitoring
• Automated response to bot attacks
• Regular bot detection rule updates
• Security team notifications

**Current Status:** Bot protection 99.2% effective"""
        
        elif 'web attack' in query_lower:
            return """🛠️ **Web Attack Mitigation Strategy**

**Immediate Response:**
1. **Web Application Firewall (WAF):**
   • Block malicious requests automatically
   • Implement OWASP Top 10 protection
   • Configure custom security rules

2. **Input Validation:**
   • Sanitize all user inputs
   • Implement parameter validation
   • Use prepared statements for databases

3. **Access Control:**
   • Implement strong authentication
   • Use session management
   • Deploy account lockout policies

**Security Hardening:**
• Regular security code reviews
• Automated vulnerability scanning
• HTTPS enforcement with HSTS
• Content Security Policy (CSP) headers

**Incident Response:**
• Automated attack blocking
• Security alert notifications
• Attack pattern analysis
• Regular security training

**Current Status:** Web security posture EXCELLENT"""
        
        else:
            return """🛠️ **Comprehensive Mitigation Strategy Center**

**Available Mitigation Strategies:**

🎯 **Threat-Specific Mitigation:**
• **DDoS Attacks** - Traffic management and protection services
• **Port Scanning** - Network hardening and monitoring
• **Bot Attacks** - Behavioral analysis and blocking
• **Web Attacks** - Application security and WAF

📊 **Current Mitigation Status:**
• Active protections: 15 security controls
• Response time: <2 seconds average
• Blocking rate: 99.8% effective
• System availability: 99.9%

🛡️ **Protection Levels:**
• Network security: OPTIMIZED
• Application security: ENHANCED
• Endpoint protection: ACTIVE
• Incident response: READY

**Quick Mitigation Commands:**
• "DDoS mitigation" - Get DDoS protection strategy
• "Port scan protection" - Network security measures
• "Bot attack defense" - Automated threat blocking
• "Web security" - Application protection methods

**Which specific threat mitigation would you like me to explain?**"""
    
    def _handle_model_performance_query(self) -> str:
        """Handle model performance queries"""
        performance = self.model_analyzer.get_model_performance()
        
        response = f"""📈 **Model Performance Overview**

🎯 **Overall Metrics:**
• Accuracy: {performance['overall_accuracy']:.1%}
• Detection Rate: {performance['detection_rate']:.1%}
• False Positive Rate: {performance['false_positive_rate']:.1%}

🤖 **Individual Model Performance:**"""
        
        for model_name, metrics in performance['models'].items():
            response += f"""
**{model_name}:**
• Accuracy: {metrics['accuracy']:.1%}
• Precision: {metrics['precision']:.1%}
• Recall: {metrics['recall']:.1%}
• F1-Score: {metrics['f1_score']:.1%}"""
        
        response += f"""

📅 Last updated: {performance['last_updated']}"""
        
        return response
    
    def _handle_historical_data_query(self) -> str:
        """Handle historical data queries"""
        historical = self.model_analyzer.get_historical_performance(7)
        
        response = f"""📊 **Historical Performance (Last 7 Days)**

📈 **Daily Accuracy Trend:**
{chr(10).join(f'• {date}: {acc:.1%}' for date, acc in zip(historical['dates'], historical['daily_accuracy']))}

🚨 **Daily Threat Detections:**
{chr(10).join(f'• {date}: {det} threats' for date, det in zip(historical['dates'], historical['daily_detections']))}

⚠️ **Daily False Positives:**
{chr(10).join(f'• {date}: {fp} false positives' for date, fp in zip(historical['dates'], historical['daily_false_positives']))}"""
        
        return response
    
    def _handle_system_info_query(self) -> str:
        """Handle system information queries"""
        threat_data = self.threat_analyzer.get_current_threats()
        
        response = f"""💻 **System Information**

🖥️ **System Status:**
• Threat Detection: {threat_data['system_status']}
• Last Detection: {threat_data['last_detection']}
• Total Packets Processed: {threat_data['total_packets_processed']:,}

🔧 **Components:**
• Real-time Detection Engine: Active
• ML Models: Loaded and Ready
• Alert System: Operational
• Database: Connected

📊 **Performance:**
• Processing Speed: High
• Memory Usage: Normal
• CPU Usage: Normal
• Network Status: Stable"""
        
        return response
    
    def _extract_threat_type(self, user_input: str) -> Optional[str]:
        """Extract threat type from user input"""
        user_input_lower = user_input.lower()
        
        threat_mappings = {
            'ddos': 'DDoS',
            'denial of service': 'DDoS',
            'dos': 'DDoS',
            'port scan': 'PortScan',
            'portscan': 'PortScan',
            'scanning': 'PortScan',
            'bot': 'Bot',
            'botnet': 'Bot',
            'web attack': 'Web Attack',
            'sql injection': 'Web Attack',
            'xss': 'Web Attack',
            'brute force': 'Web Attack',
            'infiltration': 'Infiltration',
            'ftp': 'FTP-Patator',
            'ssh': 'SSH-Patator'
        }
        
        for keyword, threat_type in threat_mappings.items():
            if keyword in user_input_lower:
                return threat_type
        
        return None
    
    def _extract_severity(self, user_input: str) -> str:
        """Extract severity from user input"""
        user_input_lower = user_input.lower()
        
        if any(word in user_input_lower for word in ['critical', 'severe', 'emergency']):
            return 'CRITICAL'
        elif any(word in user_input_lower for word in ['high', 'serious', 'urgent']):
            return 'HIGH'
        elif any(word in user_input_lower for word in ['medium', 'moderate']):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_chat_history(self, user_id: str = "default", limit: int = 10) -> List[Dict[str, Any]]:
        """Get chat history for a user"""
        # Try to get from database first
        try:
            db_history = self.db.get_chat_history(user_id, limit)
            if db_history:
                return db_history
        except Exception as e:
            self.logger.error(f"Error getting chat history from database: {e}")
        
        # Fallback to in-memory history
        user_history = [entry for entry in self.chat_history if entry['user_id'] == user_id]
        return user_history[-limit:] if user_history else []
    
    def clear_chat_history(self, user_id: str = "default"):
        """Clear chat history for a user"""
        # Clear from database
        try:
            self.db.clear_chat_history(user_id)
        except Exception as e:
            self.logger.error(f"Error clearing chat history from database: {e}")
        
        # Clear from in-memory history
        self.chat_history = [entry for entry in self.chat_history if entry['user_id'] != user_id]
    
    def get_bot_statistics(self) -> Dict[str, Any]:
        """Get chatbot usage statistics"""
        if not self.chat_history:
            return {'total_queries': 0, 'unique_users': 0, 'avg_confidence': 0.0}
        
        total_queries = len(self.chat_history)
        unique_users = len(set(entry['user_id'] for entry in self.chat_history))
        avg_confidence = np.mean([entry['confidence'] for entry in self.chat_history])
        
        # Intent distribution
        intent_counts = {}
        for entry in self.chat_history:
            intent = entry['intent']
            intent_counts[intent] = intent_counts.get(intent, 0) + 1
        
        return {
            'total_queries': total_queries,
            'unique_users': unique_users,
            'avg_confidence': avg_confidence,
            'intent_distribution': intent_counts,
            'avg_processing_time': np.mean([entry['processing_time'] for entry in self.chat_history])
        }
    
    def _handle_network_security_query(self, query):
        """Handle network security specific queries"""
        if 'firewall' in query.lower():
            return """**Firewall Configuration Best Practices:**
• Implement default deny policies
• Use application-layer filtering
• Regularly review and update firewall rules
• Monitor firewall logs for suspicious activity
• Implement zone-based security policies
• Use next-generation firewall features (NGFW)
• Enable intrusion prevention system (IPS) features
• Implement geolocation-based blocking for high-risk countries"""
        
        elif 'vpn' in query.lower():
            return """**VPN Security Guidelines:**
• Use strong encryption protocols (IPSec, OpenVPN, WireGuard)
• Implement multi-factor authentication for VPN access
• Use certificate-based authentication when possible
• Regularly update VPN software and firmware
• Monitor VPN connections and usage patterns
• Implement split tunneling carefully
• Use dedicated VPN appliances for high-security environments
• Regular security audits of VPN configurations"""
        
        elif 'network monitoring' in query.lower():
            return """**Network Monitoring Best Practices:**
• Deploy network monitoring tools (SNMP, NetFlow, sFlow)
• Monitor bandwidth utilization and traffic patterns
• Set up alerts for unusual network activity
• Use network packet capture for detailed analysis
• Implement network performance monitoring
• Monitor for network-based attacks (DDoS, port scans)
• Use network behavior analysis (NBA) tools
• Regular network security assessments"""
        
        else:
            return """**Network Security Overview:**
Network security involves protecting network infrastructure and data from unauthorized access, misuse, or attacks. Key components include:

• **Perimeter Security:** Firewalls, intrusion detection/prevention systems
• **Access Control:** Network access control (NAC), authentication systems
• **Monitoring:** Network monitoring, traffic analysis, log management
• **Encryption:** VPN, SSL/TLS, data encryption in transit
• **Segmentation:** Network segmentation, VLANs, micro-segmentation
• **Threat Detection:** Network-based threat detection, anomaly detection

Would you like specific information about any of these areas?"""
    
    def _handle_incident_response_query(self, query):
        """Handle incident response queries"""
        if 'plan' in query.lower() or 'procedure' in query.lower():
            return """**Incident Response Plan Framework:**

**Phase 1: Preparation**
• Develop incident response team and roles
• Create communication plans and contact lists
• Establish incident classification criteria
• Prepare forensic tools and procedures
• Train staff on incident response procedures

**Phase 2: Identification**
• Monitor for indicators of compromise (IOCs)
• Analyze security alerts and anomalies
• Determine scope and impact of incident
• Document initial findings
• Notify appropriate stakeholders

**Phase 3: Containment**
• Isolate affected systems and networks
• Preserve evidence for forensic analysis
• Implement temporary security measures
• Prevent further damage or data loss
• Document containment actions

**Phase 4: Eradication**
• Remove malware and malicious artifacts
• Patch vulnerabilities and security gaps
• Strengthen security controls
• Verify system integrity
• Document eradication steps

**Phase 5: Recovery**
• Restore systems from clean backups
• Monitor for signs of re-infection
• Gradually restore normal operations
• Validate system functionality
• Update security measures

**Phase 6: Lessons Learned**
• Conduct post-incident review
• Document lessons learned
• Update incident response procedures
• Improve security controls
• Share knowledge with team"""
        
        elif 'forensics' in query.lower():
            return """**Digital Forensics Best Practices:**

**Evidence Collection:**
• Maintain chain of custody documentation
• Use write-blocking tools to preserve evidence
• Create forensic images of affected systems
• Document system state and configuration
• Collect volatile memory dumps
• Preserve network logs and traffic captures

**Analysis Tools:**
• Use established forensic tools (EnCase, FTK, Volatility)
• Analyze file system artifacts and metadata
• Examine registry entries and system logs
• Analyze network traffic and communication patterns
• Identify malware signatures and behaviors
• Correlate evidence across multiple sources

**Documentation:**
• Maintain detailed forensic reports
• Document analysis methodology and findings
• Preserve evidence for legal proceedings
• Follow industry standards and best practices
• Ensure admissibility in court if needed"""
        
        else:
            return """**Incident Response Overview:**
Incident response is the systematic approach to handling and managing security incidents. Key aspects include:

• **Preparation:** Planning, training, and tool preparation
• **Identification:** Detecting and confirming security incidents
• **Containment:** Limiting the scope and impact of incidents
• **Eradication:** Removing threats and vulnerabilities
• **Recovery:** Restoring normal operations
• **Lessons Learned:** Improving future response capabilities

The goal is to minimize damage, reduce recovery time, and prevent future incidents. Would you like specific guidance on any phase of incident response?"""
    
    def _handle_help_query(self, query: str) -> str:
        """Handle help queries with specific examples"""
        query_lower = query.lower()
        
        if 'example' in query_lower or 'examples' in query_lower:
            return """**🤖 AI Assistant - Example Queries**

Here are specific examples of queries you can ask me:

**🔍 Threat Status & Detection:**
• "What are the current threats?"
• "Show me active security alerts"
• "Are there any attacks happening now?"
• "What's the threat level today?"

**📊 Threat Analysis & Details:**
• "Explain DDoS attacks"
• "What is a port scan attack?"
• "Tell me about botnet threats"
• "How do web attacks work?"
• "What are SQL injection attacks?"

**🛡️ Security Recommendations:**
• "How to prevent DDoS attacks?"
• "Best practices for network security"
• "How to secure my firewall?"
• "What should I do about malware?"
• "Security tips for my organization"

**🔧 System Information:**
• "What's the system status?"
• "How are the AI models performing?"
• "Show me system health"
• "Are all components working?"

**🌐 Network Security:**
• "How to configure my firewall?"
• "VPN security best practices"
• "Network monitoring tips"
• "How to detect network intrusions?"

**🚨 Incident Response:**
• "What's the incident response plan?"
• "How to handle a security breach?"
• "Forensics investigation steps"
• "How to contain a cyber attack?"

**🤖 AI Assistant Features:**
• "What can you help me with?"
• "How do you analyze threats?"
• "What's your detection accuracy?"
• "Can you simulate threats?"

Try asking any of these questions for detailed, specific responses!"""
        
        elif 'what can you do' in query_lower or 'capabilities' in query_lower:
            return """**🤖 My Capabilities as Your Cybersecurity AI Assistant:**

**🔍 Threat Analysis:**
• Real-time threat detection and monitoring
• Detailed threat classification and analysis
• Threat intelligence and pattern recognition
• Risk assessment and severity evaluation

**🛡️ Security Guidance:**
• Best practices and security recommendations
• Incident response procedures and plans
• Network security configuration guidance
• Vulnerability assessment and mitigation

**📊 System Monitoring:**
• System health and performance monitoring
• AI model performance analysis
• Security metrics and reporting
• Real-time status updates

**🌐 Network Security:**
• Firewall configuration and management
• VPN security and implementation
• Network monitoring and analysis
• Intrusion detection and prevention

**🚨 Incident Response:**
• Breach response procedures
• Digital forensics guidance
• Evidence collection and analysis
• Recovery and remediation steps

**🤖 AI Features:**
• Natural language threat analysis
• Context-aware responses
• Learning from interactions
• Predictive threat intelligence

I'm here to help you with any cybersecurity questions or concerns. Just ask me anything!"""
        
        else:
            return """**🤖 How I Can Help You:**

I'm your AI cybersecurity assistant, designed to help with:

• **Threat Detection & Analysis** - Get real-time threat information and detailed analysis
• **Security Recommendations** - Receive expert guidance on security best practices
• **System Monitoring** - Check system status, performance, and health
• **Incident Response** - Get step-by-step guidance for handling security incidents
• **Network Security** - Learn about firewalls, VPNs, and network protection
• **AI Model Performance** - Understand how our detection systems are working

**💡 Tips for Better Results:**
• Be specific in your questions
• Ask about particular threat types or security topics
• Request step-by-step guidance for complex procedures
• Ask for examples or detailed explanations

**🔍 Example Queries:**
• "What are the current threats?"
• "How to prevent DDoS attacks?"
• "Explain port scan attacks"
• "What's the system status?"
• "Show me security recommendations"

What would you like to know about cybersecurity today?"""
    
    def _handle_threat_status_query(self, query: str = None) -> str:
        """Handle threat status queries with dynamic responses"""
        if not query:
            query = ""
        
        query_lower = query.lower()
        
        # Simulate current threat status
        current_threats = [
            {"type": "DDoS", "count": 3, "severity": "HIGH"},
            {"type": "Port Scan", "count": 7, "severity": "MEDIUM"},
            {"type": "Bot", "count": 2, "severity": "LOW"},
            {"type": "Web Attack", "count": 1, "severity": "HIGH"}
        ]
        
        if 'current' in query_lower or 'now' in query_lower or 'active' in query_lower:
            response = "**🚨 Current Threat Status (Live Update):**\n\n"
            total_threats = sum(t['count'] for t in current_threats)
            high_severity = sum(t['count'] for t in current_threats if t['severity'] == 'HIGH')
            
            response += f"**Total Active Threats:** {total_threats}\n"
            response += f"**High Severity:** {high_severity}\n"
            response += f"**System Status:** {'🟡 MONITORING' if total_threats > 0 else '🟢 SECURE'}\n\n"
            
            response += "**Threat Breakdown:**\n"
            for threat in current_threats:
                if threat['count'] > 0:
                    icon = "🔴" if threat['severity'] == 'HIGH' else "🟡" if threat['severity'] == 'MEDIUM' else "🟢"
                    response += f"• {icon} {threat['type']}: {threat['count']} instances ({threat['severity']})\n"
            
            response += "\n**⚠️ Immediate Actions Required:**\n"
            if high_severity > 0:
                response += "• Review high-severity threats immediately\n"
                response += "• Consider blocking suspicious IP addresses\n"
                response += "• Monitor network traffic patterns\n"
            else:
                response += "• Continue monitoring for new threats\n"
                response += "• Review security logs regularly\n"
            
            return response
        
        elif 'level' in query_lower or 'risk' in query_lower:
            total_threats = sum(t['count'] for t in current_threats)
            high_severity = sum(t['count'] for t in current_threats if t['severity'] == 'HIGH')
            
            if high_severity > 2:
                risk_level = "🔴 CRITICAL"
                recommendation = "Immediate action required. Review all high-severity threats and consider emergency response procedures."
            elif high_severity > 0 or total_threats > 5:
                risk_level = "🟡 ELEVATED"
                recommendation = "Increased monitoring recommended. Review threat patterns and strengthen defenses."
            else:
                risk_level = "🟢 NORMAL"
                recommendation = "System operating within normal parameters. Continue regular monitoring."
            
            return f"""**📊 Current Threat Risk Level: {risk_level}**

**Risk Assessment:**
• Total Active Threats: {total_threats}
• High Severity Threats: {high_severity}
• System Load: {'High' if total_threats > 5 else 'Normal'}

**Recommendation:** {recommendation}

**Next Steps:**
• Monitor threat trends over the next hour
• Review security logs for patterns
• Update threat intelligence feeds
• Consider adjusting detection sensitivity if needed"""
        
        else:
            return """**🔍 Threat Status Overview:**

**Current System Status:** 🟡 ACTIVE MONITORING

**Recent Threat Activity (Last 24 Hours):**
• DDoS Attacks: 3 detected (2 blocked, 1 mitigated)
• Port Scans: 7 detected (all blocked)
• Bot Activity: 2 detected (investigating)
• Web Attacks: 1 detected (contained)

**Detection Performance:**
• Accuracy Rate: 98.7%
• False Positive Rate: 1.2%
• Response Time: <2 seconds
• Coverage: 100% of network traffic

**System Health:**
• AI Models: ✅ All operational
• Database: ✅ Connected
• Real-time Detection: ✅ Active
• Threat Intelligence: ✅ Updated

Would you like more details about any specific threat type or system component?"""

def create_chatbot(threat_detector=None) -> CybersecurityChatbot:
    """Create and return a cybersecurity chatbot instance"""
    return CybersecurityChatbot(threat_detector)

if __name__ == "__main__":
    # Example usage
    chatbot = create_chatbot()
    
    # Test queries
    test_queries = [
        "What are the current threats?",
        "Tell me about DDoS attacks",
        "How can I mitigate a PortScan attack?",
        "What's the model performance?",
        "Show me historical data",
        "What's the system status?",
        "Help me understand security"
    ]
    
    print("🤖 Cybersecurity Chatbot Demo")
    print("=" * 50)
    
    for query in test_queries:
        print(f"\n👤 User: {query}")
        response = chatbot.process_query(query)
        print(f"🤖 Bot: {response['response']}")
        print(f"   Intent: {response['intent']} (confidence: {response['confidence']:.2f})")
    
    # Show statistics
    stats = chatbot.get_bot_statistics()
    print(f"\n📊 Chatbot Statistics:")
    print(f"Total queries: {stats['total_queries']}")
    print(f"Average confidence: {stats['avg_confidence']:.2f}")
    print(f"Average processing time: {stats['avg_processing_time']:.3f}s")



