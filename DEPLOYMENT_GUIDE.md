# 🚀 Cybersecurity AI System - Deployment Guide

## 📋 Table of Contents
1. [System Overview](#system-overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Database Setup](#database-setup)
6. [Running the System](#running-the-system)
7. [Deployment Options](#deployment-options)
8. [Security Considerations](#security-considerations)
9. [Monitoring & Maintenance](#monitoring--maintenance)
10. [Troubleshooting](#troubleshooting)

## 🎯 System Overview

The Cybersecurity AI System is a comprehensive threat detection platform that combines:
- **AI-Powered Threat Detection**: Multiple ML/DL models for real-time threat analysis
- **Interactive Dashboard**: Web-based interface for monitoring and management
- **Intelligent Chatbot**: AI assistant for security queries and recommendations
- **Real-time Monitoring**: Live threat detection and alerting system
- **Database Integration**: SQLite database for data persistence and history

## 🔧 Prerequisites

### System Requirements
- **Operating System**: Windows 10/11, macOS 10.15+, or Linux (Ubuntu 18.04+)
- **Python**: 3.8+ (Recommended: Python 3.10.11)
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 10GB free space minimum
- **Network**: Internet connection for initial setup

### Software Dependencies
- Python 3.8+
- pip (latest version)
- Git (for cloning repository)

## 📦 Installation

### Method 1: Quick Setup (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd cybersecurity-ai-system

# Run the setup script
python setup_py310.py

# Or install dependencies manually
pip install -r requirements-py310.txt
```

### Method 2: Manual Installation

```bash
# Clone the repository
git clone <repository-url>
cd cybersecurity-ai-system

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create necessary directories
python -c "from config.config import create_directories; create_directories()"
```

### Method 3: Docker Installation

```bash
# Build Docker image
docker build -t cybersecurity-ai-system .

# Run container
docker run -p 5000:5000 -v $(pwd)/data:/app/data cybersecurity-ai-system
```

## ⚙️ Configuration

### 1. Database Configuration

The system uses SQLite by default. Database settings are in `config/config.py`:

```python
DATABASE_CONFIG = {
    'sqlite_path': BASE_DIR / 'cybersecurity_system.db',
    'threats_table': 'threats',
    'alerts_table': 'alerts',
    'chat_logs_table': 'chat_logs',
    'model_metrics_table': 'model_metrics'
}
```

### 2. Web Application Configuration

Update `config/config.py` for web settings:

```python
WEB_CONFIG = {
    'host': '0.0.0.0',  # Change to '127.0.0.1' for localhost only
    'port': 5000,       # Change port if needed
    'debug': False,     # Set to True for development
    'secret_key': 'your-secret-key-here'  # Change this!
}
```

### 3. Security Configuration

Update security settings in `config/config.py`:

```python
SECURITY_CONFIG = {
    'jwt_secret': 'your-jwt-secret-here',
    'jwt_expiration': 3600,
    'password_min_length': 8,
    'max_login_attempts': 5,
    'lockout_duration': 300,
    'encryption_key': b'your-32-byte-encryption-key-here'
}
```

## 🗄️ Database Setup

### Initialize Database

```bash
# Initialize database with demo data
python -c "from utils.database import initialize_database; initialize_database()"
```

### Database Tables

The system creates the following tables:
- **users**: User accounts and authentication
- **chat_history**: Chatbot conversation history
- **threats**: Detected threats and incidents
- **alerts**: Security alerts and notifications
- **model_metrics**: AI model performance metrics
- **system_logs**: System activity logs

### Demo User

A demo user is automatically created:
- **Email**: demo@cybersecurity.com
- **Password**: demo123
- **Role**: security_analyst

## 🚀 Running the System

### Development Mode

```bash
# Run in demo mode (recommended for testing)
python main.py --mode demo

# Run full system
python main.py --mode full

# Run with custom port
python main.py --mode full --port 8080
```

### Production Mode

```bash
# Run with Gunicorn (Linux/macOS)
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 web.app:app

# Run with Waitress (Windows)
pip install waitress
waitress-serve --host=0.0.0.0 --port=5000 web.app:app
```

### Access the System

1. Open your web browser
2. Navigate to `http://localhost:5000`
3. Login with demo credentials or create a new account

## 🌐 Deployment Options

### 1. Local Development

```bash
# Simple local setup
python main.py --mode demo --host 127.0.0.1 --port 5000
```

### 2. Network Deployment

```bash
# Allow network access
python main.py --mode full --host 0.0.0.0 --port 5000
```

### 3. Docker Deployment

```bash
# Build and run with Docker
docker build -t cybersecurity-ai-system .
docker run -d -p 5000:5000 --name cybersecurity-system cybersecurity-ai-system
```

### 4. Cloud Deployment

#### AWS EC2
```bash
# Install on EC2 instance
sudo apt update
sudo apt install python3 python3-pip git
git clone <repository-url>
cd cybersecurity-ai-system
pip3 install -r requirements.txt
python3 main.py --mode full --host 0.0.0.0 --port 80
```

#### Azure App Service
```bash
# Deploy to Azure
az webapp up --name cybersecurity-ai-system --resource-group myResourceGroup
```

#### Google Cloud Platform
```bash
# Deploy to GCP
gcloud app deploy
```

## 🔒 Security Considerations

### 1. Authentication
- Change default passwords
- Use strong, unique passwords
- Enable two-factor authentication (if implemented)
- Regular password updates

### 2. Network Security
- Use HTTPS in production
- Configure firewall rules
- Limit network access
- Use VPN for remote access

### 3. Data Protection
- Encrypt sensitive data
- Regular backups
- Access control
- Audit logging

### 4. System Security
- Keep system updated
- Monitor logs
- Regular security scans
- Incident response plan

## 📊 Monitoring & Maintenance

### 1. System Monitoring

```bash
# Check system status
curl http://localhost:5000/api/status

# View logs
tail -f logs/cybersecurity_system.log

# Monitor database
sqlite3 cybersecurity_system.db "SELECT COUNT(*) FROM threats;"
```

### 2. Performance Monitoring

- Monitor CPU and memory usage
- Check disk space
- Monitor network traffic
- Review error logs

### 3. Regular Maintenance

```bash
# Clean up old data (run weekly)
python -c "from utils.database import get_database; get_database().cleanup_old_data(30)"

# Backup database
cp cybersecurity_system.db backup_$(date +%Y%m%d).db

# Update dependencies
pip install --upgrade -r requirements.txt
```

### 4. Health Checks

```bash
# Check database connectivity
python -c "from utils.database import get_database; print('DB OK' if get_database().get_connection() else 'DB Error')"

# Check web application
curl -f http://localhost:5000/api/status || echo "Web app down"
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. Port Already in Use
```bash
# Find process using port 5000
netstat -ano | findstr :5000  # Windows
lsof -i :5000                 # macOS/Linux

# Kill process or use different port
python main.py --port 8080
```

#### 2. Database Connection Error
```bash
# Check database file permissions
ls -la cybersecurity_system.db

# Recreate database
rm cybersecurity_system.db
python -c "from utils.database import initialize_database; initialize_database()"
```

#### 3. Module Import Errors
```bash
# Check Python path
python -c "import sys; print(sys.path)"

# Reinstall dependencies
pip install --force-reinstall -r requirements.txt
```

#### 4. Memory Issues
```bash
# Monitor memory usage
top -p $(pgrep python)

# Reduce model complexity in config
# Or increase system memory
```

### Log Analysis

```bash
# View recent errors
grep "ERROR" logs/cybersecurity_system.log | tail -20

# Monitor real-time logs
tail -f logs/cybersecurity_system.log | grep -E "(ERROR|WARNING)"
```

### Performance Issues

1. **Slow Response Times**
   - Check database performance
   - Monitor CPU usage
   - Review model complexity

2. **High Memory Usage**
   - Reduce batch sizes
   - Clear old data
   - Optimize models

3. **Database Locks**
   - Check for long-running queries
   - Optimize database indexes
   - Consider connection pooling

## 📞 Support

### Getting Help

1. **Check Documentation**: Review this guide and code comments
2. **View Logs**: Check system logs for error messages
3. **Test Components**: Run individual components to isolate issues
4. **Community Support**: Check project repository for issues and discussions

### Reporting Issues

When reporting issues, include:
- Operating system and version
- Python version
- Error messages and logs
- Steps to reproduce
- System configuration

### Feature Requests

For new features or improvements:
- Describe the use case
- Provide examples
- Consider implementation complexity
- Check existing issues first

## 🔄 Updates and Upgrades

### Updating the System

```bash
# Backup current installation
cp -r cybersecurity-ai-system cybersecurity-ai-system-backup

# Pull latest changes
git pull origin main

# Update dependencies
pip install --upgrade -r requirements.txt

# Run database migrations (if any)
python -c "from utils.database import initialize_database; initialize_database()"
```

### Version Compatibility

- Check Python version compatibility
- Review dependency updates
- Test in development environment first
- Plan for downtime during updates

---

## 🎉 Conclusion

This deployment guide provides comprehensive instructions for setting up and maintaining the Cybersecurity AI System. The system is designed to be robust, scalable, and easy to deploy across different environments.

For additional support or questions, please refer to the project documentation or contact the development team.

**Happy Securing! 🛡️**

