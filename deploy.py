"""
Deployment Script for Cybersecurity AI System

This script handles deployment of the cybersecurity threat detection system
to various environments including local, cloud, and containerized deployments.
"""

import os
import sys
import subprocess
import argparse
import json
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
import warnings
warnings.filterwarnings('ignore')

class DeploymentManager:
    """Manages deployment of the cybersecurity system"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.deployment_config = self._load_deployment_config()
    
    def _load_deployment_config(self) -> Dict[str, Any]:
        """Load deployment configuration"""
        config_path = self.project_root / "config" / "deployment.json"
        
        default_config = {
            "environments": {
                "local": {
                    "host": "localhost",
                    "port": 5000,
                    "debug": True,
                    "workers": 1
                },
                "production": {
                    "host": "0.0.0.0",
                    "port": 80,
                    "debug": False,
                    "workers": 4
                },
                "docker": {
                    "image_name": "cybersecurity-ai-system",
                    "container_name": "cybersecurity-system",
                    "port_mapping": "5000:5000"
                }
            },
            "services": {
                "redis": {
                    "enabled": True,
                    "host": "localhost",
                    "port": 6379
                },
                "kafka": {
                    "enabled": True,
                    "bootstrap_servers": ["localhost:9092"]
                }
            }
        }
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Could not load deployment config: {e}")
        
        return default_config
    
    def check_python_version(self) -> bool:
        """Check Python version compatibility"""
        print("🐍 Checking Python version...")
        
        current_version = sys.version_info[:2]
        print(f"Current Python: {current_version[0]}.{current_version[1]}")
        
        if current_version < (3, 8):
            print("❌ Python 3.8+ required")
            return False
        elif current_version == (3, 10):
            print("✅ Python 3.10.11 is optimal")
        elif current_version > (3, 11):
            print("⚠️  Python 3.11+ may have compatibility issues")
        else:
            print("✅ Python version is compatible")
        
        return True
    
    def check_dependencies(self) -> bool:
        """Check if all required dependencies are installed"""
        print("🔍 Checking dependencies...")
        
        # Check Python version first
        if not self.check_python_version():
            return False
        
        required_packages = [
            'numpy', 'pandas', 'sklearn', 'xgboost', 'tensorflow',
            'flask', 'flask_socketio', 'flask_cors'
        ]
        
        optional_packages = [
            'redis', 'kafka', 'transformers', 'nltk'
        ]
        
        missing_packages = []
        
        print("Critical packages:")
        for package in required_packages:
            try:
                __import__(package)
                print(f"✅ {package}")
            except ImportError:
                missing_packages.append(package)
                print(f"❌ {package}")
        
        print("Optional packages:")
        for package in optional_packages:
            try:
                __import__(package)
                print(f"✅ {package}")
            except ImportError:
                print(f"⚠️  {package} (optional)")
        
        if missing_packages:
            print(f"\n⚠️  Missing critical packages: {', '.join(missing_packages)}")
            current_version = sys.version_info[:2]
            if current_version == (3, 10):
                print("Run: pip install -r requirements-py310.txt")
            else:
                print("Run: pip install -r requirements.txt")
            return False
        
        print("✅ All critical dependencies are installed")
        return True
    
    def setup_environment(self, environment: str = "local") -> bool:
        """Setup deployment environment"""
        print(f"🔧 Setting up {environment} environment...")
        
        try:
            # Create necessary directories
            directories = [
                "data/raw",
                "data/processed",
                "models/saved",
                "models/metrics",
                "logs",
                "web/static/uploads"
            ]
            
            for directory in directories:
                dir_path = self.project_root / directory
                dir_path.mkdir(parents=True, exist_ok=True)
                print(f"✅ Created directory: {directory}")
            
            # Set environment variables
            env_vars = {
                "FLASK_ENV": "development" if environment == "local" else "production",
                "PYTHONPATH": str(self.project_root)
            }
            
            for key, value in env_vars.items():
                os.environ[key] = value
                print(f"✅ Set environment variable: {key}={value}")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to setup environment: {e}")
            return False
    
    def install_dependencies(self) -> bool:
        """Install Python dependencies"""
        print("📦 Installing dependencies...")
        
        try:
            # Install from requirements.txt
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Dependencies installed successfully")
                return True
            else:
                print(f"❌ Failed to install dependencies: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error installing dependencies: {e}")
            return False
    
    def build_docker_image(self) -> bool:
        """Build Docker image for the system"""
        print("🐳 Building Docker image...")
        
        try:
            # Create Dockerfile if it doesn't exist
            dockerfile_path = self.project_root / "Dockerfile"
            if not dockerfile_path.exists():
                self._create_dockerfile()
            
            # Build Docker image
            image_name = self.deployment_config["environments"]["docker"]["image_name"]
            result = subprocess.run([
                "docker", "build", "-t", image_name, "."
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ Docker image built successfully: {image_name}")
                return True
            else:
                print(f"❌ Failed to build Docker image: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error building Docker image: {e}")
            return False
    
    def _create_dockerfile(self):
        """Create Dockerfile for the application"""
        dockerfile_content = """
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    g++ \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p data/raw data/processed models/saved models/metrics logs

# Expose port
EXPOSE 5000

# Set environment variables
ENV FLASK_ENV=production
ENV PYTHONPATH=/app

# Run the application
CMD ["python", "main.py", "--mode", "full", "--host", "0.0.0.0", "--port", "5000"]
"""
        
        dockerfile_path = self.project_root / "Dockerfile"
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile_content.strip())
        
        print("✅ Created Dockerfile")
    
    def run_docker_container(self) -> bool:
        """Run Docker container"""
        print("🚀 Running Docker container...")
        
        try:
            config = self.deployment_config["environments"]["docker"]
            image_name = config["image_name"]
            container_name = config["container_name"]
            port_mapping = config["port_mapping"]
            
            # Stop existing container if running
            subprocess.run(["docker", "stop", container_name], capture_output=True)
            subprocess.run(["docker", "rm", container_name], capture_output=True)
            
            # Run new container
            result = subprocess.run([
                "docker", "run", "-d",
                "--name", container_name,
                "-p", port_mapping,
                "-v", f"{self.project_root}/data:/app/data",
                "-v", f"{self.project_root}/models:/app/models",
                image_name
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ Docker container started: {container_name}")
                print(f"🌐 Application available at: http://localhost:5000")
                return True
            else:
                print(f"❌ Failed to run Docker container: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error running Docker container: {e}")
            return False
    
    def deploy_local(self) -> bool:
        """Deploy to local environment"""
        print("🏠 Deploying to local environment...")
        
        try:
            # Check dependencies
            if not self.check_dependencies():
                if not self.install_dependencies():
                    return False
            
            # Setup environment
            if not self.setup_environment("local"):
                return False
            
            # Run the application
            print("🚀 Starting local deployment...")
            result = subprocess.run([
                sys.executable, "main.py", "--mode", "full", "--host", "localhost", "--port", "5000"
            ])
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"❌ Local deployment failed: {e}")
            return False
    
    def deploy_production(self) -> bool:
        """Deploy to production environment"""
        print("🏭 Deploying to production environment...")
        
        try:
            # Check dependencies
            if not self.check_dependencies():
                if not self.install_dependencies():
                    return False
            
            # Setup environment
            if not self.setup_environment("production"):
                return False
            
            # Use gunicorn for production
            print("🚀 Starting production deployment with gunicorn...")
            result = subprocess.run([
                "gunicorn", "--bind", "0.0.0.0:80",
                "--workers", "4",
                "--worker-class", "eventlet",
                "--worker-connections", "1000",
                "web.app:create_web_app().app"
            ])
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"❌ Production deployment failed: {e}")
            return False
    
    def deploy_docker(self) -> bool:
        """Deploy using Docker"""
        print("🐳 Deploying with Docker...")
        
        try:
            # Build Docker image
            if not self.build_docker_image():
                return False
            
            # Run Docker container
            if not self.run_docker_container():
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ Docker deployment failed: {e}")
            return False
    
    def run_tests(self) -> bool:
        """Run system tests"""
        print("🧪 Running system tests...")
        
        try:
            result = subprocess.run([
                sys.executable, "-m", "pytest", "tests/", "-v"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ All tests passed")
                return True
            else:
                print(f"❌ Tests failed: {result.stdout}")
                return False
                
        except Exception as e:
            print(f"❌ Error running tests: {e}")
            return False
    
    def generate_documentation(self) -> bool:
        """Generate system documentation"""
        print("📚 Generating documentation...")
        
        try:
            # Create docs directory
            docs_dir = self.project_root / "docs"
            docs_dir.mkdir(exist_ok=True)
            
            # Generate API documentation
            self._generate_api_docs()
            
            # Generate user manual
            self._generate_user_manual()
            
            # Generate deployment guide
            self._generate_deployment_guide()
            
            print("✅ Documentation generated successfully")
            return True
            
        except Exception as e:
            print(f"❌ Error generating documentation: {e}")
            return False
    
    def _generate_api_docs(self):
        """Generate API documentation"""
        api_docs = """
# API Documentation

## Endpoints

### System Status
- **GET** `/api/status` - Get system status
- **GET** `/api/threats` - Get current threats
- **GET** `/api/models/performance` - Get model performance

### Chatbot
- **POST** `/api/chat` - Send message to chatbot

### Real-time Controls
- **POST** `/api/realtime/start` - Start real-time detection
- **POST** `/api/realtime/stop` - Stop real-time detection
- **POST** `/api/realtime/simulate` - Simulate network traffic

## WebSocket Events

### Client to Server
- `join_room` - Join a room for real-time updates
- `chat_message` - Send chat message
- `request_threats` - Request threat data

### Server to Client
- `status` - System status updates
- `realtime_update` - Real-time data updates
- `threats_update` - Threat data updates
- `chat_response` - Chatbot responses
"""
        
        docs_path = self.project_root / "docs" / "API.md"
        with open(docs_path, 'w') as f:
            f.write(api_docs.strip())
    
    def _generate_user_manual(self):
        """Generate user manual"""
        user_manual = """
# User Manual

## Getting Started

1. **Installation**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the System**
   ```bash
   python main.py
   ```

3. **Access Web Interface**
   Open your browser and go to `http://localhost:5000`

## Features

### Dashboard
- Real-time threat monitoring
- System status overview
- Performance metrics

### AI Assistant
- Interactive chatbot for security queries
- Threat analysis and recommendations
- Model performance insights

### Threat Monitoring
- Live threat detection
- Alert management
- Historical data analysis

### Model Performance
- AI model metrics
- Performance comparison
- Training statistics

## Usage Examples

### Chatbot Queries
- "What are the current threats?"
- "How can I mitigate a DDoS attack?"
- "Show me model performance"
- "What's the system status?"

### Real-time Controls
- Start/stop threat detection
- Simulate network traffic
- View live alerts
"""
        
        docs_path = self.project_root / "docs" / "USER_MANUAL.md"
        with open(docs_path, 'w') as f:
            f.write(user_manual.strip())
    
    def _generate_deployment_guide(self):
        """Generate deployment guide"""
        deployment_guide = """
# Deployment Guide

## Local Deployment

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run System**
   ```bash
   python main.py --mode full
   ```

## Docker Deployment

1. **Build Image**
   ```bash
   docker build -t cybersecurity-ai-system .
   ```

2. **Run Container**
   ```bash
   docker run -p 5000:5000 cybersecurity-ai-system
   ```

## Production Deployment

1. **Use Gunicorn**
   ```bash
   gunicorn --bind 0.0.0.0:80 --workers 4 web.app:create_web_app().app
   ```

2. **Use Nginx (Optional)**
   Configure Nginx as reverse proxy

## Cloud Deployment

### AWS
- Use EC2 instances
- Configure security groups
- Use RDS for database

### Azure
- Use App Service
- Configure Application Gateway
- Use Azure Database

### Google Cloud
- Use Compute Engine
- Configure Load Balancer
- Use Cloud SQL
"""
        
        docs_path = self.project_root / "docs" / "DEPLOYMENT.md"
        with open(docs_path, 'w') as f:
            f.write(deployment_guide.strip())

def main():
    """Main deployment function"""
    parser = argparse.ArgumentParser(description='Deploy Cybersecurity AI System')
    parser.add_argument('--environment', choices=['local', 'production', 'docker'], 
                       default='local', help='Deployment environment')
    parser.add_argument('--test', action='store_true', help='Run tests before deployment')
    parser.add_argument('--docs', action='store_true', help='Generate documentation')
    parser.add_argument('--skip-deps', action='store_true', help='Skip dependency check')
    
    args = parser.parse_args()
    
    print("🚀 Cybersecurity AI System Deployment")
    print("=" * 50)
    
    # Create deployment manager
    deployer = DeploymentManager()
    
    try:
        # Run tests if requested
        if args.test:
            if not deployer.run_tests():
                print("❌ Tests failed. Deployment aborted.")
                return 1
        
        # Generate documentation if requested
        if args.docs:
            deployer.generate_documentation()
        
        # Deploy based on environment
        success = False
        
        if args.environment == 'local':
            success = deployer.deploy_local()
        elif args.environment == 'production':
            success = deployer.deploy_production()
        elif args.environment == 'docker':
            success = deployer.deploy_docker()
        
        if success:
            print(f"\n✅ Deployment to {args.environment} completed successfully!")
            print("🌐 System is now running and accessible")
        else:
            print(f"\n❌ Deployment to {args.environment} failed!")
            return 1
        
        return 0
        
    except Exception as e:
        print(f"❌ Deployment error: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)


