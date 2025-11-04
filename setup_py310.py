"""
Python 3.10.11 Setup Script for Cybersecurity AI System

This script sets up the cybersecurity system specifically for Python 3.10.11
with optimized package versions and configurations.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Verify Python 3.10.11"""
    current_version = sys.version_info
    if current_version[:2] != (3, 10):
        print(f"❌ This script is designed for Python 3.10.11")
        print(f"Current version: {current_version.major}.{current_version.minor}.{current_version.micro}")
        print("Please use the appropriate setup script for your Python version")
        return False
    
    print(f"✅ Python {current_version.major}.{current_version.minor}.{current_version.micro} detected")
    return True

def upgrade_pip():
    """Upgrade pip to latest version"""
    print("📦 Upgrading pip...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                      check=True, capture_output=True)
        print("✅ Pip upgraded successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to upgrade pip: {e}")
        return False

def install_build_tools():
    """Install build tools for Python 3.10.11"""
    print("🔧 Installing build tools...")
    
    build_packages = [
        "setuptools>=65.0.0",
        "wheel>=0.37.0",
        "build>=0.8.0"
    ]
    
    try:
        for package in build_packages:
            subprocess.run([sys.executable, "-m", "pip", "install", package], 
                          check=True, capture_output=True)
        print("✅ Build tools installed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install build tools: {e}")
        return False

def install_core_packages():
    """Install core packages with Python 3.10.11 optimizations"""
    print("📚 Installing core packages...")
    
    # Install packages in order of dependency
    package_groups = [
        # Core scientific computing
        ["numpy==1.24.4", "pandas==2.0.3"],
        
        # Machine learning
        ["scikit-learn==1.3.2", "joblib==1.3.2"],
        
        # Deep learning
        ["tensorflow==2.13.0"],
        
        # XGBoost (may need special handling)
        ["xgboost==1.7.6"],
        
        # Visualization
        ["matplotlib==3.7.2", "seaborn==0.12.2", "plotly==5.15.0"],
        
        # Web framework
        ["flask==2.3.3", "flask-cors==4.0.0", "flask-socketio==5.3.6"],
        
        # Utilities
        ["python-dotenv==1.0.0", "requests==2.31.0", "tqdm==4.65.0"],
        
        # Security
        ["cryptography==41.0.4", "pyjwt==2.8.0"],
        
        # Optional packages
        ["redis==4.6.0", "kafka-python==2.0.2"],
        
        # NLP (optional)
        ["nltk==3.8.1", "transformers==4.32.1"],
        
        # Testing
        ["pytest==7.4.0", "pytest-cov==4.1.0"]
    ]
    
    for group in package_groups:
        print(f"Installing: {', '.join(group)}")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install"] + group, 
                          check=True, capture_output=True)
            print(f"✅ Installed: {', '.join(group)}")
        except subprocess.CalledProcessError as e:
            print(f"⚠️  Warning: Some packages in {group} may have failed")
            print("Continuing with installation...")
    
    return True

def install_torch():
    """Install PyTorch with Python 3.10.11 optimizations"""
    print("🔥 Installing PyTorch...")
    
    # PyTorch installation command for Python 3.10.11
    torch_cmd = [
        sys.executable, "-m", "pip", "install", 
        "torch==2.0.1", "torchvision==0.15.2"
    ]
    
    try:
        subprocess.run(torch_cmd, check=True, capture_output=True)
        print("✅ PyTorch installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install PyTorch: {e}")
        print("💡 You may need to install PyTorch manually from https://pytorch.org/")
        return False

def verify_installation():
    """Verify that all packages are installed correctly"""
    print("🔍 Verifying installation...")
    
    test_imports = [
        ("numpy", "import numpy as np; print(f'NumPy: {np.__version__}')"),
        ("pandas", "import pandas as pd; print(f'Pandas: {pd.__version__}')"),
        ("sklearn", "import sklearn; print(f'Scikit-learn: {sklearn.__version__}')"),
        ("tensorflow", "import tensorflow as tf; print(f'TensorFlow: {tf.__version__}')"),
        ("flask", "import flask; print(f'Flask: {flask.__version__}')"),
        ("xgboost", "import xgboost as xgb; print(f'XGBoost: {xgb.__version__}')")
    ]
    
    success_count = 0
    for name, test_code in test_imports:
        try:
            exec(test_code)
            print(f"✅ {name} - OK")
            success_count += 1
        except Exception as e:
            print(f"❌ {name} - Failed: {e}")
    
    print(f"\n📊 Installation Summary: {success_count}/{len(test_imports)} packages working")
    return success_count == len(test_imports)

def create_environment_file():
    """Create .env file with Python 3.10.11 optimizations"""
    print("⚙️  Creating environment configuration...")
    
    env_content = """# Python 3.10.11 Optimized Configuration
PYTHON_VERSION=3.10.11
FLASK_ENV=development
FLASK_DEBUG=True

# TensorFlow optimizations for Python 3.10.11
TF_CPP_MIN_LOG_LEVEL=2
TF_ENABLE_ONEDNN_OPTS=1

# NumPy optimizations
NUMPY_OPTIMIZATION=1

# Memory optimization
PYTHONHASHSEED=0

# Security
SECRET_KEY=cybersecurity_ai_system_secret_key_2023
"""
    
    env_file = Path(".env")
    with open(env_file, 'w') as f:
        f.write(env_content)
    
    print("✅ Environment file created")

def main():
    """Main setup function for Python 3.10.11"""
    print("🛡️ Cybersecurity AI System - Python 3.10.11 Setup")
    print("=" * 60)
    
    # Check Python version
    if not check_python_version():
        return 1
    
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Architecture: {platform.machine()}")
    
    try:
        # Upgrade pip
        if not upgrade_pip():
            print("⚠️  Continuing without pip upgrade...")
        
        # Install build tools
        if not install_build_tools():
            print("⚠️  Continuing without build tools...")
        
        # Install core packages
        if not install_core_packages():
            print("❌ Core package installation failed")
            return 1
        
        # Install PyTorch
        install_torch()  # Non-critical, continue if fails
        
        # Create environment file
        create_environment_file()
        
        # Verify installation
        if verify_installation():
            print("\n🎉 Setup completed successfully!")
            print("✅ All packages are installed and working")
            print("\n🚀 Next steps:")
            print("1. Download CICIDS2017 dataset to data/raw/")
            print("2. Run: python main.py --mode demo")
            print("3. Open: http://localhost:5000")
        else:
            print("\n⚠️  Setup completed with warnings")
            print("Some packages may need manual installation")
            print("Check the output above for specific issues")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n❌ Setup interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

