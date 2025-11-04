"""
Python Version Compatibility Checker

This script checks if the current Python version is compatible with the
cybersecurity AI system and provides installation guidance.
"""

import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Check Python version compatibility"""
    print("🐍 Python Version Compatibility Check")
    print("=" * 50)
    
    current_version = sys.version_info
    print(f"Current Python Version: {current_version.major}.{current_version.minor}.{current_version.micro}")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Architecture: {platform.machine()}")
    
    # Version requirements
    min_version = (3, 8)
    recommended_version = (3, 10, 11)
    max_version = (3, 11)
    
    print(f"\n📋 Version Requirements:")
    print(f"Minimum: Python {min_version[0]}.{min_version[1]}")
    print(f"Recommended: Python {recommended_version[0]}.{recommended_version[1]}.{recommended_version[2]}")
    print(f"Maximum: Python {max_version[0]}.{max_version[1]}")
    
    # Check compatibility
    if current_version[:2] < min_version:
        print(f"\n❌ INCOMPATIBLE: Python {current_version.major}.{current_version.minor} is too old")
        print("💡 Please upgrade to Python 3.8 or higher")
        return False
    
    elif current_version[:2] > max_version:
        print(f"\n⚠️  WARNING: Python {current_version.major}.{current_version.minor} may have compatibility issues")
        print("💡 Recommended: Use Python 3.10.11 for best compatibility")
        return True
    
    elif current_version[:3] == recommended_version:
        print(f"\n✅ PERFECT: Python {current_version.major}.{current_version.minor}.{current_version.micro} is optimal")
        return True
    
    else:
        print(f"\n✅ COMPATIBLE: Python {current_version.major}.{current_version.minor} will work")
        print("💡 For best performance, consider upgrading to Python 3.10.11")
        return True

def check_pip_version():
    """Check pip version"""
    print(f"\n📦 Pip Version Check")
    print("-" * 30)
    
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "--version"], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            pip_version = result.stdout.strip()
            print(f"✅ {pip_version}")
            return True
        else:
            print("❌ Pip not found or not working")
            return False
    except Exception as e:
        print(f"❌ Error checking pip: {e}")
        return False

def check_required_packages():
    """Check if required packages can be imported"""
    print(f"\n🔍 Package Compatibility Check")
    print("-" * 30)
    
    critical_packages = [
        'numpy', 'pandas', 'sklearn', 'tensorflow', 'flask'
    ]
    
    optional_packages = [
        'xgboost', 'torch', 'redis', 'kafka', 'transformers', 'nltk'
    ]
    
    print("Critical packages:")
    critical_ok = True
    for package in critical_packages:
        try:
            __import__(package)
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package} - Not installed")
            critical_ok = False
    
    print("\nOptional packages:")
    optional_ok = True
    for package in optional_packages:
        try:
            __import__(package)
            print(f"✅ {package}")
        except ImportError:
            print(f"⚠️  {package} - Not installed (optional)")
    
    return critical_ok

def get_installation_commands():
    """Get installation commands for current Python version"""
    print(f"\n🚀 Installation Commands")
    print("-" * 30)
    
    current_version = sys.version_info[:2]
    
    if current_version == (3, 10):
        print("For Python 3.10.11 (Recommended):")
        print("pip install -r requirements-py310.txt")
    else:
        print("For your Python version:")
        print("pip install -r requirements.txt")
    
    print("\nAlternative installation methods:")
    print("1. Using conda:")
    print("   conda create -n cybersecurity python=3.10.11")
    print("   conda activate cybersecurity")
    print("   pip install -r requirements.txt")
    
    print("\n2. Using virtual environment:")
    print("   python -m venv cybersecurity_env")
    print("   source cybersecurity_env/bin/activate  # Linux/Mac")
    print("   cybersecurity_env\\Scripts\\activate     # Windows")
    print("   pip install -r requirements.txt")

def main():
    """Main compatibility check"""
    print("🛡️ Cybersecurity AI System - Compatibility Check")
    print("=" * 60)
    
    # Check Python version
    python_ok = check_python_version()
    
    # Check pip
    pip_ok = check_pip_version()
    
    # Check packages
    packages_ok = check_required_packages()
    
    # Summary
    print(f"\n📊 Compatibility Summary")
    print("=" * 30)
    print(f"Python Version: {'✅' if python_ok else '❌'}")
    print(f"Pip: {'✅' if pip_ok else '❌'}")
    print(f"Packages: {'✅' if packages_ok else '❌'}")
    
    if python_ok and pip_ok and packages_ok:
        print(f"\n🎉 Your system is ready to run the Cybersecurity AI System!")
        print("Run: python main.py --mode demo")
    else:
        print(f"\n🔧 Setup Required:")
        get_installation_commands()
        
        if not python_ok:
            print("\n❌ Please upgrade Python first")
        elif not pip_ok:
            print("\n❌ Please fix pip installation")
        elif not packages_ok:
            print("\n❌ Please install required packages")
    
    print(f"\n📚 For more help, check the documentation in docs/")

if __name__ == "__main__":
    main()

