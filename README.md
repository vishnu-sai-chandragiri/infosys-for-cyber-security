# AI-Based Cybersecurity Threat Detection System

A comprehensive cybersecurity threat detection system using the CICIDS2017 dataset with real-time monitoring, AI-powered chatbot, and advanced machine learning models.

## Features

- **Multi-Model AI Detection**: Random Forest, XGBoost, Isolation Forest, LSTM, and Autoencoders
- **Real-Time Threat Detection**: Live network traffic monitoring and anomaly detection
- **AI Chatbot Interface**: Interactive query system for threat analysis
- **Web Dashboard**: Comprehensive visualization of threats and system metrics
- **Modular Architecture**: Extensible design for future enhancements

## Project Structure

```
cybersecurity-ai-system/
├── data/                   # Dataset storage and preprocessing
├── models/                 # ML/DL model implementations
├── realtime/              # Real-time detection pipeline
├── chatbot/               # AI chatbot backend
├── web/                   # Web interface and dashboard
├── utils/                 # Utility functions
├── tests/                 # Test suites
├── config/                # Configuration files
└── docs/                  # Documentation
```

## Installation

### Prerequisites
- **Python 3.10.11** (Recommended) or Python 3.8+
- pip (latest version)
- 8GB+ RAM recommended
- 10GB+ free disk space

### Quick Setup

1. **Check Compatibility**
   ```bash
   python check_compatibility.py
   ```

2. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cybersecurity-ai-system
   ```

3. **Install Dependencies**
   
   For Python 3.10.11 (Recommended):
   ```bash
   pip install -r requirements-py310.txt
   ```
   
   For other Python versions:
   ```bash
   pip install -r requirements.txt
   ```

4. **Download CICIDS2017 dataset** to `data/raw/` directory

5. **Run the system**
   ```bash
   python main.py --mode demo  # Demo mode
   python main.py --mode full  # Full system
   ```

## Usage

1. **Data Preprocessing**: Run `python data/preprocess.py` to prepare the dataset
2. **Model Training**: Execute `python models/train_models.py` to train all models
3. **Start System**: Launch `python main.py` to start the complete system
4. **Access Dashboard**: Open browser to `http://localhost:5000`

## API Endpoints

- `/api/threats` - Get current threats
- `/api/models/performance` - Model performance metrics
- `/api/chat` - Chatbot interaction
- `/api/realtime/status` - Real-time detection status

## Security Features

- Encrypted data transmission
- Secure model storage
- Privacy-compliant data handling
- Real-time threat mitigation

## Contributing

Please read the contributing guidelines before submitting pull requests.

## License

This project is licensed under the MIT License.


