# CipherGuard Development Commands

## Quick Setup

### 1. Project Setup
```bash
mkdir CipherGuard
cd CipherGuard
git init
```

### 2. Python Environment
```bash
python -m venv venv
venv\Scripts\activate
pip install --upgrade pip
```

### 3. Install Dependencies
```bash
pip install cryptography>=41.0.0 matplotlib>=3.7.0 numpy>=1.24.0
pip freeze > requirements.txt
```

### 4. Create Project Structure
```bash
mkdir src src\gui src\crypto src\simulations src\utils src\analysis
mkdir logs tests sample_files signed_documents signed_documents\keys
```

## Development Commands

### 5. Core Files
```bash
# Main application
echo "import tkinter as tk" > src\main.py

# Crypto modules
echo "# RSA Key Management" > src\crypto\key_manager.py
echo "# Hybrid Encryption" > src\crypto\cipher.py
echo "# Message Storage" > src\crypto\message_storage.py

# GUI components
echo "# Main GUI" > src\gui\gui.py
echo "# Splash Screen" > src\gui\splash_screen.py

# Simulations
echo "# Email Simulation" > src\simulations\email_sim.py
echo "# VPN Simulation" > src\simulations\vpn_sim.py
echo "# Digital Signatures" > src\simulations\digital_signature.py

# Utils
echo "# Logger" > src\utils\logger.py
echo "# Security Utils" > src\utils\security_utils.py
```

### 6. Testing Setup
```bash
pip install pytest pytest-cov
mkdir tests\unit tests\integration
echo "# Tests" > tests\__init__.py
```

### 7. Sample Data
```bash
echo "Test document content" > sample_files\test_document.txt
echo "Sample email content" > sample_files\test_email.eml
```

## Run Application
```bash
python src\main.py
```

## Testing
```bash
pytest tests/ -v
```

## Version Control
```bash
git add .
git commit -m "Initial CipherGuard implementation"
git tag v1.0.0
```
