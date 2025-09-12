# CipherGuard - Ethical Codebreaking Simulation

## Overview
CipherGuard is a comprehensive educational cryptographic simulation system that demonstrates Public Key Encryption (PKE) applications in real-world scenarios. The system provides hands-on learning experiences for secure email communication, VPN encryption, and digital signatures while emphasizing ethical use and educational purposes.

## Key Features

### Core Simulations
- **Secure Email Communication**: RSA + AES hybrid encryption with digital signatures
- **VPN Handshake & Tunnel Establishment**: SSL/TLS-like key exchange and secure tunneling
- **Digital Signature Creation & Verification**: Document signing with integrity verification

### Educational Tools
- **Interactive GUI**: Tabbed interface with real-time feedback
- **Process Visualization**: Step-by-step visual representations of cryptographic processes
- **Tool Integration**: Demonstrations using OpenSSL, GnuPG, and Wireshark
- **Performance Comparison**: Analysis of different encryption methods
- **Message Storage**: Secure persistence of encrypted communications
- **Comprehensive Logging**: Detailed event tracking and reporting

## System Requirements
- Python 3.8 or higher
- Windows/Linux/macOS
- 4GB RAM minimum
- 100MB disk space

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd CipherGuard
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python src/main.py
   ```

## Usage Guide

### Secure Email Simulation
1. Navigate to the "Secure Email" tab
2. Click "Generate Keys" to create RSA key pairs
3. Enter a message in the text area
4. Click "Encrypt & Send" to encrypt with hybrid encryption
5. Click "Decrypt & Receive" to decrypt and verify signature
6. Use "Save Message" to store encrypted communications

### VPN Simulation
1. Go to the "VPN Simulation" tab
2. Click "Initialize VPN" to start the handshake process
3. Click "Start Tunnel" to establish the encrypted tunnel
4. Monitor traffic in the Traffic Monitor section
5. Click "Stop Tunnel" to close the connection

### Digital Signatures
1. Open the "Digital Signatures" tab
2. Click "Generate Keys" to create signing keys
3. Enter document content in the text area
4. Click "Sign Document" to create a digital signature
5. Click "Verify Signature" to validate document integrity

### Method Comparison
1. Visit the "Method Comparison" tab
2. Click "Run Comparison" to analyze different encryption methods
3. View performance metrics and security levels

### Process Visualization
1. Access the "Process Visualization" tab
2. Select the process type (email, VPN, or signature)
3. Click "Next Step" to see step-by-step visualizations
4. Use "Reset" to return to the beginning

### Cryptographic Tools
1. Navigate to the "Cryptographic Tools" tab
2. Try different tool demonstrations:
   - OpenSSL key generation
   - GnuPG email encryption
   - Wireshark VPN analysis
   - Command-line workflows

## Architecture

### Directory Structure
```
CipherGuard/
├── src/
│   ├── main.py                 # Application entry point
│   ├── gui/
│   │   ├── main_window.py      # Main GUI interface
│   │   └── visualizations.py   # Process visualizations
│   ├── simulations/
│   │   ├── email_sim.py        # Email encryption simulation
│   │   ├── vpn_sim.py          # VPN simulation engine
│   │   └── digital_signature.py # Digital signature operations
│   ├── crypto/
│   │   ├── cipher.py           # Hybrid encryption engine
│   │   ├── key_manager.py      # RSA key management
│   │   ├── key_storage.py      # Secure key storage
│   │   └── message_storage.py  # Encrypted message persistence
│   ├── analysis/
│   │   └── comparison.py       # Performance comparison engine
│   └── utils/
│       ├── logger.py           # Comprehensive logging
│       ├── tool_integration.py # External tool integration
│       └── wireshark_integration.py # Network analysis
├── logs/                       # Application logs
├── tests/                      # Unit tests
├── docs/                       # Documentation
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

### Key Components

#### Cryptographic Engine
- **Hybrid Encryption**: RSA for key exchange, AES for bulk data
- **Digital Signatures**: RSA-PSS with SHA-256 hashing
- **Key Management**: Secure generation, storage, and lifecycle management

#### Simulation Engines
- **Email Simulator**: End-to-end encrypted email workflow
- **VPN Simulator**: TLS-like handshake and tunnel establishment
- **Signature Engine**: Document signing and verification

#### User Interface
- **Tabbed Interface**: Organized by functionality
- **Real-time Feedback**: Live status updates and results
- **Visual Process Flow**: Step-by-step cryptographic visualizations

## Security Considerations

### Educational Purpose
- This system is designed for educational demonstration only
- Not intended for production security applications
- Simplified implementations may not include all real-world security measures

### Ethical Use
- Must be used in controlled, authorized environments
- Intended for cybersecurity education and training
- Should not be used for unauthorized access or malicious purposes

### Data Protection
- All simulated keys and messages are stored locally
- Temporary files are cleaned up after use
- No sensitive data should be used in demonstrations

## Technical Specifications

### Encryption Standards
- **RSA**: 2048-bit keys with OAEP padding
- **AES**: 256-bit keys with CBC mode
- **Hashing**: SHA-256 for integrity verification
- **Digital Signatures**: RSA-PSS with SHA-256

### Performance Metrics
- Key generation: ~100ms for 2048-bit RSA
- Encryption speed: Varies by message size
- Memory usage: <50MB typical operation

## Troubleshooting

### Common Issues
1. **Import Errors**: Ensure all dependencies are installed
2. **GUI Not Loading**: Check matplotlib backend configuration
3. **Tool Integration Fails**: External tools may not be installed
4. **Performance Issues**: Reduce key sizes for faster operation

### Log Files
- Application logs: `logs/cipherguard.log`
- Simulation reports: `logs/simulation_report.json`

## Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Install development dependencies
4. Run tests before submitting

### Code Standards
- Follow PEP 8 Python style guidelines
- Include docstrings for all functions
- Add unit tests for new features
- Update documentation as needed

## License
This project is for educational purposes. Please ensure ethical use in accordance with local laws and institutional policies.

## Acknowledgments
- Built using Python cryptography library
- GUI implemented with tkinter
- Visualizations powered by matplotlib
- Inspired by real-world cryptographic protocols

## Support
For questions or issues, please refer to the documentation or create an issue in the repository.