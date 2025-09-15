import subprocess
import os
import tempfile
import json
from datetime import datetime
from utils.security_utils import SecurityUtils

class CryptographicToolIntegration:
    """Integration with external cryptographic tools like OpenSSL, GnuPG"""
    
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()
        self.tool_results = []
    
    def openssl_demo(self, operation="genrsa"):
        """Demonstrate OpenSSL operations"""
        try:
            if operation == "genrsa":
                return self._openssl_generate_keys()
            elif operation == "encrypt":
                return self._openssl_encrypt_demo()
            elif operation == "verify":
                return self._openssl_verify_demo()
        except Exception as e:
            return {"status": "error", "message": f"OpenSSL operation failed: {str(e)}"}
    
    def _openssl_generate_keys(self):
        """Generate RSA keys using OpenSSL command line"""
        try:
            # Check if OpenSSL is available
            cmd_args = SecurityUtils.validate_command_args(['openssl', 'version'])
            result = subprocess.run(cmd_args, 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Generate private key
                private_key_file = os.path.join(self.temp_dir, 'private_key.pem')
                public_key_file = os.path.join(self.temp_dir, 'public_key.pem')
                
                # Generate private key
                cmd1 = SecurityUtils.validate_command_args(['openssl', 'genrsa', '-out', private_key_file, '2048'])
                subprocess.run(cmd1, check=True, capture_output=True)
                
                # Extract public key
                cmd2 = SecurityUtils.validate_command_args(['openssl', 'rsa', '-in', private_key_file, 
                              '-pubout', '-out', public_key_file])
                subprocess.run(cmd2, check=True, capture_output=True)
                
                return {
                    "status": "success",
                    "message": "RSA key pair generated using OpenSSL",
                    "private_key_file": private_key_file,
                    "public_key_file": public_key_file,
                    "tool": "OpenSSL",
                    "command": "openssl genrsa -out private_key.pem 2048"
                }
            else:
                return self._simulate_openssl_demo()
                
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return self._simulate_openssl_demo()
    
    def _simulate_openssl_demo(self):
        """Simulate OpenSSL operations when tool is not available"""
        return {
            "status": "simulated",
            "message": "OpenSSL simulation (tool not available)",
            "demonstration": [
                "Command: openssl genrsa -out private_key.pem 2048",
                "Generating RSA private key, 2048 bit long modulus",
                "e is 65537 (0x10001)",
                "",
                "Command: openssl rsa -in private_key.pem -pubout -out public_key.pem",
                "writing RSA key",
                "",
                "Keys generated successfully!"
            ],
            "tool": "OpenSSL (Simulated)"
        }
    
    def gnupg_demo(self, operation="encrypt"):
        """Demonstrate GnuPG operations for email encryption"""
        try:
            # Check if GPG is available
            cmd_args = SecurityUtils.validate_command_args(['gpg', '--version'])
            result = subprocess.run(cmd_args, 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return self._gnupg_real_demo(operation)
            else:
                return self._simulate_gnupg_demo(operation)
                
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return self._simulate_gnupg_demo(operation)
    
    def _simulate_gnupg_demo(self, operation):
        """Simulate GnuPG operations"""
        if operation == "encrypt":
            return {
                "status": "simulated",
                "message": "GnuPG email encryption simulation",
                "demonstration": [
                    "Command: gpg --gen-key",
                    "Generating key pair for user@example.com",
                    "Key ID: 1234ABCD generated",
                    "",
                    "Command: gpg --encrypt --recipient user@example.com message.txt",
                    "Encrypting message with recipient's public key",
                    "Output: message.txt.gpg (encrypted)",
                    "",
                    "Command: gpg --decrypt message.txt.gpg",
                    "Decrypting with private key",
                    "Message decrypted successfully!"
                ],
                "tool": "GnuPG (Simulated)"
            }
        return {"status": "error", "message": "Unknown GnuPG operation"}
    
    def wireshark_simulation(self):
        """Simulate Wireshark-like network traffic analysis for VPN"""
        return {
            "status": "simulated",
            "message": "Network traffic analysis simulation",
            "packets": [
                {
                    "time": "0.000000",
                    "source": "192.168.1.100",
                    "destination": "10.0.0.1",
                    "protocol": "TLS",
                    "info": "Client Hello, TLS 1.3"
                },
                {
                    "time": "0.001234",
                    "source": "10.0.0.1", 
                    "destination": "192.168.1.100",
                    "protocol": "TLS",
                    "info": "Server Hello, Certificate, Server Key Exchange"
                },
                {
                    "time": "0.002456",
                    "source": "192.168.1.100",
                    "destination": "10.0.0.1",
                    "protocol": "TLS",
                    "info": "Client Key Exchange, Change Cipher Spec"
                },
                {
                    "time": "0.003678",
                    "source": "10.0.0.1",
                    "destination": "192.168.1.100", 
                    "protocol": "TLS",
                    "info": "Change Cipher Spec, Finished"
                },
                {
                    "time": "0.004890",
                    "source": "192.168.1.100",
                    "destination": "10.0.0.1",
                    "protocol": "TLS",
                    "info": "Application Data (Encrypted)"
                }
            ],
            "analysis": [
                "TLS handshake completed successfully",
                "RSA key exchange used for session key",
                "AES-256-GCM cipher suite negotiated",
                "All following traffic encrypted"
            ],
            "tool": "Wireshark (Simulated)"
        }
    
    def bash_crypto_workflow(self, workflow_type="email"):
        """Demonstrate cryptographic workflows using bash-like commands"""
        workflows = {
            "email": [
                "# Secure Email Workflow",
                "echo 'Generating RSA key pair...'",
                "openssl genrsa -out sender_private.pem 2048",
                "openssl rsa -in sender_private.pem -pubout -out sender_public.pem",
                "",
                "echo 'Encrypting message...'",
                "echo 'Secret message' > message.txt",
                "openssl rsautl -encrypt -pubin -inkey recipient_public.pem -in message.txt -out encrypted_message.bin",
                "",
                "echo 'Creating digital signature...'",
                "openssl dgst -sha256 -sign sender_private.pem -out signature.bin message.txt",
                "",
                "echo 'Verifying signature...'",
                "openssl dgst -sha256 -verify sender_public.pem -signature signature.bin message.txt",
                "",
                "echo 'Email encryption workflow complete!'"
            ],
            "vpn": [
                "# VPN Key Exchange Workflow",
                "echo 'Generating server certificate...'",
                "openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes",
                "",
                "echo 'Client connecting to VPN server...'",
                "openssl s_client -connect vpn.server.com:443 -cert client_cert.pem -key client_key.pem",
                "",
                "echo 'Establishing secure tunnel...'",
                "# TLS handshake exchanges session keys",
                "# All traffic now encrypted with AES",
                "",
                "echo 'VPN tunnel established!'"
            ],
            "signature": [
                "# Digital Signature Workflow", 
                "echo 'Creating document hash...'",
                "sha256sum document.txt > document.hash",
                "",
                "echo 'Signing document...'",
                "openssl dgst -sha256 -sign private_key.pem -out document.sig document.txt",
                "",
                "echo 'Verifying signature...'",
                "openssl dgst -sha256 -verify public_key.pem -signature document.sig document.txt",
                "",
                "echo 'Signature verification complete!'"
            ]
        }
        
        return {
            "status": "success",
            "workflow": workflows.get(workflow_type, []),
            "type": workflow_type,
            "tool": "Bash/OpenSSL Workflow"
        }
    
    def get_tool_demonstration_report(self):
        """Generate a comprehensive report of tool demonstrations"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "tools_demonstrated": [
                {
                    "tool": "OpenSSL",
                    "purpose": "RSA key generation and encryption operations",
                    "commands": [
                        "openssl genrsa -out private.pem 2048",
                        "openssl rsa -in private.pem -pubout -out public.pem",
                        "openssl rsautl -encrypt -pubin -inkey public.pem -in message.txt"
                    ]
                },
                {
                    "tool": "GnuPG",
                    "purpose": "Email encryption and digital signatures",
                    "commands": [
                        "gpg --gen-key",
                        "gpg --encrypt --recipient user@example.com message.txt",
                        "gpg --decrypt message.txt.gpg"
                    ]
                },
                {
                    "tool": "Wireshark",
                    "purpose": "Network traffic analysis for VPN monitoring",
                    "features": [
                        "TLS handshake analysis",
                        "Encrypted packet inspection",
                        "Protocol identification"
                    ]
                }
            ],
            "educational_value": [
                "Demonstrates real-world cryptographic tool usage",
                "Shows command-line cryptographic workflows",
                "Illustrates industry-standard practices",
                "Provides hands-on learning experience"
            ]
        }
        
        return report
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            import shutil
            shutil.rmtree(self.temp_dir)
        except (OSError, PermissionError) as e:
            print(f"Warning: Failed to cleanup temporary directory: {e}")
        except Exception as e:
            print(f"Unexpected error during cleanup: {e}")