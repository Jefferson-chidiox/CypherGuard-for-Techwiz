from cryptography.fernet import Fernet
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.key_manager import KeyManager
from crypto.cipher import CipherEngine

class VPNSimulation:
    def __init__(self):
        self.client_keys = KeyManager()
        self.server_keys = KeyManager()
        self.cipher = CipherEngine()
        self.session_key = None
        self.tunnel_established = False
        self.simulation_log = []
    
    def handshake(self):
        """Simulate VPN handshake process"""
        # Generate key pairs
        self.client_keys.generate_key_pair()
        self.server_keys.generate_key_pair()
        
        # Generate symmetric session key
        self.session_key = Fernet.generate_key()
        
        # Encrypt session key with server's public key
        encrypted_session_key = self.cipher.encrypt_message(
            self.session_key.decode('utf-8'), 
            self.server_keys.public_key
        )
        
        self.log_event("VPN handshake initiated")
        self.log_event("Session key generated and encrypted")
        
        return encrypted_session_key
    
    def establish_tunnel(self):
        """Establish VPN tunnel using the handshake data"""
        if not self.session_key:
            raise Exception("No session key available. Run handshake first.")
        
        # Create Fernet cipher with session key
        fernet_cipher = Fernet(self.session_key)
        
        self.tunnel_established = True
        self.log_event("VPN tunnel established successfully")
        self.log_event("Symmetric encryption active for data transmission")
        
        return fernet_cipher
    
    def transmit_data(self, data, fernet_cipher):
        """Transmit data through VPN tunnel"""
        if not self.tunnel_established:
            raise Exception("VPN tunnel not established")
        
        encrypted_data = fernet_cipher.encrypt(data.encode('utf-8'))
        self.log_event(f"Data transmitted through VPN tunnel")
        
        return encrypted_data
    
    def log_event(self, event):
        import datetime
        self.simulation_log.append(f"{datetime.datetime.now()}: {event}")
    
    def get_status(self):
        """Get current VPN status"""
        return {
            'tunnel_established': self.tunnel_established,
            'session_key_active': bool(self.session_key),
            'log_entries': len(self.simulation_log)
        }
    
    def close_tunnel(self):
        """Close VPN tunnel and cleanup"""
        self.tunnel_established = False
        self.session_key = None
        self.log_event("VPN tunnel closed and session keys destroyed")
        return True