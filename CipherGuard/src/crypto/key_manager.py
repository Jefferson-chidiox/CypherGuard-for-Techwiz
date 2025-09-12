import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

class KeyManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.session_keys = {}
    
    def generate_key_pair(self, key_size=2048):
        """Generate RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key
    
    def export_keys(self, password=None):
        """Export keys in PEM format with optional encryption"""
        if password:
            # Encrypt private key with password
            encryption_algorithm = serialization.BestAvailableEncryption(
                password.encode('utf-8')
            )
        else:
            encryption_algorithm = serialization.NoEncryption()
            
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'private_key': base64.b64encode(private_pem).decode('utf-8'),
            'public_key': base64.b64encode(public_pem).decode('utf-8')
        }
    
    def import_keys(self, private_pem, password=None):
        """Import keys from PEM format"""
        try:
            if password:
                self.private_key = serialization.load_pem_private_key(
                    base64.b64decode(private_pem),
                    password=password.encode('utf-8'),
                    backend=default_backend()
                )
            else:
                self.private_key = serialization.load_pem_private_key(
                    base64.b64decode(private_pem),
                    password=None,
                    backend=default_backend()
                )
                
            self.public_key = self.private_key.public_key()
            return True
            
        except Exception as e:
            print(f"Failed to import keys: {str(e)}")
            return False
    
    def generate_session_key(self, session_id=None):
        """Generate a new session key"""
        if not session_id:
            session_id = base64.b64encode(os.urandom(16)).decode('utf-8')
            
        # Generate a new Fernet key
        key = Fernet.generate_key()
        self.session_keys[session_id] = key
        
        return {
            'session_id': session_id,
            'key': base64.b64encode(key).decode('utf-8')
        }
    
    def get_session_key(self, session_id):
        """Retrieve a session key"""
        return self.session_keys.get(session_id)
    
    def delete_session_key(self, session_id):
        """Delete a session key"""
        if session_id in self.session_keys:
            del self.session_keys[session_id]
            return True
        return False
    
    def derive_key(self, password, salt=None):
        """Derive a key from a password using PBKDF2"""
        if not salt:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.b64encode(kdf.derive(password.encode('utf-8')))
        
        return {
            'key': key.decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8')
        }