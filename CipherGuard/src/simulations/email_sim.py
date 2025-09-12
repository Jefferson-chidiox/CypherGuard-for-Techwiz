import datetime
import sys
import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.key_manager import KeyManager
from crypto.cipher import CipherEngine
from utils.logger import SimulationLogger

class SecureEmailSimulation:
    def __init__(self):
        self.sender_keys = KeyManager()
        self.recipient_keys = KeyManager()
        self.cipher = CipherEngine()
        self.logger = SimulationLogger()
        
    def generate_keys(self):
        """Generate key pairs for sender and recipient"""
        try:
            # Generate new keys
            sender_private, sender_public = self.sender_keys.generate_key_pair()
            recipient_private, recipient_public = self.recipient_keys.generate_key_pair()

            # Initialize cipher engine if needed
            if not self.cipher:
                self.cipher = CipherEngine()

            self.logger.log_encryption_event(
                "Key Generation",
                "Generated key pairs for sender and recipient"
            )

            if not sender_public or not recipient_public:
                raise Exception("Failed to generate key pairs")

            return {
                'status': 'success',
                'sender_public': base64.b64encode(
                    sender_public.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                ).decode('utf-8'),
                'recipient_public': base64.b64encode(
                    recipient_public.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                ).decode('utf-8')
            }
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"Key generation failed: {str(e)}"
            )
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def encrypt_email(self, plain_text, recipient_public_key=None):
        """Encrypt email using recipient's public key"""
        try:
            if not recipient_public_key:
                recipient_public_key = self.recipient_keys.public_key
                
            encrypted_data = self.cipher.encrypt_message(plain_text, recipient_public_key)
            signature = self._sign_email(plain_text)
            
            self.logger.log_encryption_event(
                "Email Encryption",
                "Email encrypted successfully"
            )
            
            return {
                'status': 'success',
                'message': encrypted_data['message'],
                'key': encrypted_data['key'],
                'iv': encrypted_data['iv'],
                'auth_tag': encrypted_data.get('auth_tag'),
                'signature': signature
            }
            
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"Email encryption failed: {str(e)}"
            )
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def _sign_email(self, message):
        """Sign email with sender's private key"""
        try:
            if not self.sender_keys.private_key:
                raise ValueError("Sender's private key not available")
                
            message_bytes = message.encode('utf-8')
            signature = self.sender_keys.private_key.sign(
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            self.logger.log_encryption_event(
                "Email Signing",
                "Email signed with sender's private key"
            )
            
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"Email signing failed: {str(e)}"
            )
            raise
    
    def verify_and_decrypt(self, encrypted_message, signature, sender_public_key=None):
        """Verify signature and decrypt email"""
        try:
            if not sender_public_key:
                sender_public_key = self.sender_keys.public_key
                
            # Decrypt message first
            decrypted_message = self.cipher.decrypt_message(encrypted_message, self.recipient_keys.private_key)
            
            # Verify signature against decrypted content
            try:
                signature_bytes = base64.b64decode(signature)
                sender_public_key.verify(
                    signature_bytes,
                    decrypted_message.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                signature_valid = True
            except Exception:
                signature_valid = False
                self.logger.log_encryption_event(
                    "Signature Verification",
                    "Email signature verification failed"
                )
            
            self.logger.log_encryption_event(
                "Email Decryption",
                "Email decrypted successfully"
            )
            
            return {
                'status': 'success',
                'content': decrypted_message,
                'signature_valid': signature_valid,
                'sender': 'sender@example.com',  # In a real app, this would come from the message
                'subject': 'Secure Message'      # In a real app, this would come from the message
            }
            
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"Email decryption failed: {str(e)}"
            )
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def get_simulation_state(self):
        """Get current state of email simulation for visualization"""
        return {
            'sender_keys_generated': bool(self.sender_keys.public_key),
            'recipient_keys_generated': bool(self.recipient_keys.public_key),
            'encryption_status': self.cipher.get_status(),
            'last_operation': self.logger.get_last_log()
        }
