import os
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet

class CipherEngine:
    def __init__(self):
        self.status = "Ready"
        self.last_operation = None
    
    def encrypt_message(self, message, public_key):
        """Encrypt message using hybrid encryption (RSA + AES)"""
        try:
            # Generate a random AES key
            aes_key = os.urandom(32)
            iv = os.urandom(16)
            
            # Encrypt the AES key with RSA
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Encrypt the message with AES-GCM (authenticated encryption)
            nonce = iv[:12]  # GCM uses 12-byte nonce
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
            auth_tag = encryptor.tag
            
            # Combine encrypted key, IV, and message
            result = {
                'key': base64.b64encode(encrypted_key).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'message': base64.b64encode(encrypted_message).decode('utf-8'),
                'auth_tag': base64.b64encode(auth_tag).decode('utf-8')
            }
            
            self.status = "Encryption successful"
            self.last_operation = "encrypt"
            return result
            
        except Exception as e:
            self.status = f"Encryption failed: {str(e)}"
            raise
    
    def decrypt_message(self, encrypted_data, private_key):
        """Decrypt message using hybrid encryption"""
        try:
            # Decode components
            encrypted_key = base64.b64decode(encrypted_data['key'])
            iv = base64.b64decode(encrypted_data['iv'])
            encrypted_message = base64.b64decode(encrypted_data.get('encrypted_message') or encrypted_data.get('message'))
            auth_tag = base64.b64decode(encrypted_data.get('auth_tag', '')) if encrypted_data.get('auth_tag') else None
            
            # Decrypt the AES key with RSA
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt the message with AES-GCM
            if auth_tag:
                nonce = iv[:12]  # GCM uses 12-byte nonce
                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, auth_tag))
                decryptor = cipher.decryptor()
                message = decryptor.update(encrypted_message) + decryptor.finalize()
            else:
                # Fallback for old CBC format
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
                message = self._unpad_message(padded_message)
            
            self.status = "Decryption successful"
            self.last_operation = "decrypt"
            return message.decode('utf-8')
            
        except Exception as e:
            self.status = f"Decryption failed: {str(e)}"
            raise
    
    def _pad_message(self, message):
        """Add PKCS7 padding"""
        block_size = 16
        padding_length = block_size - (len(message) % block_size)
        padding = bytes([padding_length] * padding_length)
        return message + padding
    
    def _unpad_message(self, padded_message):
        """Remove PKCS7 padding"""
        padding_length = padded_message[-1]
        return padded_message[:-padding_length]
    
    def get_status(self):
        """Get current cipher status"""
        return {
            'status': self.status,
            'last_operation': self.last_operation
        }