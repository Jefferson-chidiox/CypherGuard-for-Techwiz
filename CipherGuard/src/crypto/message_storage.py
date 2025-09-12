import os
import json
import base64
import binascii
from datetime import datetime
from utils.security_utils import SecurityUtils

class MessageStorage:
    def __init__(self, storage_dir="encrypted_messages"):
        self.storage_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), storage_dir)
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir)

    def save_encrypted_message(self, encrypted_data, metadata=None):
        """Save an encrypted message with metadata"""
        try:
            # Ensure all binary data is base64 encoded
            message_data = {
                'encrypted_content': {
                    'message': self._ensure_base64(encrypted_data.get('message') or encrypted_data.get('encrypted_message')),
                    'key': self._ensure_base64(encrypted_data.get('key') or encrypted_data.get('encrypted_key')),
                    'iv': self._ensure_base64(encrypted_data['iv']),
                    'auth_tag': self._ensure_base64(encrypted_data.get('auth_tag'))
                },
                'signature': self._ensure_base64(encrypted_data.get('signature')),
                'metadata': metadata or {},
                'created_at': datetime.now().isoformat()
            }

            filename = f"message_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc"
            filename = SecurityUtils.sanitize_filename(filename)
            filepath = SecurityUtils.validate_file_path(
                os.path.join(self.storage_dir, filename), 
                self.storage_dir
            )
            with open(filepath, 'w') as f:
                json.dump(message_data, f, indent=2)

            return filename

        except Exception as e:
            raise Exception(f"Failed to save encrypted message: {str(e)}")

    def _ensure_base64(self, data):
        """Ensure data is in base64 string format"""
        if data is None:
            return None
        if isinstance(data, bytes):
            return base64.b64encode(data).decode('utf-8')
        if isinstance(data, str):
            try:
                # Try to decode to see if it's already base64
                base64.b64decode(data)
                return data
            except (ValueError, binascii.Error):
                # If it's not base64, encode it
                return base64.b64encode(data.encode('utf-8')).decode('utf-8')
        return str(data)

    def load_encrypted_message(self, filename):
        """Load an encrypted message from storage"""
        try:
            filename = SecurityUtils.sanitize_filename(filename)
            filepath = SecurityUtils.validate_file_path(
                os.path.join(self.storage_dir, filename), 
                self.storage_dir
            )
            with open(filepath, 'r') as f:
                message_data = json.load(f)

            return {
                'message': message_data['encrypted_content']['message'],
                'key': message_data['encrypted_content']['key'],
                'iv': message_data['encrypted_content']['iv'],
                'auth_tag': message_data['encrypted_content'].get('auth_tag'),
                'signature': message_data.get('signature'),
                'metadata': message_data.get('metadata', {}),
                'created_at': message_data['created_at']
            }

        except Exception as e:
            raise Exception(f"Failed to load encrypted message: {str(e)}")

    def list_saved_messages(self):
        """List all saved encrypted messages"""
        messages = []
        for filename in os.listdir(self.storage_dir):
            if filename.endswith('.enc'):
                with open(os.path.join(self.storage_dir, filename), 'r') as f:
                    message_data = json.load(f)
                messages.append({
                    'filename': filename,
                    'created_at': message_data['created_at'],
                    'metadata': message_data.get('metadata', {})
                })
        return messages
