import os
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from utils.logger import SimulationLogger

class DigitalSignature:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.logger = SimulationLogger()
        
        # Setup signed documents storage directory
        self.storage_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'signed_documents')
        self.keys_dir = os.path.join(self.storage_dir, 'keys')
        
        # Create storage directories if they don't exist
        os.makedirs(self.storage_dir, exist_ok=True)
        os.makedirs(self.keys_dir, exist_ok=True)
        
    def generate_keys(self):
        """Generate a new key pair for digital signatures"""
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()
            
            self.logger.log_encryption_event(
                "Key Generation",
                "Generated new key pair for digital signatures"
            )
            return True
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"Key generation failed: {str(e)}"
            )
            return False
    
    def export_public_key(self, filename=None):
        """Export public key to a file for sharing"""
        try:
            if not self.public_key:
                raise ValueError("No public key available. Generate keys first.")
            
            # Serialize public key
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Generate filename if not provided
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"public_key_{timestamp}.pem"
            
            filepath = os.path.join(self.keys_dir, filename)
            
            with open(filepath, 'wb') as f:
                f.write(pem)
            
            self.logger.log_encryption_event(
                "Key Export",
                f"Public key exported to {filename}"
            )
            
            return {
                'status': 'success',
                'filename': filename,
                'filepath': filepath
            }
            
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"Public key export failed: {str(e)}"
            )
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def import_public_key(self, filepath):
        """Import public key from a file"""
        try:
            with open(filepath, 'rb') as f:
                pem_data = f.read()
            
            # Load public key
            public_key = serialization.load_pem_public_key(pem_data)
            
            self.logger.log_encryption_event(
                "Key Import",
                f"Public key imported from {os.path.basename(filepath)}"
            )
            
            return {
                'status': 'success',
                'public_key': public_key
            }
            
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"Public key import failed: {str(e)}"
            )
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def sign_document(self, document_content):
        """Sign a document using the private key"""
        try:
            if not self.private_key:
                raise ValueError("No private key available. Generate keys first.")

            # Create document hash
            document_bytes = document_content.encode('utf-8')
            
            # Create hash of document
            digest = hashes.Hash(hashes.SHA256())
            digest.update(document_bytes)
            document_hash = digest.finalize()
            
            # Sign the document
            signature = self.private_key.sign(
                document_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            self.logger.log_encryption_event(
                "Document Signing",
                "Document signed successfully"
            )
            
            return {
                'status': 'success',
                'signature': base64.b64encode(signature).decode('utf-8'),
                'document_hash': base64.b64encode(document_hash).decode('utf-8')
            }
            
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"Document signing failed: {str(e)}"
            )
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def save_signed_document(self, document_content, signature_data, document_name=None, metadata=None):
        """Save a signed document with its signature and metadata"""
        try:
            if not self.public_key:
                raise ValueError("No public key available. Generate keys first.")
            
            # Generate filename if not provided
            if not document_name:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                document_name = f"signed_document_{timestamp}"
            
            # Prepare document data
            signed_doc_data = {
                'document_name': document_name,
                'document_content': document_content,
                'signature': signature_data['signature'],
                'document_hash': signature_data['document_hash'],
                'created_at': datetime.now().isoformat(),
                'metadata': metadata or {},
                'public_key_pem': base64.b64encode(
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                ).decode('utf-8')
            }
            
            # Save signed document
            filename = f"{document_name}.signed"
            filepath = os.path.join(self.storage_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(signed_doc_data, f, indent=2)
            
            self.logger.log_encryption_event(
                "Document Save",
                f"Signed document saved as {filename}"
            )
            
            return {
                'status': 'success',
                'filename': filename,
                'filepath': filepath,
                'document_name': document_name
            }
            
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"Failed to save signed document: {str(e)}"
            )
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def load_signed_document(self, filename):
        """Load a signed document from storage"""
        try:
            filepath = os.path.join(self.storage_dir, filename)
            
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"Signed document {filename} not found")
            
            with open(filepath, 'r') as f:
                signed_doc_data = json.load(f)
            
            self.logger.log_encryption_event(
                "Document Load",
                f"Signed document {filename} loaded successfully"
            )
            
            return {
                'status': 'success',
                'data': signed_doc_data
            }
            
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"Failed to load signed document {filename}: {str(e)}"
            )
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def list_signed_documents(self):
        """List all saved signed documents"""
        try:
            documents = []
            
            if not os.path.exists(self.storage_dir):
                return {'status': 'success', 'documents': []}
            
            for filename in os.listdir(self.storage_dir):
                if filename.endswith('.signed'):
                    try:
                        filepath = os.path.join(self.storage_dir, filename)
                        with open(filepath, 'r') as f:
                            doc_data = json.load(f)
                        
                        # Extract summary information
                        doc_info = {
                            'filename': filename,
                            'document_name': doc_data.get('document_name', 'Unknown'),
                            'created_at': doc_data.get('created_at', 'Unknown'),
                            'content_preview': doc_data.get('document_content', '')[:100] + '...' if len(doc_data.get('document_content', '')) > 100 else doc_data.get('document_content', ''),
                            'metadata': doc_data.get('metadata', {})
                        }
                        documents.append(doc_info)
                    except:
                        # Skip corrupted files
                        continue
            
            # Sort by creation date (newest first)
            documents.sort(key=lambda x: x['created_at'], reverse=True)
            
            self.logger.log_encryption_event(
                "Document List",
                f"Found {len(documents)} signed documents"
            )
            
            return {
                'status': 'success',
                'documents': documents
            }
            
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"Failed to list signed documents: {str(e)}"
            )
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def verify_external_signed_document(self, signed_doc_data, public_key=None):
        """Verify a signed document using embedded or provided public key"""
        try:
            # Use provided public key or extract from document
            if public_key:
                verification_key = public_key
            elif 'public_key_pem' in signed_doc_data:
                # Decode and load the embedded public key
                pem_data = base64.b64decode(signed_doc_data['public_key_pem'])
                verification_key = serialization.load_pem_public_key(pem_data)
            else:
                raise ValueError("No public key available for verification")
            
            # Extract document data
            document_content = signed_doc_data['document_content']
            signature_data = {
                'signature': signed_doc_data['signature'],
                'document_hash': signed_doc_data.get('document_hash')
            }
            
            # Verify the signature
            document_bytes = document_content.encode('utf-8')
            signature_bytes = base64.b64decode(signature_data['signature'])
            
            try:
                verification_key.verify(
                    signature_bytes,
                    document_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                # Verify document hash if available
                hash_valid = True
                if signature_data.get('document_hash'):
                    digest = hashes.Hash(hashes.SHA256())
                    digest.update(document_bytes)
                    computed_hash = base64.b64encode(digest.finalize()).decode('utf-8')
                    hash_valid = computed_hash == signature_data['document_hash']
                
                self.logger.log_encryption_event(
                    "External Document Verification",
                    f"Document '{signed_doc_data.get('document_name', 'Unknown')}' verified successfully"
                )
                
                return {
                    'status': 'success',
                    'verified': True,
                    'hash_valid': hash_valid,
                    'document_name': signed_doc_data.get('document_name', 'Unknown'),
                    'created_at': signed_doc_data.get('created_at', 'Unknown')
                }
                
            except InvalidSignature:
                self.logger.log_encryption_event(
                    "External Document Verification",
                    f"Document '{signed_doc_data.get('document_name', 'Unknown')}' signature is invalid"
                )
                
                return {
                    'status': 'success',
                    'verified': False,
                    'message': 'Invalid signature - document may have been tampered with',
                    'document_name': signed_doc_data.get('document_name', 'Unknown')
                }
                
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"External document verification failed: {str(e)}"
            )
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def verify_signature(self, document_content, signature_data):
        """Verify a document's signature"""
        try:
            if not self.public_key:
                raise ValueError("No public key available. Generate keys first.")
            
            signature_bytes = base64.b64decode(signature_data['signature'])
            document_bytes = document_content.encode('utf-8')
            
            try:
                self.public_key.verify(
                    signature_bytes,
                    document_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                self.logger.log_encryption_event(
                    "Signature Verification",
                    "Signature verified successfully"
                )
                
                return {
                    'status': 'success',
                    'verified': True
                }
                
            except InvalidSignature:
                self.logger.log_encryption_event(
                    "Signature Verification",
                    "Invalid signature detected"
                )
                
                return {
                    'status': 'success',
                    'verified': False,
                    'message': 'Invalid signature'
                }
                
        except Exception as e:
            self.logger.log_encryption_event(
                "Error",
                f"Signature verification failed: {str(e)}"
            )
            return {
                'status': 'error',
                'message': str(e)
            }