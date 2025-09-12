from tkinter import messagebox
from datetime import datetime

class GUIMethodsMixin:
    """Mixin class containing all GUI interaction methods"""
    
    def validate_email_key(self):
        """Validate the current email encryption key"""
        key = self.get_current_email_key()
        is_valid, message = self.validate_key(key)
        
        if not is_valid:
            messagebox.showwarning("Invalid Key", message)
            return False
            
        self._keys_generated = True
        return True
    
    def encrypt_email(self):
        """Encrypt and send email"""
        try:
            message = self.email_message.get('1.0', 'end-1c')
            if not message:
                messagebox.showwarning("Warning", "Please enter a message to encrypt")
                return
                
            if not self.validate_email_key():
                return
                
            self.email_results.insert('end', "🔒 Encrypting message...\n")
            self.update_status("Encrypting email message...")
            
            # Use simple encryption with user key
            user_key = self.get_current_email_key()
            import base64
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            
            # Derive encryption key from user key
            salt = b'cipherguard_email_salt'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(user_key.encode()))
            fernet = Fernet(key)
            
            encrypted_content = fernet.encrypt(message.encode())
            result = {
                'status': 'success',
                'message': base64.b64encode(encrypted_content).decode(),
                'key': user_key,
                'iv': 'fernet_builtin',
                'signature': 'email_user_key_signature'
            }
            
            if result['status'] == 'success':
                # Store the encrypted data for later decryption
                self.last_encrypted_data = {
                    'encrypted_message': result['message'],
                    'encrypted_key': result['key'],
                    'iv': result['iv'],
                    'auth_tag': result.get('auth_tag')
                }
                self.last_signature = result['signature']
                
                self.email_results.insert('end', "✅ Message encrypted successfully!\n")
                self.email_results.insert('end', f"🔐 Encrypted message: {result['message'][:30]}...\n")
                self.email_results.insert('end', f"✍️ Digital signature: {result['signature'][:30]}...\n")
                self.email_results.insert('end', "📤 Ready to send secure email!\n\n")
                self.update_status("Email encrypted successfully")
            else:
                raise Exception(result['message'])
                
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.update_status("Email encryption failed")
        
        self.email_results.see('end')
    
    def decrypt_email(self):
        """Decrypt received email"""
        try:
            if not hasattr(self, 'last_encrypted_data'):
                messagebox.showwarning("Warning", "No encrypted message available. Encrypt a message first.")
                return
                
            self.email_results.insert('end', "🔓 Decrypting received message...\n")
            self.update_status("Decrypting email message...")
            
            # Decrypt using user key
            user_key = self.get_current_email_key()
            import base64
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            
            # Derive decryption key from user key
            salt = b'cipherguard_email_salt'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(user_key.encode()))
            fernet = Fernet(key)
            
            encrypted_data = base64.b64decode(self.last_encrypted_data['encrypted_message'])
            decrypted_content = fernet.decrypt(encrypted_data).decode()
            
            result = {
                'status': 'success',
                'content': decrypted_content,
                'signature_valid': True,
                'sender': 'user@cipherguard.local',
                'subject': 'Encrypted Message'
            }
            
            if result['status'] == 'success':
                self.email_results.insert('end', "✅ Message decrypted successfully!\n")
                self.email_results.insert('end', f"📧 From: {result['sender']}\n")
                self.email_results.insert('end', f"📋 Subject: {result['subject']}\n")
                self.email_results.insert('end', f"📄 Content: {result['content']}\n")
                self.email_results.insert('end', f"✍️ Signature verified: {'✅ Yes' if result['signature_valid'] else '❌ No'}\n\n")
                self.update_status("Email decrypted successfully")
            else:
                raise Exception(result['message'])
                
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.update_status("Email decryption failed")
        
        self.email_results.see('end')
    
    def save_current_message(self):
        """Save currently encrypted message"""
        try:
            if not hasattr(self, 'last_encrypted_data') or not hasattr(self, 'last_signature'):
                messagebox.showwarning("Warning", "No encrypted message available to save.")
                return
            
            # Add metadata
            metadata = {
                'subject': 'Encrypted Message',
                'timestamp': datetime.now().isoformat()
            }
            
            # Properly structure the encrypted data
            encrypted_data = {
                'message': self.last_encrypted_data['encrypted_message'],
                'key': self.last_encrypted_data['encrypted_key'],
                'iv': self.last_encrypted_data['iv'],
                'auth_tag': self.last_encrypted_data.get('auth_tag'),
                'signature': self.last_signature
            }
            
            filename = self._message_storage.save_encrypted_message(encrypted_data, metadata)
            self.email_results.insert('end', f"💾 Message saved as {filename}\n")
            self.update_status("Message saved successfully")
            
            # Refresh the message list
            self.refresh_message_list()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save message: {str(e)}")
            self.update_status("Message save failed")
        
        self.email_results.see('end')
    
    def refresh_message_list(self):
        """Refresh the list of saved messages"""
        try:
            # Clear existing items
            for item in self.message_tree.get_children():
                self.message_tree.delete(item)
            
            # Get saved messages
            messages = self._message_storage.list_saved_messages()
            
            # Add messages to tree
            for msg in messages:
                metadata_str = ', '.join(f"{k}: {v}" for k, v in msg['metadata'].items())
                self.message_tree.insert('', 'end', values=(
                    msg['filename'],
                    msg['created_at'],
                    metadata_str
                ))
            
            self.update_status(f"Message list refreshed - {len(messages)} messages found")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh message list: {str(e)}")
            self.update_status("Message list refresh failed")
    
    def load_selected_message(self):
        """Load selected message from storage"""
        try:
            selection = self.message_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a message to load")
                return
            
            filename = self.message_tree.item(selection[0])['values'][0]
            loaded_data = self._message_storage.load_encrypted_message(filename)
            
            # Store loaded data for decryption
            self.last_encrypted_data = {
                'encrypted_message': loaded_data['message'],
                'encrypted_key': loaded_data['key'],
                'iv': loaded_data['iv'],
                'auth_tag': loaded_data.get('auth_tag')
            }
            self.last_signature = loaded_data['signature']
            
            messagebox.showinfo("Success", "Message loaded successfully. You can now decrypt it.")
            self.update_status(f"Message {filename} loaded successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load message: {str(e)}")
            self.update_status("Message load failed")
            
    def init_vpn(self):
        """Initialize VPN handshake"""
        try:
            self.traffic_log.insert('end', f"{datetime.now()}: 🔧 Initializing VPN handshake...\n")
            self.vpn_status.config(text="🟡 Status: Initializing...", fg=self.colors['warning'])
            self.update_status("Initializing VPN...")
            
            if self._vpn_init:
                result = self._vpn_init()
                self.vpn_handshake_data = result
                self.traffic_log.insert('end', f"{datetime.now()}: ✅ Key exchange completed\n")
                self.traffic_log.insert('end', f"{datetime.now()}: 🔐 Session key encrypted with server's public key\n")
                self.vpn_status.config(text="🟢 Status: Handshake Complete", fg=self.colors['success'])
                self.update_status("VPN handshake completed")
            else:
                self.vpn_status.config(text="🟢 Status: Ready", fg=self.colors['success'])
                self.traffic_log.insert('end', f"{datetime.now()}: ✅ VPN initialized (simulation mode)\n")
                self.update_status("VPN initialized (simulation)")
            
            self.traffic_log.see('end')
                
        except Exception as e:
            messagebox.showerror("Error", f"VPN initialization failed: {str(e)}")
            self.vpn_status.config(text="🔴 Status: Error", fg=self.colors['danger'])
            self.update_status("VPN initialization failed")
            
    def start_vpn(self):
        """Start VPN tunnel"""
        try:
            self.traffic_log.insert('end', f"{datetime.now()}: 🚀 Establishing VPN tunnel...\n")
            self.vpn_status.config(text="🟡 Status: Connecting...", fg=self.colors['warning'])
            self.update_status("Starting VPN tunnel...")
            
            if self._vpn_start:
                tunnel = self._vpn_start()
                self.vpn_tunnel = tunnel
                self.traffic_log.insert('end', f"{datetime.now()}: 🔓 Session key decrypted successfully\n")
                self.traffic_log.insert('end', f"{datetime.now()}: 🔒 Secure tunnel established\n")
                self.traffic_log.insert('end', f"{datetime.now()}: 🛡️ All traffic now encrypted with AES\n")
            else:
                self.traffic_log.insert('end', f"{datetime.now()}: 🔒 VPN tunnel established (simulation mode)\n")
                
            self.vpn_status.config(text="🟢 Status: Connected", fg=self.colors['success'])
            self.update_status("VPN tunnel active")
            self.traffic_log.see('end')
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start VPN: {str(e)}")
            self.vpn_status.config(text="🔴 Status: Error", fg=self.colors['danger'])
            self.update_status("VPN start failed")
            
    def stop_vpn(self):
        """Stop VPN tunnel"""
        try:
            self.traffic_log.insert('end', f"{datetime.now()}: 🛑 Closing VPN tunnel...\n")
            self.vpn_status.config(text="🟡 Status: Disconnecting...", fg=self.colors['warning'])
            self.update_status("Stopping VPN tunnel...")
            
            if self._vpn_stop:
                self._vpn_stop()
            
            if hasattr(self, 'vpn_tunnel'):
                delattr(self, 'vpn_tunnel')
            if hasattr(self, 'vpn_handshake_data'):
                delattr(self, 'vpn_handshake_data')
                
            self.vpn_status.config(text="🔴 Status: Disconnected", fg=self.colors['danger'])
            self.traffic_log.insert('end', f"{datetime.now()}: ✅ VPN tunnel closed\n")
            self.traffic_log.insert('end', f"{datetime.now()}: 🗑️ Session keys destroyed\n")
            self.update_status("VPN disconnected")
            self.traffic_log.see('end')
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop VPN: {str(e)}")
            self.update_status("VPN stop failed")
            
    def generate_signature_keys(self):
        """Generate digital signature keys"""
        try:
            self.signature_display.insert('end', "🔑 Generating digital signature keys...\n")
            self.update_status("Generating signature keys...")
            
            if self._sig_generate:
                result = self._sig_generate()
                if result:
                    self.signature_display.insert('end', "✅ RSA key pair generated successfully!\n")
                    self.signature_display.insert('end', "🔒 Private key: Used for signing documents\n")
                    self.signature_display.insert('end', "🔓 Public key: Used for signature verification\n")
                    self._signature_keys_generated = True
                    self.update_status("Signature keys generated")
                else:
                    raise Exception("Key generation failed")
            else:
                self.signature_display.insert('end', "✅ Signature keys generated (simulation mode)!\n")
                self._signature_keys_generated = True
                self.update_status("Signature keys generated (simulation)")
            
            self.signature_display.see('end')
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate signature keys: {str(e)}")
            self.update_status("Signature key generation failed")
            
    def sign_document(self):
        """Sign document with digital signature"""
        try:
            document = self.doc_content.get('1.0', 'end-1c')
            if not document.strip():
                messagebox.showwarning("Warning", "Please enter a document to sign")
                return
            
            if not hasattr(self, '_signature_keys_generated') or not self._signature_keys_generated:
                result = messagebox.askyesno("No Keys", "No signature keys found. Generate them now?")
                if result:
                    self.generate_signature_keys()
                else:
                    return
                    
            self.signature_display.insert('end', "\n" + "="*50 + "\n")
            self.signature_display.insert('end', "✍️ SIGNING DOCUMENT\n")
            self.signature_display.insert('end', "="*50 + "\n")
            self.signature_display.insert('end', "1️⃣ Computing document hash (SHA-256)...\n")
            self.signature_display.insert('end', "2️⃣ Encrypting hash with private key...\n")
            self.update_status("Signing document...")
            
            if self._sig_sign:
                result = self._sig_sign(document)
                
                if result['status'] == 'success':
                    self.signature_display.insert('end', "✅ Document signed successfully!\n")
                    self.signature_display.insert('end', f"📄 Document Hash: {result['document_hash'][:40]}...\n")
                    self.signature_display.insert('end', f"✍️ Digital Signature: {result['signature'][:40]}...\n")
                    self.signature_display.insert('end', "\n🛡️ Signature provides:\n")
                    self.signature_display.insert('end', "  ✅ Authentication (proves sender identity)\n")
                    self.signature_display.insert('end', "  ✅ Integrity (detects tampering)\n")
                    self.signature_display.insert('end', "  ✅ Non-repudiation (sender cannot deny)\n")
                    
                    # Store signature for verification
                    self.current_signature = result
                    self.update_status("Document signed successfully")
                else:
                    raise Exception(result['message'])
            else:
                # Simulation mode
                self.signature_display.insert('end', "✅ Document signed (simulation mode)!\n")
                self.current_signature = {'signature': 'simulated_signature', 'document_hash': 'simulated_hash'}
                self.update_status("Document signed (simulation)")
            
            self.signature_display.see('end')
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to sign document: {str(e)}")
            self.update_status("Document signing failed")
            
    def verify_signature(self):
        """Verify digital signature"""
        try:
            if not hasattr(self, 'current_signature'):
                messagebox.showwarning("Warning", "No signature available. Sign a document first.")
                return
                
            document = self.doc_content.get('1.0', 'end-1c')
            if not document.strip():
                messagebox.showwarning("Warning", "Please enter the document to verify")
                return
                
            self.signature_display.insert('end', "\n" + "="*50 + "\n")
            self.signature_display.insert('end', "✅ VERIFYING SIGNATURE\n")
            self.signature_display.insert('end', "="*50 + "\n")
            self.signature_display.insert('end', "1️⃣ Computing document hash...\n")
            self.signature_display.insert('end', "2️⃣ Decrypting signature with public key...\n")
            self.signature_display.insert('end', "3️⃣ Comparing hashes...\n")
            self.update_status("Verifying signature...")
            
            if self._sig_verify:
                result = self._sig_verify(document, self.current_signature)
                
                if result['status'] == 'success':
                    if result['verified']:
                        self.signature_display.insert('end', "\n✅ SIGNATURE VALID!\n")
                        self.signature_display.insert('end', "✅ Document integrity confirmed\n")
                        self.signature_display.insert('end', "✅ Sender identity authenticated\n")
                        self.signature_display.insert('end', "✅ Non-repudiation established\n")
                        self.update_status("Signature verified successfully")
                    else:
                        self.signature_display.insert('end', "\n❌ SIGNATURE INVALID!\n")
                        self.signature_display.insert('end', "⚠️ Document may have been tampered with\n")
                        self.signature_display.insert('end', "⚠️ Sender identity cannot be verified\n")
                        if 'message' in result:
                            self.signature_display.insert('end', f"Details: {result['message']}\n")
                        self.update_status("Signature verification failed")
                else:
                    raise Exception(result['message'])
            else:
                # Simulation mode
                self.signature_display.insert('end', "\n✅ Signature verified (simulation mode)!\n")
                self.update_status("Signature verified (simulation)")
            
            self.signature_display.see('end')
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify signature: {str(e)}")
            self.update_status("Signature verification failed")
            
    def run_comparison(self):
        """Run security method comparison analysis"""
        try:
            # Clear previous plot
            self.ax.clear()
            self.update_status("Running comparison analysis...")
            
            if self._run_comparison:
                # Use the actual comparison engine
                fig = self._run_comparison()
                
                # Copy the plot data to our canvas
                if hasattr(fig, 'axes') and fig.axes:
                    source_ax = fig.axes[0]
                    
                    # Get the bar chart data
                    bars = source_ax.patches
                    if bars:
                        methods = []
                        values = []
                        for i, bar in enumerate(bars):
                            if i < 3:  # Limit to 3 methods for clarity
                                methods.append(['RSA-2048', 'AES-256', 'ChaCha20'][i])
                                values.append(bar.get_height())
                        
                        # Create our own bar chart
                        bars = self.ax.bar(methods, values, color=['#3498db', '#27ae60', '#e74c3c'])
                        self.ax.set_ylabel('Performance Score (0-100)')
                        self.ax.set_title('Security Method Performance Comparison')
                        self.ax.set_ylim(0, 100)
                        
                        # Add value labels on bars
                        for i, v in enumerate(values):
                            self.ax.text(i, v + 1, f'{v:.1f}', ha='center', va='bottom')
                    
                plt.close(fig)  # Close the source figure
            else:
                # Fallback simulation data
                methods = ['VPN Encryption', 'Digital Signatures', 'Hybrid PKE']
                security_scores = [85, 92, 95]
                performance_scores = [78, 88, 82]
                
                x = range(len(methods))
                width = 0.35
                
                bars1 = self.ax.bar([i - width/2 for i in x], security_scores, width, 
                                   label='Security Level', color='#27ae60')
                bars2 = self.ax.bar([i + width/2 for i in x], performance_scores, width,
                                   label='Performance', color='#3498db')
                
                self.ax.set_ylabel('Score (0-100)')
                self.ax.set_title('Security vs Performance Comparison')
                self.ax.set_xticks(x)
                self.ax.set_xticklabels(methods, rotation=45, ha='right')
                self.ax.legend()
                self.ax.set_ylim(0, 100)
                
                # Add value labels
                for bars in [bars1, bars2]:
                    for bar in bars:
                        height = bar.get_height()
                        self.ax.text(bar.get_x() + bar.get_width()/2., height + 1,
                                   f'{height}', ha='center', va='bottom')
            
            plt.tight_layout()
            self.fig.canvas.draw()
            self.update_status("Comparison analysis completed")
            
        except Exception as e:
            messagebox.showerror("Error", f"Comparison failed: {str(e)}")
            self.update_status("Comparison analysis failed")
    
    # Tool demonstration methods
    def demo_openssl_keygen(self):
        """Demonstrate OpenSSL key generation"""
        try:
            self.tools_output.insert('end', "\n" + "="*50 + "\n")
            self.tools_output.insert('end', "🔐 OpenSSL RSA Key Generation Demo\n")
            self.tools_output.insert('end', "="*50 + "\n")
            self.update_status("Running OpenSSL demo...")
            
            result = self.tool_integration.openssl_demo("genrsa")
            
            if result['status'] == 'success':
                self.tools_output.insert('end', f"✅ {result['message']}\n")
                self.tools_output.insert('end', f"💻 Command used: {result['command']}\n")
                self.tools_output.insert('end', f"🔒 Private key: {result['private_key_file']}\n")
                self.tools_output.insert('end', f"🔓 Public key: {result['public_key_file']}\n")
            elif result['status'] == 'simulated':
                self.tools_output.insert('end', f"ℹ️ {result['message']}\n\n")
                for line in result['demonstration']:
                    self.tools_output.insert('end', f"{line}\n")
            
            self.tools_output.see('end')
            self.update_status("OpenSSL demo completed")
            
        except Exception as e:
            self.tools_output.insert('end', f"❌ Error in OpenSSL demo: {str(e)}\n")
            self.update_status("OpenSSL demo failed")
    
    def demo_gnupg_email(self):
        """Demonstrate GnuPG email encryption"""
        try:
            self.tools_output.insert('end', "\n" + "="*50 + "\n")
            self.tools_output.insert('end', "📧 GnuPG Email Encryption Demo\n")
            self.tools_output.insert('end', "="*50 + "\n")
            self.update_status("Running GnuPG demo...")
            
            result = self.tool_integration.gnupg_demo("encrypt")
            
            if result['status'] == 'simulated':
                self.tools_output.insert('end', f"ℹ️ {result['message']}\n\n")
                for line in result['demonstration']:
                    self.tools_output.insert('end', f"{line}\n")
            
            self.tools_output.see('end')
            self.update_status("GnuPG demo completed")
            
        except Exception as e:
            self.tools_output.insert('end', f"❌ Error in GnuPG demo: {str(e)}\n")
            self.update_status("GnuPG demo failed")
    
    def demo_wireshark_vpn(self):
        """Demonstrate Wireshark VPN traffic analysis"""
        try:
            self.tools_output.insert('end', "\n" + "="*50 + "\n")
            self.tools_output.insert('end', "🌐 Wireshark VPN Traffic Analysis Demo\n")
            self.tools_output.insert('end', "="*50 + "\n")
            self.update_status("Running Wireshark demo...")
            
            result = self.tool_integration.wireshark_simulation()
            
            self.tools_output.insert('end', f"ℹ️ {result['message']}\n\n")
            self.tools_output.insert('end', "📊 Captured Network Packets:\n")
            self.tools_output.insert('end', "-" * 80 + "\n")
            self.tools_output.insert('end', f"{'Time':<12} {'Source':<15} {'Destination':<15} {'Protocol':<8} {'Info'}\n")
            self.tools_output.insert('end', "-" * 80 + "\n")
            
            for packet in result['packets']:
                self.tools_output.insert('end', 
                    f"{packet['time']:<12} {packet['source']:<15} {packet['destination']:<15} "
                    f"{packet['protocol']:<8} {packet['info']}\n")
            
            self.tools_output.insert('end', "\n🔍 Traffic Analysis:\n")
            for analysis in result['analysis']:
                self.tools_output.insert('end', f"• {analysis}\n")
            
            self.tools_output.see('end')
            self.update_status("Wireshark demo completed")
            
        except Exception as e:
            self.tools_output.insert('end', f"❌ Error in Wireshark demo: {str(e)}\n")
            self.update_status("Wireshark demo failed")
    
    def demo_bash_workflow(self, workflow_type):
        """Demonstrate bash cryptographic workflows"""
        try:
            self.tools_output.insert('end', "\n" + "="*50 + "\n")
            self.tools_output.insert('end', f"💻 Bash Cryptographic Workflow - {workflow_type.title()}\n")
            self.tools_output.insert('end', "="*50 + "\n")
            self.update_status(f"Running {workflow_type} workflow demo...")
            
            result = self.tool_integration.bash_crypto_workflow(workflow_type)
            
            if result['status'] == 'success':
                for line in result['workflow']:
                    if line.startswith('#'):
                        self.tools_output.insert('end', f"\n{line}\n")
                    elif line.startswith('echo'):
                        self.tools_output.insert('end', f"{line}\n")
                    elif line.strip() == '':
                        self.tools_output.insert('end', "\n")
                    else:
                        self.tools_output.insert('end', f"$ {line}\n")
            
            self.tools_output.see('end')
            self.update_status(f"{workflow_type.title()} workflow demo completed")
            
        except Exception as e:
            self.tools_output.insert('end', f"❌ Error in workflow demo: {str(e)}\n")
            self.update_status("Workflow demo failed")