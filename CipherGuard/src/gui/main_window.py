import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from utils.tool_integration import CryptographicToolIntegration

class CipherGuardGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CipherGuard - Ethical Codebreaking Simulation")
        self.root.geometry("1200x800")
        
        # Initialize handlers as None
        self._email_generate = None
        self._email_encrypt = None
        self._email_decrypt = None
        self._vpn_init = None
        self._vpn_start = None
        self._vpn_stop = None
        self._vpn_status = None
        self._sig_generate = None
        self._sig_sign = None
        self._sig_verify = None
        self._run_comparison = None
        self._message_storage = None
        
        self.create_widgets()
    
    def create_widgets(self):
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Email Simulation Tab
        self.email_frame = ttk.Frame(notebook)
        notebook.add(self.email_frame, text='Secure Email')
        self.create_email_tab()
        
        # VPN Simulation Tab
        self.vpn_frame = ttk.Frame(notebook)
        notebook.add(self.vpn_frame, text='VPN Simulation')
        self.create_vpn_tab()
        
        # Digital Signature Tab
        self.signature_frame = ttk.Frame(notebook)
        notebook.add(self.signature_frame, text='Digital Signatures')
        self.create_signature_tab()
        
        # Comparison Tab
        self.comparison_frame = ttk.Frame(notebook)
        notebook.add(self.comparison_frame, text='Method Comparison')
        self.create_comparison_tab()

        # Message Storage Tab
        self.storage_frame = ttk.Frame(notebook) 
        notebook.add(self.storage_frame, text='Message Storage')
        self.create_storage_tab()
        
        
        # Tools Demo Tab
        self.tools_frame = ttk.Frame(notebook)
        notebook.add(self.tools_frame, text='Cryptographic Tools')
        self.create_tools_tab()
    
    def create_email_tab(self):
        # Message input
        ttk.Label(self.email_frame, text="Message:").pack(pady=5)
        self.email_message = scrolledtext.ScrolledText(self.email_frame, height=5)
        self.email_message.pack(fill='x', padx=10, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(self.email_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Generate Keys", command=self.generate_email_keys).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Encrypt & Send", command=self.encrypt_email).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Decrypt & Receive", command=self.decrypt_email).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Save Message", command=self.save_current_message).pack(side='left', padx=5)
        
        # Results area
        self.email_results = scrolledtext.ScrolledText(self.email_frame, height=15)
        self.email_results.pack(fill='both', expand=True, padx=10, pady=5)
        
    def create_storage_tab(self):
        # Message list
        list_frame = ttk.LabelFrame(self.storage_frame, text="Saved Messages")
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create treeview for messages
        columns = ('filename', 'created_at', 'metadata')
        self.message_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        
        # Set column headings
        self.message_tree.heading('filename', text='Filename')
        self.message_tree.heading('created_at', text='Created At')
        self.message_tree.heading('metadata', text='Metadata')
        
        # Set column widths
        self.message_tree.column('filename', width=200)
        self.message_tree.column('created_at', width=150)
        self.message_tree.column('metadata', width=300)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.message_tree.yview)
        self.message_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        self.message_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Buttons
        btn_frame = ttk.Frame(self.storage_frame)
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Refresh List", command=self.refresh_message_list).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Load Selected", command=self.load_selected_message).pack(side='left', padx=5)

    def create_vpn_tab(self):
        # Controls
        control_frame = ttk.LabelFrame(self.vpn_frame, text="VPN Controls")
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(control_frame, text="Initialize VPN", command=self.init_vpn).pack(side='left', padx=5, pady=5)
        ttk.Button(control_frame, text="Start Tunnel", command=self.start_vpn).pack(side='left', padx=5, pady=5)
        ttk.Button(control_frame, text="Stop Tunnel", command=self.stop_vpn).pack(side='left', padx=5, pady=5)
        
        # Status
        status_frame = ttk.LabelFrame(self.vpn_frame, text="VPN Status")
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.vpn_status = ttk.Label(status_frame, text="Status: Not Initialized")
        self.vpn_status.pack(padx=5, pady=5)
        
        # Traffic monitor
        monitor_frame = ttk.LabelFrame(self.vpn_frame, text="Traffic Monitor")
        monitor_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.traffic_log = scrolledtext.ScrolledText(monitor_frame, height=10)
        self.traffic_log.pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_signature_tab(self):
        # Document input
        ttk.Label(self.signature_frame, text="Document:").pack(pady=5)
        self.doc_content = scrolledtext.ScrolledText(self.signature_frame, height=5)
        self.doc_content.pack(fill='x', padx=10, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(self.signature_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Generate Keys", command=self.generate_signature_keys).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Sign Document", command=self.sign_document).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Verify Signature", command=self.verify_signature).pack(side='left', padx=5)
        
        # Signature display
        self.signature_display = scrolledtext.ScrolledText(self.signature_frame, height=10)
        self.signature_display.pack(fill='both', expand=True, padx=10, pady=5)
        
    def create_comparison_tab(self):
        # Comparison controls
        control_frame = ttk.Frame(self.comparison_frame)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(control_frame, text="Compare:").pack(side='left', padx=5)
        ttk.Button(control_frame, text="Run Comparison", command=self.run_comparison).pack(side='left', padx=5)
        
        # Graph area
        self.fig, self.ax = plt.subplots(figsize=(8, 6))
        canvas = FigureCanvasTkAgg(self.fig, master=self.comparison_frame)
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=5)
        
    def set_email_handlers(self, generate_keys, encrypt, decrypt):
        """Set email encryption handlers"""
        self._email_generate = generate_keys
        self._email_encrypt = encrypt
        self._email_decrypt = decrypt
    
    def set_vpn_handlers(self, init_vpn, start_vpn, stop_vpn, get_status):
        """Set VPN simulation handlers"""
        self._vpn_init = init_vpn
        self._vpn_start = start_vpn
        self._vpn_stop = stop_vpn
        self._vpn_status = get_status
    
    def set_signature_handlers(self, generate_keys, sign, verify):
        """Set digital signature handlers"""
        self._sig_generate = generate_keys
        self._sig_sign = sign
        self._sig_verify = verify
    
    def set_comparison_handler(self, run_comparison):
        """Set comparison analysis handler"""
        self._run_comparison = run_comparison

    def set_message_storage_handler(self, message_storage):
        """Set message storage handler"""
        self._message_storage = message_storage
    
    def generate_email_keys(self):
        """Generate email encryption keys"""
        try:
            self.email_results.insert('end', "Generating new key pairs...\n")
            result = self._email_generate()
            
            if result['status'] == 'success':
                self.email_results.insert('end', "Keys generated successfully!\n")
                self.email_results.insert('end', f"Sender's public key: {result['sender_public'][:30]}...\n")
                self.email_results.insert('end', f"Recipient's public key: {result['recipient_public'][:30]}...\n")
                self._keys_generated = True
            else:
                raise Exception(result['message'])
                
        except Exception as e:
            self._keys_generated = False
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")
    
    def encrypt_email(self):
        """Encrypt and send email"""
        try:
            message = self.email_message.get('1.0', 'end-1c')
            if not message:
                messagebox.showwarning("Warning", "Please enter a message to encrypt")
                return
                
            if not hasattr(self, '_keys_generated'):
                result = messagebox.askyesno("No Keys", "No encryption keys found. Would you like to generate them now?")
                if result:
                    self.generate_email_keys()
                else:
                    return
                    
            if not hasattr(self, '_keys_generated') or not self._keys_generated:
                messagebox.showerror("Error", "Please generate encryption keys first")
                return
                
            self.email_results.insert('end', "Encrypting message...\n")
            result = self._email_encrypt(message, None)  # Using default recipient key
            
            if result['status'] == 'success':
                # Store the encrypted data for later decryption
                self.last_encrypted_data = {
                    'message': result['message'],
                    'key': result['key'],
                    'iv': result['iv'],
                    'auth_tag': result.get('auth_tag')
                }
                self.last_signature = result['signature']
                
                self.email_results.insert('end', "Message encrypted successfully!\n")
                self.email_results.insert('end', f"Encrypted message: {result['message'][:30]}...\n")
                self.email_results.insert('end', f"Digital signature: {result['signature'][:30]}...\n")
            else:
                raise Exception(result['message'])
                
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_email(self):
        """Decrypt received email"""
        try:
            if not hasattr(self, 'last_encrypted_data'):
                messagebox.showwarning("Warning", "No encrypted message available. Encrypt a message first.")
                return
                
            self.email_results.insert('end', "Decrypting received message...\n")
            result = self._email_decrypt(
                self.last_encrypted_data,
                self.last_signature,
                None  # Using default sender public key
            )
            
            if result['status'] == 'success':
                self.email_results.insert('end', "Message decrypted successfully!\n")
                self.email_results.insert('end', f"From: {result['sender']}\n")
                self.email_results.insert('end', f"Subject: {result['subject']}\n")
                self.email_results.insert('end', f"Content: {result['content']}\n")
                self.email_results.insert('end', f"Signature verified: {'Yes' if result['signature_valid'] else 'No'}\n")
            else:
                raise Exception(result['message'])
                
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
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
                'message': self.last_encrypted_data['message'],
                'key': self.last_encrypted_data['key'],
                'iv': self.last_encrypted_data['iv'],
                'auth_tag': self.last_encrypted_data.get('auth_tag'),
                'signature': self.last_signature
            }
            
            filename = self._message_storage.save_encrypted_message(encrypted_data, metadata)
            self.email_results.insert('end', f"Message saved as {filename}\n")
            
            # Refresh the message list
            self.refresh_message_list()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save message: {str(e)}")
    
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
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh message list: {str(e)}")
    
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
                'message': loaded_data['message'],
                'key': loaded_data['key'],
                'iv': loaded_data['iv'],
                'auth_tag': loaded_data.get('auth_tag')
            }
            self.last_signature = loaded_data['signature']
            
            messagebox.showinfo("Success", "Message loaded successfully. You can now decrypt it.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load message: {str(e)}")
            
    def init_vpn(self):
        try:
            self.traffic_log.insert('end', f"{datetime.now()}: Initializing VPN handshake...\n")
            self.vpn_status.config(text="Status: Initializing...")
            
            if self._vpn_init:
                result = self._vpn_init()
                self.vpn_handshake_data = result
                self.traffic_log.insert('end', f"{datetime.now()}: Key exchange completed\n")
                self.traffic_log.insert('end', f"{datetime.now()}: Session key encrypted with server's public key\n")
                self.vpn_status.config(text="Status: Handshake Complete")
            else:
                self.vpn_status.config(text="Status: Ready")
                self.traffic_log.insert('end', f"{datetime.now()}: VPN initialized (simulation mode)\n")
                
        except Exception as e:
            messagebox.showerror("Error", f"VPN initialization failed: {str(e)}")
            
    def start_vpn(self):
        try:
            self.traffic_log.insert('end', f"{datetime.now()}: Establishing VPN tunnel...\n")
            self.vpn_status.config(text="Status: Connecting...")
            
            if self._vpn_start:
                tunnel = self._vpn_start()
                self.vpn_tunnel = tunnel
                self.traffic_log.insert('end', f"{datetime.now()}: Session key decrypted successfully\n")
                self.traffic_log.insert('end', f"{datetime.now()}: Secure tunnel established\n")
                self.traffic_log.insert('end', f"{datetime.now()}: All traffic now encrypted with AES\n")
            else:
                self.traffic_log.insert('end', f"{datetime.now()}: VPN tunnel established (simulation mode)\n")
                
            self.vpn_status.config(text="Status: Connected")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start VPN: {str(e)}")
            
    def stop_vpn(self):
        try:
            self.traffic_log.insert('end', f"{datetime.now()}: Closing VPN tunnel...\n")
            self.vpn_status.config(text="Status: Disconnecting...")
            
            if self._vpn_stop:
                self._vpn_stop()
            
            if hasattr(self, 'vpn_tunnel'):
                delattr(self, 'vpn_tunnel')
            if hasattr(self, 'vpn_handshake_data'):
                delattr(self, 'vpn_handshake_data')
                
            self.vpn_status.config(text="Status: Disconnected")
            self.traffic_log.insert('end', f"{datetime.now()}: VPN tunnel closed\n")
            self.traffic_log.insert('end', f"{datetime.now()}: Session keys destroyed\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop VPN: {str(e)}")
            
    def generate_signature_keys(self):
        try:
            self.signature_display.insert('end', "Generating digital signature keys...\n")
            
            if self._sig_generate:
                result = self._sig_generate()
                if result:
                    self.signature_display.insert('end', "✓ RSA key pair generated successfully!\n")
                    self.signature_display.insert('end', "✓ Private key: Used for signing documents\n")
                    self.signature_display.insert('end', "✓ Public key: Used for signature verification\n")
                    self._signature_keys_generated = True
                else:
                    raise Exception("Key generation failed")
            else:
                self.signature_display.insert('end', "Signature keys generated (simulation mode)!\n")
                self._signature_keys_generated = True
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate signature keys: {str(e)}")
            
    def sign_document(self):
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
                    
            self.signature_display.insert('end', "\n=== SIGNING DOCUMENT ===\n")
            self.signature_display.insert('end', "1. Computing document hash (SHA-256)...\n")
            self.signature_display.insert('end', "2. Encrypting hash with private key...\n")
            
            if self._sig_sign:
                result = self._sig_sign(document)
                
                if result['status'] == 'success':
                    self.signature_display.insert('end', "✓ Document signed successfully!\n")
                    self.signature_display.insert('end', f"Document Hash: {result['document_hash'][:40]}...\n")
                    self.signature_display.insert('end', f"Digital Signature: {result['signature'][:40]}...\n")
                    self.signature_display.insert('end', "\n✓ Signature provides:\n")
                    self.signature_display.insert('end', "  - Authentication (proves sender identity)\n")
                    self.signature_display.insert('end', "  - Integrity (detects tampering)\n")
                    self.signature_display.insert('end', "  - Non-repudiation (sender cannot deny)\n")
                    
                    # Store signature for verification
                    self.current_signature = result
                else:
                    raise Exception(result['message'])
            else:
                # Simulation mode
                self.signature_display.insert('end', "✓ Document signed (simulation mode)!\n")
                self.current_signature = {'signature': 'simulated_signature', 'document_hash': 'simulated_hash'}
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to sign document: {str(e)}")
            
    def verify_signature(self):
        try:
            if not hasattr(self, 'current_signature'):
                messagebox.showwarning("Warning", "No signature available. Sign a document first.")
                return
                
            document = self.doc_content.get('1.0', 'end-1c')
            if not document.strip():
                messagebox.showwarning("Warning", "Please enter the document to verify")
                return
                
            self.signature_display.insert('end', "\n=== VERIFYING SIGNATURE ===\n")
            self.signature_display.insert('end', "1. Computing document hash...\n")
            self.signature_display.insert('end', "2. Decrypting signature with public key...\n")
            self.signature_display.insert('end', "3. Comparing hashes...\n")
            
            if self._sig_verify:
                result = self._sig_verify(document, self.current_signature)
                
                if result['status'] == 'success':
                    if result['verified']:
                        self.signature_display.insert('end', "\n✓ SIGNATURE VALID!\n")
                        self.signature_display.insert('end', "✓ Document integrity confirmed\n")
                        self.signature_display.insert('end', "✓ Sender identity authenticated\n")
                        self.signature_display.insert('end', "✓ Non-repudiation established\n")
                    else:
                        self.signature_display.insert('end', "\n✗ SIGNATURE INVALID!\n")
                        self.signature_display.insert('end', "⚠ Document may have been tampered with\n")
                        self.signature_display.insert('end', "⚠ Sender identity cannot be verified\n")
                        if 'message' in result:
                            self.signature_display.insert('end', f"Details: {result['message']}\n")
                else:
                    raise Exception(result['message'])
            else:
                # Simulation mode
                self.signature_display.insert('end', "\n✓ Signature verified (simulation mode)!\n")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify signature: {str(e)}")
            
    def run_comparison(self):
        try:
            # Clear previous plot
            self.ax.clear()
            
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
                        self.ax.bar(methods, values, color=['#ff7f0e', '#2ca02c', '#d62728'])
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
                                   label='Security Level', color='#2ca02c')
                bars2 = self.ax.bar([i + width/2 for i in x], performance_scores, width,
                                   label='Performance', color='#ff7f0e')
                
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
            
        except Exception as e:
            messagebox.showerror("Error", f"Comparison failed: {str(e)}")
    
    
    def create_tools_tab(self):
        """Create the cryptographic tools demonstration tab"""
        try:
            self.tool_integration = CryptographicToolIntegration()
            
            # Tool selection frame
            tool_frame = ttk.LabelFrame(self.tools_frame, text="Cryptographic Tools Demo")
            tool_frame.pack(fill='x', padx=10, pady=5)
            
            # OpenSSL demo
            ttk.Button(tool_frame, text="OpenSSL Key Generation", 
                      command=self.demo_openssl_keygen).pack(side='left', padx=5, pady=5)
            ttk.Button(tool_frame, text="GnuPG Email Encryption", 
                      command=self.demo_gnupg_email).pack(side='left', padx=5, pady=5)
            ttk.Button(tool_frame, text="Wireshark VPN Analysis", 
                      command=self.demo_wireshark_vpn).pack(side='left', padx=5, pady=5)
            
            # Workflow demo frame
            workflow_frame = ttk.LabelFrame(self.tools_frame, text="Command-Line Workflows")
            workflow_frame.pack(fill='x', padx=10, pady=5)
            
            ttk.Button(workflow_frame, text="Email Workflow", 
                      command=lambda: self.demo_bash_workflow('email')).pack(side='left', padx=5, pady=5)
            ttk.Button(workflow_frame, text="VPN Workflow", 
                      command=lambda: self.demo_bash_workflow('vpn')).pack(side='left', padx=5, pady=5)
            ttk.Button(workflow_frame, text="Signature Workflow", 
                      command=lambda: self.demo_bash_workflow('signature')).pack(side='left', padx=5, pady=5)
            
            # Results display
            results_frame = ttk.LabelFrame(self.tools_frame, text="Tool Output")
            results_frame.pack(fill='both', expand=True, padx=10, pady=5)
            
            self.tools_output = scrolledtext.ScrolledText(results_frame, height=20)
            self.tools_output.pack(fill='both', expand=True, padx=5, pady=5)
            
            # Initial message
            self.tools_output.insert('end', "CipherGuard - Cryptographic Tools Integration\n")
            self.tools_output.insert('end', "="*50 + "\n\n")
            self.tools_output.insert('end', "This tab demonstrates the use of industry-standard cryptographic tools:\n")
            self.tools_output.insert('end', "• OpenSSL - RSA key generation and encryption\n")
            self.tools_output.insert('end', "• GnuPG - Email encryption and digital signatures\n")
            self.tools_output.insert('end', "• Wireshark - Network traffic analysis for VPN\n\n")
            self.tools_output.insert('end', "Click any button above to see tool demonstrations.\n\n")
            
        except Exception as e:
            ttk.Label(self.tools_frame, 
                     text=f"Tools demo unavailable: {str(e)}").pack(pady=20)
    
    def demo_openssl_keygen(self):
        """Demonstrate OpenSSL key generation"""
        try:
            self.tools_output.insert('end', "\n" + "="*50 + "\n")
            self.tools_output.insert('end', "OpenSSL RSA Key Generation Demo\n")
            self.tools_output.insert('end', "="*50 + "\n")
            
            result = self.tool_integration.openssl_demo("genrsa")
            
            if result['status'] == 'success':
                self.tools_output.insert('end', f"✓ {result['message']}\n")
                self.tools_output.insert('end', f"Command used: {result['command']}\n")
                self.tools_output.insert('end', f"Private key: {result['private_key_file']}\n")
                self.tools_output.insert('end', f"Public key: {result['public_key_file']}\n")
            elif result['status'] == 'simulated':
                self.tools_output.insert('end', f"ℹ {result['message']}\n\n")
                for line in result['demonstration']:
                    self.tools_output.insert('end', f"{line}\n")
            
            self.tools_output.see('end')
            
        except Exception as e:
            self.tools_output.insert('end', f"Error in OpenSSL demo: {str(e)}\n")
    
    def demo_gnupg_email(self):
        """Demonstrate GnuPG email encryption"""
        try:
            self.tools_output.insert('end', "\n" + "="*50 + "\n")
            self.tools_output.insert('end', "GnuPG Email Encryption Demo\n")
            self.tools_output.insert('end', "="*50 + "\n")
            
            result = self.tool_integration.gnupg_demo("encrypt")
            
            if result['status'] == 'simulated':
                self.tools_output.insert('end', f"ℹ {result['message']}\n\n")
                for line in result['demonstration']:
                    self.tools_output.insert('end', f"{line}\n")
            
            self.tools_output.see('end')
            
        except Exception as e:
            self.tools_output.insert('end', f"Error in GnuPG demo: {str(e)}\n")
    
    def demo_wireshark_vpn(self):
        """Demonstrate Wireshark VPN traffic analysis"""
        try:
            self.tools_output.insert('end', "\n" + "="*50 + "\n")
            self.tools_output.insert('end', "Wireshark VPN Traffic Analysis Demo\n")
            self.tools_output.insert('end', "="*50 + "\n")
            
            result = self.tool_integration.wireshark_simulation()
            
            self.tools_output.insert('end', f"ℹ {result['message']}\n\n")
            self.tools_output.insert('end', "Captured Network Packets:\n")
            self.tools_output.insert('end', "-" * 80 + "\n")
            self.tools_output.insert('end', f"{'Time':<12} {'Source':<15} {'Destination':<15} {'Protocol':<8} {'Info'}\n")
            self.tools_output.insert('end', "-" * 80 + "\n")
            
            for packet in result['packets']:
                self.tools_output.insert('end', 
                    f"{packet['time']:<12} {packet['source']:<15} {packet['destination']:<15} "
                    f"{packet['protocol']:<8} {packet['info']}\n")
            
            self.tools_output.insert('end', "\nTraffic Analysis:\n")
            for analysis in result['analysis']:
                self.tools_output.insert('end', f"• {analysis}\n")
            
            self.tools_output.see('end')
            
        except Exception as e:
            self.tools_output.insert('end', f"Error in Wireshark demo: {str(e)}\n")
    
    def demo_bash_workflow(self, workflow_type):
        """Demonstrate bash cryptographic workflows"""
        try:
            self.tools_output.insert('end', "\n" + "="*50 + "\n")
            self.tools_output.insert('end', f"Bash Cryptographic Workflow - {workflow_type.title()}\n")
            self.tools_output.insert('end', "="*50 + "\n")
            
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
            
        except Exception as e:
            self.tools_output.insert('end', f"Error in workflow demo: {str(e)}\n")