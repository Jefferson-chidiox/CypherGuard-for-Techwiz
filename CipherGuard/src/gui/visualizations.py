import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.patches as patches
from matplotlib.animation import FuncAnimation
import numpy as np

class CryptoVisualization:
    def __init__(self, parent_frame):
        self.parent = parent_frame
        self.fig, self.ax = plt.subplots(figsize=(10, 6))
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
        
    def visualize_email_encryption(self, step="start"):
        """Visualize email encryption process"""
        self.ax.clear()
        
        if step == "key_generation":
            self._draw_key_generation()
        elif step == "encryption":
            self._draw_encryption_process()
        elif step == "transmission":
            self._draw_secure_transmission()
        elif step == "decryption":
            self._draw_decryption_process()
        else:
            self._draw_overview()
            
        self.canvas.draw()
    
    def visualize_vpn_handshake(self, step="start"):
        """Visualize VPN handshake process"""
        self.ax.clear()
        
        if step == "handshake":
            self._draw_vpn_handshake()
        elif step == "key_exchange":
            self._draw_key_exchange()
        elif step == "tunnel":
            self._draw_tunnel_establishment()
        else:
            self._draw_vpn_overview()
            
        self.canvas.draw()
    
    def visualize_digital_signature(self, step="start"):
        """Visualize digital signature process"""
        self.ax.clear()
        
        if step == "signing":
            self._draw_signing_process()
        elif step == "verification":
            self._draw_verification_process()
        else:
            self._draw_signature_overview()
            
        self.canvas.draw()
    
    def _draw_key_generation(self):
        """Draw RSA key generation visualization"""
        self.ax.set_xlim(0, 10)
        self.ax.set_ylim(0, 6)
        
        # Draw key generation process
        self.ax.text(5, 5, 'RSA Key Generation', ha='center', fontsize=16, fontweight='bold')
        
        # Private key
        private_rect = patches.Rectangle((1, 3), 3, 1, linewidth=2, edgecolor='red', facecolor='lightcoral')
        self.ax.add_patch(private_rect)
        self.ax.text(2.5, 3.5, 'Private Key\n(Keep Secret)', ha='center', va='center', fontsize=10)
        
        # Public key
        public_rect = patches.Rectangle((6, 3), 3, 1, linewidth=2, edgecolor='green', facecolor='lightgreen')
        self.ax.add_patch(public_rect)
        self.ax.text(7.5, 3.5, 'Public Key\n(Share Freely)', ha='center', va='center', fontsize=10)
        
        # Arrow showing generation
        self.ax.arrow(5, 2, 0, 0.8, head_width=0.2, head_length=0.1, fc='blue', ec='blue')
        self.ax.text(5, 1.5, 'Key Pair Generation\n(2048-bit RSA)', ha='center', fontsize=10)
        
        self.ax.set_title('Step 1: Generate RSA Key Pairs')
        self.ax.axis('off')
    
    def _draw_encryption_process(self):
        """Draw hybrid encryption visualization"""
        self.ax.set_xlim(0, 12)
        self.ax.set_ylim(0, 8)
        
        # Original message
        msg_rect = patches.Rectangle((1, 6), 2, 1, linewidth=2, edgecolor='blue', facecolor='lightblue')
        self.ax.add_patch(msg_rect)
        self.ax.text(2, 6.5, 'Message', ha='center', va='center', fontsize=10)
        
        # AES key generation
        aes_rect = patches.Rectangle((1, 4), 2, 1, linewidth=2, edgecolor='orange', facecolor='moccasin')
        self.ax.add_patch(aes_rect)
        self.ax.text(2, 4.5, 'AES Key\n(Random)', ha='center', va='center', fontsize=9)
        
        # AES encryption
        self.ax.arrow(3.2, 6.5, 1.5, 0, head_width=0.2, head_length=0.2, fc='blue', ec='blue')
        self.ax.text(4, 7, 'AES Encrypt', ha='center', fontsize=9)
        
        encrypted_msg = patches.Rectangle((5, 6), 2, 1, linewidth=2, edgecolor='purple', facecolor='plum')
        self.ax.add_patch(encrypted_msg)
        self.ax.text(6, 6.5, 'Encrypted\nMessage', ha='center', va='center', fontsize=9)
        
        # RSA encryption of AES key
        self.ax.arrow(3.2, 4.5, 1.5, 0, head_width=0.2, head_length=0.2, fc='orange', ec='orange')
        self.ax.text(4, 3.8, 'RSA Encrypt', ha='center', fontsize=9)
        
        encrypted_key = patches.Rectangle((5, 4), 2, 1, linewidth=2, edgecolor='red', facecolor='lightcoral')
        self.ax.add_patch(encrypted_key)
        self.ax.text(6, 4.5, 'Encrypted\nAES Key', ha='center', va='center', fontsize=9)
        
        # Public key
        pub_key = patches.Rectangle((8, 2), 2, 1, linewidth=2, edgecolor='green', facecolor='lightgreen')
        self.ax.add_patch(pub_key)
        self.ax.text(9, 2.5, "Recipient's\nPublic Key", ha='center', va='center', fontsize=9)
        
        self.ax.set_title('Step 2: Hybrid Encryption (RSA + AES)')
        self.ax.axis('off')
    
    def _draw_signing_process(self):
        """Draw digital signature process"""
        self.ax.set_xlim(0, 12)
        self.ax.set_ylim(0, 8)
        
        # Document
        doc_rect = patches.Rectangle((1, 6), 2, 1, linewidth=2, edgecolor='blue', facecolor='lightblue')
        self.ax.add_patch(doc_rect)
        self.ax.text(2, 6.5, 'Document', ha='center', va='center', fontsize=10)
        
        # Hash function
        self.ax.arrow(3.2, 6.5, 1.5, -1, head_width=0.2, head_length=0.2, fc='blue', ec='blue')
        self.ax.text(4, 6, 'SHA-256\nHash', ha='center', fontsize=9)
        
        hash_rect = patches.Rectangle((5, 4.5), 2, 1, linewidth=2, edgecolor='orange', facecolor='moccasin')
        self.ax.add_patch(hash_rect)
        self.ax.text(6, 5, 'Document\nHash', ha='center', va='center', fontsize=9)
        
        # Private key signing
        self.ax.arrow(7.2, 5, 1.5, 0, head_width=0.2, head_length=0.2, fc='red', ec='red')
        self.ax.text(8, 5.5, 'Sign with\nPrivate Key', ha='center', fontsize=9)
        
        signature_rect = patches.Rectangle((9, 4.5), 2, 1, linewidth=2, edgecolor='purple', facecolor='plum')
        self.ax.add_patch(signature_rect)
        self.ax.text(10, 5, 'Digital\nSignature', ha='center', va='center', fontsize=9)
        
        # Private key
        priv_key = patches.Rectangle((5, 2), 2, 1, linewidth=2, edgecolor='red', facecolor='lightcoral')
        self.ax.add_patch(priv_key)
        self.ax.text(6, 2.5, 'Private Key\n(Signer)', ha='center', va='center', fontsize=9)
        
        self.ax.set_title('Digital Signature Creation Process')
        self.ax.axis('off')
    
    def _draw_verification_process(self):
        """Draw signature verification process"""
        self.ax.set_xlim(0, 12)
        self.ax.set_ylim(0, 8)
        
        # Received document
        doc_rect = patches.Rectangle((1, 6), 2, 1, linewidth=2, edgecolor='blue', facecolor='lightblue')
        self.ax.add_patch(doc_rect)
        self.ax.text(2, 6.5, 'Document', ha='center', va='center', fontsize=10)
        
        # Received signature
        sig_rect = patches.Rectangle((1, 4), 2, 1, linewidth=2, edgecolor='purple', facecolor='plum')
        self.ax.add_patch(sig_rect)
        self.ax.text(2, 4.5, 'Signature', ha='center', va='center', fontsize=10)
        
        # Hash document
        self.ax.arrow(3.2, 6.5, 1.5, -0.5, head_width=0.2, head_length=0.2, fc='blue', ec='blue')
        self.ax.text(4, 6.2, 'Hash', ha='center', fontsize=9)
        
        hash1_rect = patches.Rectangle((5, 5.5), 2, 1, linewidth=2, edgecolor='orange', facecolor='moccasin')
        self.ax.add_patch(hash1_rect)
        self.ax.text(6, 6, 'Hash 1', ha='center', va='center', fontsize=9)
        
        # Decrypt signature
        self.ax.arrow(3.2, 4.5, 1.5, 0.5, head_width=0.2, head_length=0.2, fc='purple', ec='purple')
        self.ax.text(4, 4.2, 'Decrypt with\nPublic Key', ha='center', fontsize=9)
        
        hash2_rect = patches.Rectangle((5, 3.5), 2, 1, linewidth=2, edgecolor='orange', facecolor='moccasin')
        self.ax.add_patch(hash2_rect)
        self.ax.text(6, 4, 'Hash 2', ha='center', va='center', fontsize=9)
        
        # Compare
        self.ax.arrow(7.2, 5.5, 1.5, -0.5, head_width=0.2, head_length=0.2, fc='green', ec='green')
        self.ax.arrow(7.2, 4, 1.5, 0.5, head_width=0.2, head_length=0.2, fc='green', ec='green')
        
        result_rect = patches.Rectangle((9, 4.5), 2, 1, linewidth=2, edgecolor='green', facecolor='lightgreen')
        self.ax.add_patch(result_rect)
        self.ax.text(10, 5, 'Compare\n✓ Valid', ha='center', va='center', fontsize=9)
        
        self.ax.set_title('Digital Signature Verification Process')
        self.ax.axis('off')
    
    def _draw_vpn_handshake(self):
        """Draw VPN handshake visualization"""
        self.ax.set_xlim(0, 12)
        self.ax.set_ylim(0, 8)
        
        # Client
        client_rect = patches.Rectangle((1, 6), 2, 1.5, linewidth=2, edgecolor='blue', facecolor='lightblue')
        self.ax.add_patch(client_rect)
        self.ax.text(2, 6.75, 'VPN\nClient', ha='center', va='center', fontsize=10)
        
        # Server
        server_rect = patches.Rectangle((9, 6), 2, 1.5, linewidth=2, edgecolor='green', facecolor='lightgreen')
        self.ax.add_patch(server_rect)
        self.ax.text(10, 6.75, 'VPN\nServer', ha='center', va='center', fontsize=10)
        
        # Handshake arrows
        self.ax.arrow(3.2, 7, 5.5, 0, head_width=0.2, head_length=0.3, fc='blue', ec='blue')
        self.ax.text(6, 7.3, '1. Client Hello + Public Key', ha='center', fontsize=9)
        
        self.ax.arrow(8.8, 6.5, -5.5, 0, head_width=0.2, head_length=0.3, fc='green', ec='green')
        self.ax.text(6, 6.2, '2. Server Hello + Public Key', ha='center', fontsize=9)
        
        # Session key
        session_rect = patches.Rectangle((5, 4), 2, 1, linewidth=2, edgecolor='orange', facecolor='moccasin')
        self.ax.add_patch(session_rect)
        self.ax.text(6, 4.5, 'Session Key\n(AES)', ha='center', va='center', fontsize=9)
        
        self.ax.arrow(3.2, 6, 1.5, -1.2, head_width=0.2, head_length=0.2, fc='orange', ec='orange')
        self.ax.arrow(7.2, 4.5, 1.5, 1.2, head_width=0.2, head_length=0.2, fc='orange', ec='orange')
        self.ax.text(4, 5, 'Generate', ha='center', fontsize=8)
        self.ax.text(8, 5, 'Encrypt &\nSend', ha='center', fontsize=8)
        
        self.ax.set_title('VPN Handshake Process')
        self.ax.axis('off')
    
    def _draw_overview(self):
        """Draw general overview"""
        self.ax.text(0.5, 0.5, 'CipherGuard Cryptographic Simulation\n\nSelect an operation to see visualization', 
                    ha='center', va='center', transform=self.ax.transAxes, fontsize=14)
        self.ax.axis('off')
    
    def _draw_vpn_overview(self):
        self._draw_overview()
    
    def _draw_signature_overview(self):
        self._draw_overview()

class ProcessFlowVisualization:
    """Enhanced visualization for step-by-step process flows"""
    
    def __init__(self, parent_frame):
        self.parent = parent_frame
        self.setup_ui()
    
    def setup_ui(self):
        # Create control frame
        control_frame = ttk.Frame(self.parent)
        control_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(control_frame, text="Process Visualization:").pack(side='left', padx=5)
        
        self.process_var = tk.StringVar(value="email")
        process_combo = ttk.Combobox(control_frame, textvariable=self.process_var, 
                                   values=["email", "vpn", "signature"], state="readonly")
        process_combo.pack(side='left', padx=5)
        process_combo.bind('<<ComboboxSelected>>', self.on_process_change)
        
        ttk.Button(control_frame, text="Next Step", command=self.next_step).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Reset", command=self.reset).pack(side='left', padx=5)
        
        # Create visualization frame
        viz_frame = ttk.Frame(self.parent)
        viz_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.visualization = CryptoVisualization(viz_frame)
        self.current_step = 0
        self.steps = {
            "email": ["start", "key_generation", "encryption", "transmission", "decryption"],
            "vpn": ["start", "handshake", "key_exchange", "tunnel"],
            "signature": ["start", "signing", "verification"]
        }
    
    def on_process_change(self, event=None):
        self.reset()
    
    def next_step(self):
        process = self.process_var.get()
        steps = self.steps[process]
        
        if self.current_step < len(steps) - 1:
            self.current_step += 1
        else:
            self.current_step = 0
            
        step = steps[self.current_step]
        
        if process == "email":
            self.visualization.visualize_email_encryption(step)
        elif process == "vpn":
            self.visualization.visualize_vpn_handshake(step)
        elif process == "signature":
            self.visualization.visualize_digital_signature(step)
    
    def reset(self):
        self.current_step = 0
        process = self.process_var.get()
        
        if process == "email":
            self.visualization.visualize_email_encryption("start")
        elif process == "vpn":
            self.visualization.visualize_vpn_handshake("start")
        elif process == "signature":
            self.visualization.visualize_digital_signature("start")