import os
import tkinter as tk
from tkinter import filedialog, messagebox
import secrets
import string
from datetime import datetime

class KeyManagementMixin:
    """Mixin class for key management operations"""
    
    def __init__(self):
        self.key_visible = False
        self.email_key_visible = False
    
    def generate_and_save_key(self):
        """Generate a new encryption key and save it to file"""
        try:
            # Generate a secure random key
            key = self.generate_secure_key()
            
            # Set the key in the entry field
            self.key_entry.delete(0, 'end')
            self.key_entry.insert(0, key)
            
            # Ask user where to save the key
            key_file = filedialog.asksaveasfilename(
                title="Save Encryption Key",
                defaultextension=".key",
                filetypes=[("Key files", "*.key"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if key_file:
                # Save key to file
                with open(key_file, 'w') as f:
                    f.write(f"# CipherGuard Encryption Key\n")
                    f.write(f"# Generated: {datetime.now().isoformat()}\n")
                    f.write(f"# KEEP THIS KEY SECURE AND PRIVATE\n")
                    f.write(f"{key}\n")
                
                self.file_results.insert('end', f"🔑 New encryption key generated!\n")
                self.file_results.insert('end', f"💾 Key saved to: {os.path.basename(key_file)}\n")
                self.file_results.insert('end', f"⚠️ IMPORTANT: Store this key file securely!\n")
                self.file_results.insert('end', f"📍 Key location: {key_file}\n")
                self.file_results.insert('end', f"🔒 You'll need this key to decrypt your files\n\n")
                
                # Show security guidance
                self.show_key_security_guidance()
                
                self.file_keys_generated = True
                self.update_status("Key generated and saved successfully")
                self.file_results.see('end')
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate and save key: {str(e)}")
            self.update_status("Key generation failed")
    
    def generate_and_save_email_key(self):
        """Generate a new email encryption key and save it to file"""
        try:
            # Generate a secure random key
            key = self.generate_secure_key()
            
            # Set the key in the entry field
            self.email_key_entry.delete(0, 'end')
            self.email_key_entry.insert(0, key)
            
            # Ask user where to save the key
            key_file = filedialog.asksaveasfilename(
                title="Save Email Encryption Key",
                defaultextension=".key",
                filetypes=[("Key files", "*.key"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if key_file:
                # Save key to file
                with open(key_file, 'w') as f:
                    f.write(f"# CipherGuard Email Encryption Key\n")
                    f.write(f"# Generated: {datetime.now().isoformat()}\n")
                    f.write(f"# KEEP THIS KEY SECURE AND PRIVATE\n")
                    f.write(f"{key}\n")
                
                self.email_results.insert('end', f"🔑 New email encryption key generated!\n")
                self.email_results.insert('end', f"💾 Key saved to: {os.path.basename(key_file)}\n")
                self.email_results.insert('end', f"⚠️ IMPORTANT: Store this key file securely!\n")
                self.email_results.insert('end', f"📍 Key location: {key_file}\n")
                self.email_results.insert('end', f"🔒 You'll need this key to decrypt your emails\n\n")
                
                # Show security guidance
                self.show_key_security_guidance()
                
                self._keys_generated = True
                self.update_status("Email key generated and saved successfully")
                self.email_results.see('end')
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate and save email key: {str(e)}")
            self.update_status("Email key generation failed")
    
    def load_key_file(self):
        """Load encryption key from file"""
        try:
            key_file = filedialog.askopenfilename(
                title="Load Encryption Key",
                filetypes=[("Key files", "*.key"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if key_file:
                with open(key_file, 'r') as f:
                    content = f.read().strip()
                    
                # Extract key from file (skip comment lines)
                lines = content.split('\n')
                key = None
                for line in lines:
                    if not line.startswith('#') and line.strip():
                        key = line.strip()
                        break
                
                if key:
                    self.key_entry.delete(0, 'end')
                    self.key_entry.insert(0, key)
                    
                    self.file_results.insert('end', f"🔑 Encryption key loaded successfully!\n")
                    self.file_results.insert('end', f"📥 From: {os.path.basename(key_file)}\n")
                    self.file_results.insert('end', f"✅ Ready for file operations\n\n")
                    
                    self.file_keys_generated = True
                    self.update_status("Key loaded successfully")
                    self.file_results.see('end')
                else:
                    raise Exception("No valid key found in file")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load key: {str(e)}")
            self.update_status("Key loading failed")
    
    def load_email_key_file(self):
        """Load email encryption key from file"""
        try:
            key_file = filedialog.askopenfilename(
                title="Load Email Encryption Key",
                filetypes=[("Key files", "*.key"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if key_file:
                with open(key_file, 'r') as f:
                    content = f.read().strip()
                    
                # Extract key from file (skip comment lines)
                lines = content.split('\n')
                key = None
                for line in lines:
                    if not line.startswith('#') and line.strip():
                        key = line.strip()
                        break
                
                if key:
                    self.email_key_entry.delete(0, 'end')
                    self.email_key_entry.insert(0, key)
                    
                    self.email_results.insert('end', f"🔑 Email encryption key loaded successfully!\n")
                    self.email_results.insert('end', f"📥 From: {os.path.basename(key_file)}\n")
                    self.email_results.insert('end', f"✅ Ready for email operations\n\n")
                    
                    self._keys_generated = True
                    self.update_status("Email key loaded successfully")
                    self.email_results.see('end')
                else:
                    raise Exception("No valid key found in file")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load email key: {str(e)}")
            self.update_status("Email key loading failed")
    
    def toggle_key_visibility(self):
        """Toggle visibility of the encryption key"""
        self.key_visible = not self.key_visible
        if self.key_visible:
            self.key_entry.config(show='')
        else:
            self.key_entry.config(show='*')
    
    def toggle_email_key_visibility(self):
        """Toggle visibility of the email encryption key"""
        self.email_key_visible = not self.email_key_visible
        if self.email_key_visible:
            self.email_key_entry.config(show='')
        else:
            self.email_key_entry.config(show='*')
    
    def generate_secure_key(self, length=32):
        """Generate a cryptographically secure random key"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def show_key_security_guidance(self):
        """Show security guidance for key storage"""
        guidance_msg = """🔐 KEY SECURITY GUIDANCE

Your encryption key has been saved. Please follow these security practices:

✅ RECOMMENDED:
• Store the key file in a secure location (encrypted drive, password manager)
• Make a backup copy in a different secure location
• Never share your key via email or messaging apps
• Use a strong password to protect the folder containing your key

❌ AVOID:
• Storing keys on cloud storage without encryption
• Leaving key files on desktop or downloads folder
• Sharing keys through unsecured channels
• Using the same key for multiple sensitive files

💡 TIP: Remember the location where you saved your key file - you'll need it to decrypt your files later!"""
        
        messagebox.showinfo("Key Security Guidance", guidance_msg)
    
    def get_current_key(self):
        """Get the current encryption key from the input field"""
        return self.key_entry.get().strip() if hasattr(self, 'key_entry') else ""
    
    def get_current_email_key(self):
        """Get the current email encryption key from the input field"""
        return self.email_key_entry.get().strip() if hasattr(self, 'email_key_entry') else ""
    
    def validate_key(self, key):
        """Validate if the provided key is suitable for encryption"""
        if not key:
            return False, "Key cannot be empty"
        if len(key) < 8:
            return False, "Key must be at least 8 characters long"
        return True, "Key is valid"