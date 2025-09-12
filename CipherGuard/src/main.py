import tkinter as tk
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from gui.complete_modern_gui import CompleteCipherGuardGUI
from simulations.email_sim import SecureEmailSimulation
from simulations.vpn_sim import VPNSimulation
from simulations.digital_signature import DigitalSignature
from crypto.message_storage import MessageStorage
from analysis.comparison import SecurityMethodComparison

class CipherGuardApp:
    def __init__(self):
        self.root = tk.Tk()
        
        # Initialize simulation engines first
        self.email_sim = SecureEmailSimulation()
        self.vpn_sim = VPNSimulation()
        self.signature_engine = DigitalSignature()
        self.message_storage = MessageStorage()
        self.comparison_engine = SecurityMethodComparison()
        
        # Create GUI after initializing backends
        self.gui = CompleteCipherGuardGUI(self.root)
        
        # Connect GUI to backend
        self.connect_gui_handlers()
    
    def create_delete_document_handler(self):
        """Create a handler for deleting signed documents"""
        def delete_document(filename):
            try:
                filepath = os.path.join(self.signature_engine.storage_dir, filename)
                if os.path.exists(filepath):
                    os.remove(filepath)
                    return {'status': 'success'}
                else:
                    return {'status': 'error', 'message': 'File not found'}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
        return delete_document
    
    def connect_gui_handlers(self):
        """Connect GUI buttons to backend functions"""
        # Set up email handlers
        self.gui.set_email_handlers(
            generate_keys=self.email_sim.generate_keys,
            encrypt=self.email_sim.encrypt_email,
            decrypt=self.email_sim.verify_and_decrypt
        )
        
        # Set up VPN handlers
        self.gui.set_vpn_handlers(
            init_vpn=self.vpn_sim.handshake,
            start_vpn=lambda: self.vpn_sim.establish_tunnel(),
            stop_vpn=lambda: self.vpn_sim.close_tunnel(),
            get_status=lambda: self.vpn_sim.get_status()
        )
        
        # Set up signature handlers with enhanced document management
        self.gui.set_signature_handlers(
            generate_keys=self.signature_engine.generate_keys,
            sign=self.signature_engine.sign_document,
            verify=self.signature_engine.verify_signature,
            save_document=self.signature_engine.save_signed_document,
            load_document=self.signature_engine.load_signed_document,
            list_documents=self.signature_engine.list_signed_documents,
            verify_external=self.signature_engine.verify_external_signed_document,
            export_key=self.signature_engine.export_public_key,
            import_key=self.signature_engine.import_public_key,
            delete_document=self.create_delete_document_handler()
        )
        
        # Set up message storage handler
        self.gui.set_message_storage_handler(self.message_storage)
        
        # Set up comparison handler
        self.gui.set_comparison_handler(self.comparison_engine.generate_comparison_chart)
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = CipherGuardApp()
    app.run()