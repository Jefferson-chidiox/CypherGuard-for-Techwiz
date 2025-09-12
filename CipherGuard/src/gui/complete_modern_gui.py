import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime
import os
import matplotlib
matplotlib.use('TkAgg')
from gui.visualizations import ProcessFlowVisualization
from utils.tool_integration import CryptographicToolIntegration
from gui.file_handlers import FileHandlerMixin

class CompleteCipherGuardGUI(FileHandlerMixin):
    def __init__(self, root):
        self.root = root
        self.root.title("CipherGuard - Advanced Cryptographic Security Suite")
        
        # Make window responsive to screen size
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Set window to 85% of screen size with reasonable maximums
        window_width = min(int(screen_width * 0.85), 1200)
        window_height = min(int(screen_height * 0.85), 800)
        
        # Center window on screen
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.root.configure(bg='#f0f0f0')
        
        # Make window resizable
        self.root.resizable(True, True)
        
        # Set minimum window size
        self.root.minsize(900, 600)
        
        # Add keyboard shortcuts for better navigation
        self.root.bind('<Control-Tab>', self.next_tab)
        self.root.bind('<Control-Shift-Tab>', self.prev_tab)
        self.root.bind('<F11>', self.toggle_fullscreen)
        
        # Modern color scheme
        self.colors = {
            'primary': '#2c3e50',
            'secondary': '#3498db', 
            'success': '#27ae60',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'light': '#ecf0f1',
            'dark': '#34495e',
            'accent': '#9b59b6'
        }
        
        # Configure modern styles
        self.setup_styles()
        
        # Initialize handlers
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
        
        # Initialize state variables
        self.last_encrypted_result = None
        self.selected_file_path = None
        
        # Tutorial state
        self.tutorial_active = False
        self.tutorial_step = 0
        
        self.create_modern_interface()
        self.show_welcome_guide()
    
    def create_scrollable_frame(self, parent):
        """Create a scrollable frame for tab content"""
        # Create canvas and scrollbar
        canvas = tk.Canvas(parent, bg=self.colors['light'])
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.colors['light'])
        
        # Configure scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind mouse wheel to canvas
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        return scrollable_frame
    
    def next_tab(self, event=None):
        """Navigate to next tab"""
        current = self.notebook.index(self.notebook.select())
        total = self.notebook.index('end')
        next_tab = (current + 1) % total
        self.notebook.select(next_tab)
    
    def prev_tab(self, event=None):
        """Navigate to previous tab"""
        current = self.notebook.index(self.notebook.select())
        total = self.notebook.index('end')
        prev_tab = (current - 1) % total
        self.notebook.select(prev_tab)
    
    def toggle_fullscreen(self, event=None):
        """Toggle fullscreen mode"""
        current_state = self.root.attributes('-fullscreen')
        self.root.attributes('-fullscreen', not current_state)
    
    def setup_styles(self):
        """Configure modern ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure notebook style
        style.configure('Modern.TNotebook', background=self.colors['light'])
        style.configure('Modern.TNotebook.Tab', 
                       background=self.colors['primary'],
                       foreground='white',
                       padding=[20, 10])
        style.map('Modern.TNotebook.Tab',
                 background=[('selected', self.colors['secondary'])])
        
        # Configure button styles
        style.configure('Primary.TButton',
                       background=self.colors['secondary'],
                       foreground='white',
                       padding=[15, 8],
                       font=('Segoe UI', 10, 'bold'))
        style.map('Primary.TButton',
                 background=[('active', self.colors['primary'])])
        
        style.configure('Success.TButton',
                       background=self.colors['success'],
                       foreground='white',
                       padding=[15, 8])
        
        style.configure('Warning.TButton',
                       background=self.colors['warning'],
                       foreground='white',
                       padding=[15, 8])
    
    def create_modern_interface(self):
        """Create the modern interface layout"""
        # Header frame (reduced height)
        header_frame = tk.Frame(self.root, bg=self.colors['primary'], height=60)
        header_frame.pack(fill='x', side='top')
        header_frame.pack_propagate(False)
        
        # Title and subtitle (compact)
        title_label = tk.Label(header_frame, 
                              text="CipherGuard", 
                              font=('Segoe UI', 20, 'bold'),
                              fg='white', 
                              bg=self.colors['primary'])
        title_label.pack(pady=(8, 0))
        
        subtitle_label = tk.Label(header_frame,
                                 text="Advanced Cryptographic Security & Education Platform",
                                 font=('Segoe UI', 9),
                                 fg=self.colors['light'],
                                 bg=self.colors['primary'])
        subtitle_label.pack()
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['light'])
        main_container.pack(fill='both', expand=True, padx=10, pady=(10, 5))
        
        # Create notebook with modern styling
        self.notebook = ttk.Notebook(main_container, style='Modern.TNotebook')
        self.notebook.pack(fill='both', expand=True)
        
        # Create tabs
        self.create_file_encryption_tab()
        self.create_vpn_tab()
        self.create_signature_tab()
        self.create_comparison_tab()
        self.create_storage_tab()
        self.create_tools_tab()
        
        # Status bar
        self.create_status_bar()
    
    def create_file_encryption_tab(self):
        """Create unified secure communication tab for files and messages"""
        self.secure_comm_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.secure_comm_frame, text='🔐 Secure Communication')
        
        # Welcome section
        welcome_frame = tk.Frame(self.secure_comm_frame, bg='white', relief='raised', bd=1)
        welcome_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(welcome_frame, 
                text="🔐 Secure Communication Hub",
                font=('Segoe UI', 16, 'bold'),
                bg='white',
                fg=self.colors['primary']).pack(pady=10)
        
        tk.Label(welcome_frame,
                text="Encrypt files (.txt, .eml) or compose secure messages - all saved in unified encrypted format",
                font=('Segoe UI', 10),
                bg='white',
                fg=self.colors['dark']).pack(pady=(0, 10))
        
        # Input method selection
        input_section = tk.LabelFrame(self.secure_comm_frame, text="Input Method", 
                                     font=('Segoe UI', 12, 'bold'),
                                     fg=self.colors['primary'])
        input_section.pack(fill='x', padx=10, pady=10)
        
        # Radio buttons for input method
        self.input_method = tk.StringVar(value="message")
        method_frame = tk.Frame(input_section)
        method_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Radiobutton(method_frame, text="📝 Compose Message", 
                      variable=self.input_method, value="message",
                      command=self.toggle_input_method,
                      font=('Segoe UI', 10)).pack(side='left', padx=10)
        
        tk.Radiobutton(method_frame, text="📁 Upload File", 
                      variable=self.input_method, value="file",
                      command=self.toggle_input_method,
                      font=('Segoe UI', 10)).pack(side='left', padx=10)
        
        # Message composition area
        self.message_section = tk.LabelFrame(self.secure_comm_frame, text="Message Content",
                                            font=('Segoe UI', 12, 'bold'),
                                            fg=self.colors['primary'])
        self.message_section.pack(fill='x', padx=10, pady=10)
        
        tk.Label(self.message_section, text="Enter your message:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=10, pady=(10, 5))
        self.message_content = scrolledtext.ScrolledText(self.message_section, height=6, font=('Segoe UI', 10))
        self.message_content.pack(fill='x', padx=10, pady=(0, 10))
        
        # File selection area (initially hidden)
        self.file_section = tk.LabelFrame(self.secure_comm_frame, text="File Selection", 
                                         font=('Segoe UI', 12, 'bold'),
                                         fg=self.colors['primary'])
        
        # File path display
        self.file_path_var = tk.StringVar(value="No file selected")
        file_path_frame = tk.Frame(self.file_section)
        file_path_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(file_path_frame, text="Selected File:", font=('Segoe UI', 10, 'bold')).pack(anchor='w')
        self.file_path_label = tk.Label(file_path_frame, textvariable=self.file_path_var,
                                       font=('Segoe UI', 9), fg=self.colors['secondary'])
        self.file_path_label.pack(anchor='w', pady=(5, 0))
        
        # Single file selection button
        file_btn_frame = tk.Frame(self.file_section)
        file_btn_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(file_btn_frame, text="📁 Select File (.txt, .eml, .enc)", 
                  command=self.select_file,
                  style='Primary.TButton').pack(side='left', padx=5)
        
        # File type description
        tk.Label(self.file_section, 
                text="Supported formats: .txt (text), .eml (email), .enc (encrypted)",
                font=('Segoe UI', 9),
                fg=self.colors['dark']).pack(padx=10, pady=(0, 10))
        
        # Key management section
        key_section = tk.LabelFrame(self.secure_comm_frame, text="Encryption Key Management",
                                   font=('Segoe UI', 12, 'bold'),
                                   fg=self.colors['primary'])
        key_section.pack(fill='x', padx=10, pady=10)
        
        # Key text area
        key_text_frame = tk.Frame(key_section)
        key_text_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(key_text_frame, text="Encryption Key:", font=('Segoe UI', 10, 'bold')).pack(anchor='w')
        self.key_text_area = scrolledtext.ScrolledText(key_text_frame, height=4, font=('Consolas', 9))
        self.key_text_area.pack(fill='x', pady=(5, 0))
        
        # Key buttons
        key_btn_frame = tk.Frame(key_section)
        key_btn_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(key_btn_frame, text="🔑 Generate Key",
                  command=self.generate_and_display_key,
                  style='Success.TButton').pack(side='left', padx=5)
        
        ttk.Button(key_btn_frame, text="💾 Save Key",
                  command=self.save_key_to_file,
                  style='Primary.TButton').pack(side='left', padx=5)
        
        ttk.Button(key_btn_frame, text="📥 Load Key",
                  command=self.load_key_from_file,
                  style='Primary.TButton').pack(side='left', padx=5)
        
        # Operations section
        ops_section = tk.LabelFrame(self.secure_comm_frame, text="Secure Operations",
                                   font=('Segoe UI', 12, 'bold'),
                                   fg=self.colors['primary'])
        ops_section.pack(fill='x', padx=10, pady=10)
        
        ops_btn_frame = tk.Frame(ops_section)
        ops_btn_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(ops_btn_frame, text="🔒 Encrypt & Save As...",
                  command=self.encrypt_and_save_as,
                  style='Success.TButton').pack(side='left', padx=5)
        
        ttk.Button(ops_btn_frame, text="🔓 Decrypt & Save As...",
                  command=self.decrypt_and_save_as,
                  style='Warning.TButton').pack(side='left', padx=5)
        
        ttk.Button(ops_btn_frame, text="💾 Quick Save",
                  command=self.encrypt_and_save,
                  style='Primary.TButton').pack(side='left', padx=5)
        
        # Progress bar
        self.secure_progress = ttk.Progressbar(ops_section, mode='indeterminate')
        self.secure_progress.pack(fill='x', padx=10, pady=5)
        
        # Results display
        results_section = tk.LabelFrame(self.secure_comm_frame, text="Operation Results",
                                       font=('Segoe UI', 12, 'bold'),
                                       fg=self.colors['primary'])
        results_section.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.secure_results = scrolledtext.ScrolledText(results_section, 
                                                       height=12,
                                                       font=('Consolas', 10),
                                                       bg='#2c3e50',
                                                       fg='#ecf0f1',
                                                       insertbackground='white')
        self.secure_results.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Add initial help text
        self.secure_results.insert('end', "🔐 CipherGuard Secure Communication Hub\n")
        self.secure_results.insert('end', "=" * 50 + "\n\n")
        self.secure_results.insert('end', "📋 Instructions:\n")
        self.secure_results.insert('end', "1. Choose input method: Compose message or upload file\n")
        self.secure_results.insert('end', "2. Generate or enter encryption key in text area\n")
        self.secure_results.insert('end', "3. Use 'Encrypt & Save As...' to choose custom name/location\n")
        self.secure_results.insert('end', "4. Use 'Decrypt & Save As...' to save decrypted content\n")
        self.secure_results.insert('end', "5. 'Quick Save' uses default names and locations\n\n")
        self.secure_results.insert('end', "✨ Ready for secure communication!\n\n")
        
        # Initialize with message mode
        self.toggle_input_method()
        
        # Store last encrypted result for decryption
        self.last_encrypted_result = None
        
        # Add some initial help text to key area
        self.key_text_area.insert('1.0', "Click 'Generate Key' to create a new encryption key\nor paste your existing key here...")
        
        # Auto-refresh message storage when app starts
        self.root.after(1000, self.refresh_message_list)
    

    
    def create_vpn_tab(self):
        """Create enhanced VPN simulation tab"""
        self.vpn_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.vpn_frame, text='🌐 VPN Tunnel')
        
        # Header
        header_section = tk.Frame(self.vpn_frame, bg='white', relief='raised', bd=1)
        header_section.pack(fill='x', padx=10, pady=10)
        
        tk.Label(header_section,
                text="🌐 VPN Encryption & Secure Tunnel Simulation",
                font=('Segoe UI', 16, 'bold'),
                bg='white',
                fg=self.colors['primary']).pack(pady=10)
        
        # VPN Controls
        control_section = tk.LabelFrame(self.vpn_frame, text="VPN Controls",
                                       font=('Segoe UI', 12, 'bold'))
        control_section.pack(fill='x', padx=10, pady=10)
        
        control_btn_frame = tk.Frame(control_section)
        control_btn_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(control_btn_frame, text="🔧 Initialize VPN",
                  command=self.init_vpn,
                  style='Primary.TButton').pack(side='left', padx=5)
        
        ttk.Button(control_btn_frame, text="🚀 Start Tunnel",
                  command=self.start_vpn,
                  style='Success.TButton').pack(side='left', padx=5)
        
        ttk.Button(control_btn_frame, text="🛑 Stop Tunnel",
                  command=self.stop_vpn,
                  style='Warning.TButton').pack(side='left', padx=5)
        
        # Status display
        status_section = tk.LabelFrame(self.vpn_frame, text="Connection Status",
                                      font=('Segoe UI', 12, 'bold'))
        status_section.pack(fill='x', padx=10, pady=10)
        
        self.vpn_status = tk.Label(status_section, 
                                  text="🔴 Status: Not Initialized",
                                  font=('Segoe UI', 12, 'bold'),
                                  fg=self.colors['danger'])
        self.vpn_status.pack(padx=10, pady=10)
        
        # Traffic monitor
        monitor_section = tk.LabelFrame(self.vpn_frame, text="Traffic Monitor",
                                       font=('Segoe UI', 12, 'bold'))
        monitor_section.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.traffic_log = scrolledtext.ScrolledText(monitor_section,
                                                    font=('Consolas', 10),
                                                    bg='#2c3e50',
                                                    fg='#ecf0f1',
                                                    insertbackground='white')
        self.traffic_log.pack(fill='both', expand=True, padx=10, pady=10)
    
    def create_signature_tab(self):
        """Create enhanced digital signature tab"""
        self.signature_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.signature_frame, text='✍️ Digital Signatures')
        
        # Header
        header_section = tk.Frame(self.signature_frame, bg='white', relief='raised', bd=1)
        header_section.pack(fill='x', padx=10, pady=10)
        
        tk.Label(header_section,
                text="✍️ Digital Signatures for Data Integrity",
                font=('Segoe UI', 16, 'bold'),
                bg='white',
                fg=self.colors['primary']).pack(pady=10)
        
        # Document input
        doc_section = tk.LabelFrame(self.signature_frame, text="Document Content",
                                   font=('Segoe UI', 12, 'bold'))
        doc_section.pack(fill='x', padx=10, pady=10)
        
        tk.Label(doc_section, text="Enter document to sign:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=10, pady=(10, 5))
        self.doc_content = scrolledtext.ScrolledText(doc_section, height=6, font=('Segoe UI', 10))
        self.doc_content.pack(fill='x', padx=10, pady=(0, 10))
        
        # Control buttons - Split into multiple rows for better organization
        control_section = tk.Frame(self.signature_frame)
        control_section.pack(fill='x', padx=10, pady=10)
        
        # First row - Basic operations
        control_row1 = tk.Frame(control_section)
        control_row1.pack(fill='x', pady=2)
        
        ttk.Button(control_row1, text="🔑 Generate Keys",
                  command=self.generate_signature_keys,
                  style='Success.TButton').pack(side='left', padx=5)
        
        ttk.Button(control_row1, text="✍️ Sign Document",
                  command=self.sign_document,
                  style='Primary.TButton').pack(side='left', padx=5)
        
        ttk.Button(control_row1, text="✅ Verify Signature",
                  command=self.verify_signature,
                  style='Warning.TButton').pack(side='left', padx=5)
        
        # Second row - Document management
        control_row2 = tk.Frame(control_section)
        control_row2.pack(fill='x', pady=2)
        
        ttk.Button(control_row2, text="💾 Save Signed Document",
                  command=self.save_signed_document,
                  style='Primary.TButton').pack(side='left', padx=5)
        
        ttk.Button(control_row2, text="📂 Load Signed Document",
                  command=self.load_signed_document_dialog,
                  style='Primary.TButton').pack(side='left', padx=5)
        
        ttk.Button(control_row2, text="📤 Upload External Document",
                  command=self.upload_external_signed_document,
                  style='Primary.TButton').pack(side='left', padx=5)
        
        # Third row - Key management
        control_row3 = tk.Frame(control_section)
        control_row3.pack(fill='x', pady=2)
        
        ttk.Button(control_row3, text="🔑📤 Export Public Key",
                  command=self.export_public_key,
                  style='Success.TButton').pack(side='left', padx=5)
        
        ttk.Button(control_row3, text="🔑📥 Import Public Key",
                  command=self.import_public_key,
                  style='Success.TButton').pack(side='left', padx=5)
        
        # Create horizontal paned window for results and document browser
        paned_window = tk.PanedWindow(self.signature_frame, orient='horizontal')
        paned_window.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Signature display (left side)
        sig_section = tk.LabelFrame(paned_window, text="Signature Processing Results",
                                   font=('Segoe UI', 12, 'bold'))
        paned_window.add(sig_section, minsize=400)
        
        self.signature_display = scrolledtext.ScrolledText(sig_section,
                                                          font=('Consolas', 10),
                                                          bg='#2c3e50',
                                                          fg='#ecf0f1',
                                                          insertbackground='white')
        self.signature_display.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Signed documents browser (right side)
        browser_section = tk.LabelFrame(paned_window, text="Saved Signed Documents",
                                       font=('Segoe UI', 12, 'bold'))
        paned_window.add(browser_section, minsize=350)
        
        # Browser controls
        browser_controls = tk.Frame(browser_section)
        browser_controls.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(browser_controls, text="🔄 Refresh List",
                  command=self.refresh_signed_documents,
                  style='Primary.TButton').pack(side='left', padx=5)
        
        ttk.Button(browser_controls, text="📋 Load Selected",
                  command=self.load_selected_signed_document,
                  style='Success.TButton').pack(side='left', padx=5)
        
        ttk.Button(browser_controls, text="🗑️ Delete Selected",
                  command=self.delete_selected_signed_document,
                  style='Warning.TButton').pack(side='left', padx=5)
        
        # Documents tree view
        tree_frame = tk.Frame(browser_section)
        tree_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create treeview with columns
        self.signed_docs_tree = ttk.Treeview(tree_frame, 
                                            columns=('Name', 'Date', 'Content Preview'),
                                            show='tree headings')
        
        # Configure columns
        self.signed_docs_tree.heading('#0', text='File')
        self.signed_docs_tree.heading('Name', text='Document Name')
        self.signed_docs_tree.heading('Date', text='Created')
        self.signed_docs_tree.heading('Content Preview', text='Preview')
        
        self.signed_docs_tree.column('#0', width=120, minwidth=100)
        self.signed_docs_tree.column('Name', width=150, minwidth=120)
        self.signed_docs_tree.column('Date', width=140, minwidth=120)
        self.signed_docs_tree.column('Content Preview', width=200, minwidth=150)
        
        # Add scrollbar for tree
        tree_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.signed_docs_tree.yview)
        self.signed_docs_tree.configure(yscrollcommand=tree_scrollbar.set)
        
        # Pack tree and scrollbar
        self.signed_docs_tree.pack(side='left', fill='both', expand=True)
        tree_scrollbar.pack(side='right', fill='y')
        
        # Initialize with some help text in signature display
        self.signature_display.insert('end', """
✍️ DIGITAL SIGNATURE OPERATIONS GUIDE

🔑 GETTING STARTED:
1. Click "Generate Keys" to create your signature key pair
2. Enter document content above
3. Click "Sign Document" to create digital signature
4. Use "Verify Signature" to validate the signature

💾 DOCUMENT MANAGEMENT:
• "Save Signed Document" - Save current signed document
• "Load Signed Document" - Browse and load saved documents
• "Upload External Document" - Verify documents from others

🔑 KEY MANAGEMENT:
• "Export Public Key" - Share your public key with others
• "Import Public Key" - Add others' public keys for verification

📂 SIGNED DOCUMENTS BROWSER:
• View all your saved signed documents on the right
• Click "Refresh List" to update the browser
• Select and load documents for verification or review

💡 TIP: Always save important signed documents for future verification!
""")
    
    def create_comparison_tab(self):
        """Create enhanced comparison analysis tab"""
        self.comparison_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.comparison_frame, text='📊 Method Comparison')
        
        # Header
        header_section = tk.Frame(self.comparison_frame, bg='white', relief='raised', bd=1)
        header_section.pack(fill='x', padx=10, pady=10)
        
        tk.Label(header_section,
                text="📊 Security Method Performance Analysis",
                font=('Segoe UI', 16, 'bold'),
                bg='white',
                fg=self.colors['primary']).pack(pady=10)
        
        # Control section
        control_section = tk.Frame(self.comparison_frame)
        control_section.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(control_section, text="📈 Run Comprehensive Analysis",
                  command=self.run_comparison,
                  style='Primary.TButton').pack(side='left', padx=5)
        
        # Create horizontal paned window for chart and results
        paned_window = tk.PanedWindow(self.comparison_frame, orient='horizontal')
        paned_window.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Chart display
        chart_section = tk.LabelFrame(paned_window, text="VPN vs Digital Signatures Comparison",
                                     font=('Segoe UI', 12, 'bold'))
        paned_window.add(chart_section, minsize=500)
        
        self.fig, self.ax = plt.subplots(figsize=(10, 6))
        self.fig.patch.set_facecolor('white')
        canvas = FigureCanvasTkAgg(self.fig, master=chart_section)
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)
        
        # Comparison analysis results
        results_section = tk.LabelFrame(paned_window, text="Detailed Analysis Results",
                                       font=('Segoe UI', 12, 'bold'))
        paned_window.add(results_section, minsize=400)
        
        self.comparison_results = scrolledtext.ScrolledText(results_section,
                                                           font=('Consolas', 10),
                                                           bg='#f8f9fa',
                                                           fg='#2c3e50',
                                                           insertbackground='#2c3e50',
                                                           wrap='word')
        self.comparison_results.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Initialize with placeholder text
        self.comparison_results.insert('end', """
📊 VPN ENCRYPTION vs DIGITAL SIGNATURES ANALYSIS

Click "Run Comprehensive Analysis" to compare:

🔍 Performance Metrics:
• Performance Overhead
• Confidentiality Effectiveness 
• Authenticity & Non-repudiation
• Implementation Complexity

🎯 This analysis will determine which method is better for:
• Data Privacy (Confidentiality)
• Sender Verification (Authenticity)
• Overall Security Goals

📈 Results will include detailed recommendations based on specific security requirements.
""")
    
    def create_storage_tab(self):
        """Create enhanced message storage tab"""
        self.storage_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.storage_frame, text='💾 Message Storage')
        
        # Header
        header_section = tk.Frame(self.storage_frame, bg='white', relief='raised', bd=1)
        header_section.pack(fill='x', padx=10, pady=10)
        
        tk.Label(header_section,
                text="💾 Encrypted Message Storage & Management",
                font=('Segoe UI', 16, 'bold'),
                bg='white',
                fg=self.colors['primary']).pack(pady=10)
        
        tk.Label(header_section,
                text="View all saved encrypted messages with creation dates and metadata",
                font=('Segoe UI', 10),
                bg='white',
                fg=self.colors['dark']).pack(pady=(0, 10))
        
        # Message list
        list_section = tk.LabelFrame(self.storage_frame, text="Saved Messages",
                                    font=('Segoe UI', 12, 'bold'))
        list_section.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Treeview for messages
        columns = ('filename', 'created_at', 'type', 'metadata')
        self.message_tree = ttk.Treeview(list_section, columns=columns, show='headings', height=15)
        
        self.message_tree.heading('filename', text='Filename')
        self.message_tree.heading('created_at', text='Date Created')
        self.message_tree.heading('type', text='Type')
        self.message_tree.heading('metadata', text='Metadata')
        
        self.message_tree.column('filename', width=180)
        self.message_tree.column('created_at', width=140)
        self.message_tree.column('type', width=80)
        self.message_tree.column('metadata', width=250)
        
        scrollbar = ttk.Scrollbar(list_section, orient='vertical', command=self.message_tree.yview)
        self.message_tree.configure(yscrollcommand=scrollbar.set)
        
        self.message_tree.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        scrollbar.pack(side='right', fill='y', pady=10)
        
        # Control buttons
        btn_section = tk.Frame(self.storage_frame)
        btn_section.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(btn_section, text="🔄 Refresh List",
                  command=self.refresh_message_list,
                  style='Primary.TButton').pack(side='left', padx=5)
        
        ttk.Button(btn_section, text="📥 Load Selected",
                  command=self.load_selected_message,
                  style='Success.TButton').pack(side='left', padx=5)
        
        ttk.Button(btn_section, text="🗑️ Delete Selected",
                  command=self.delete_selected_message,
                  style='Warning.TButton').pack(side='left', padx=5)
        
        # Auto-refresh when tab is opened
        self.notebook.bind('<<NotebookTabChanged>>', self.on_tab_changed)
    
    def create_tools_tab(self):
        """Create enhanced cryptographic tools tab"""
        self.tools_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.tools_frame, text='🛠️ Crypto Tools')
        
        # Header
        header_section = tk.Frame(self.tools_frame, bg='white', relief='raised', bd=1)
        header_section.pack(fill='x', padx=10, pady=10)
        
        tk.Label(header_section,
                text="🛠️ Professional Cryptographic Tools Integration",
                font=('Segoe UI', 16, 'bold'),
                bg='white',
                fg=self.colors['primary']).pack(pady=10)
        
        try:
            self.tool_integration = CryptographicToolIntegration()
            
            # Tool demos section
            tools_section = tk.LabelFrame(self.tools_frame, text="Industry Standard Tools",
                                         font=('Segoe UI', 12, 'bold'))
            tools_section.pack(fill='x', padx=10, pady=10)
            
            tools_btn_frame = tk.Frame(tools_section)
            tools_btn_frame.pack(fill='x', padx=10, pady=10)
            
            ttk.Button(tools_btn_frame, text="🔐 OpenSSL Demo",
                      command=self.demo_openssl_keygen,
                      style='Primary.TButton').pack(side='left', padx=5)
            
            ttk.Button(tools_btn_frame, text="📧 GnuPG Demo",
                      command=self.demo_gnupg_email,
                      style='Success.TButton').pack(side='left', padx=5)
            
            ttk.Button(tools_btn_frame, text="🌐 Wireshark Analysis",
                      command=self.demo_wireshark_vpn,
                      style='Warning.TButton').pack(side='left', padx=5)
            
            # Workflow demos
            workflow_section = tk.LabelFrame(self.tools_frame, text="Command-Line Workflows",
                                           font=('Segoe UI', 12, 'bold'))
            workflow_section.pack(fill='x', padx=10, pady=10)
            
            workflow_btn_frame = tk.Frame(workflow_section)
            workflow_btn_frame.pack(fill='x', padx=10, pady=10)
            
            ttk.Button(workflow_btn_frame, text="📧 Email Workflow",
                      command=lambda: self.demo_bash_workflow('email'),
                      style='Primary.TButton').pack(side='left', padx=5)
            
            ttk.Button(workflow_btn_frame, text="🌐 VPN Workflow",
                      command=lambda: self.demo_bash_workflow('vpn'),
                      style='Primary.TButton').pack(side='left', padx=5)
            
            ttk.Button(workflow_btn_frame, text="✍️ Signature Workflow",
                      command=lambda: self.demo_bash_workflow('signature'),
                      style='Primary.TButton').pack(side='left', padx=5)
            
            # Results display
            results_section = tk.LabelFrame(self.tools_frame, text="Tool Output & Demonstrations",
                                           font=('Segoe UI', 12, 'bold'))
            results_section.pack(fill='both', expand=True, padx=10, pady=10)
            
            self.tools_output = scrolledtext.ScrolledText(results_section,
                                                         font=('Consolas', 10),
                                                         bg='#2c3e50',
                                                         fg='#ecf0f1',
                                                         insertbackground='white')
            self.tools_output.pack(fill='both', expand=True, padx=10, pady=10)
            
            # Initial message
            self.tools_output.insert('end', "🛠️ CipherGuard - Professional Cryptographic Tools\n")
            self.tools_output.insert('end', "=" * 60 + "\n\n")
            self.tools_output.insert('end', "This section demonstrates industry-standard tools:\n\n")
            self.tools_output.insert('end', "🔐 OpenSSL - RSA key generation and encryption\n")
            self.tools_output.insert('end', "📧 GnuPG - Email encryption and digital signatures\n")
            self.tools_output.insert('end', "🌐 Wireshark - Network traffic analysis for VPN\n\n")
            self.tools_output.insert('end', "Click any button above to see demonstrations.\n\n")
            
        except Exception as e:
            tk.Label(self.tools_frame,
                    text=f"Tools integration unavailable: {str(e)}",
                    font=('Segoe UI', 12),
                    fg=self.colors['danger']).pack(pady=20)
    
    def create_status_bar(self):
        """Create modern status bar"""
        self.status_bar = tk.Frame(self.root, bg=self.colors['dark'], height=30)
        self.status_bar.pack(fill='x', side='bottom')
        self.status_bar.pack_propagate(False)
        
        self.status_text = tk.Label(self.status_bar,
                                   text="Ready - Welcome to CipherGuard",
                                   bg=self.colors['dark'],
                                   fg='white',
                                   font=('Segoe UI', 9))
        self.status_text.pack(side='left', padx=10, pady=5)
        
        # Tutorial button
        tutorial_btn = tk.Button(self.status_bar,
                                text="🎓 Start Tutorial",
                                command=self.start_tutorial,
                                bg=self.colors['accent'],
                                fg='white',
                                font=('Segoe UI', 9),
                                relief='flat',
                                padx=15)
        tutorial_btn.pack(side='right', padx=10, pady=2)
    
    def show_welcome_guide(self):
        """Show welcome guide for new users"""
        welcome_msg = """
🎉 Welcome to CipherGuard!

This advanced cryptographic security suite helps you:

🔐 Unified secure communication (files & messages)
🌐 Understand VPN tunnel establishment
✍️ Create and verify digital signatures
📈 Compare security method performance
💾 Manage encrypted message storage
🛠️ Learn industry-standard crypto tools

✨ Navigation Tips:
• Use Ctrl+Tab to switch between tabs
• Press F11 for fullscreen mode
• Window is resizable and responsive

🎓 Click 'Start Tutorial' in the status bar for step-by-step guidance!

Ready to explore cryptographic security?
        """
        
        messagebox.showinfo("Welcome to CipherGuard", welcome_msg)
    
    def start_tutorial(self):
        """Start interactive tutorial"""
        self.tutorial_active = True
        self.tutorial_step = 0
        self.show_tutorial_step()
    
    def show_tutorial_step(self):
        """Show current tutorial step"""
        if not self.tutorial_active:
            return
            
        tutorial_steps = [
            {
                'title': 'Step 1: Secure Communication',
                'message': 'Let\'s start with secure communication. Click on the "🔐 Secure Communication" tab to encrypt your first message or file.',
                'tab': 0
            },
            {
                'title': 'Step 2: Choose Input Method',
                'message': 'Choose between "Compose Message" to type a message or "Upload File" to encrypt a .txt or .eml file.',
                'tab': 0
            },
            {
                'title': 'Step 3: Generate Keys',
                'message': 'Click "🔑 Generate Keys" to create encryption keys for secure communication.',
                'tab': 0
            },
            {
                'title': 'Step 4: Encrypt & Save',
                'message': 'Now click "🔒 Encrypt & Save" to secure your content in unified encrypted format.',
                'tab': 0
            },
            {
                'title': 'Step 5: Explore Other Features',
                'message': 'Great! Now explore other tabs to learn about VPN tunnels, digital signatures, and crypto tools.',
                'tab': None
            }
        ]
        
        if self.tutorial_step < len(tutorial_steps):
            step = tutorial_steps[self.tutorial_step]
            
            if step['tab'] is not None:
                self.notebook.select(step['tab'])
            
            result = messagebox.askquestion(step['title'], 
                                          step['message'] + "\n\nContinue tutorial?")
            
            if result == 'yes':
                self.tutorial_step += 1
                self.root.after(1000, self.show_tutorial_step)
            else:
                self.tutorial_active = False
        else:
            messagebox.showinfo("Tutorial Complete", 
                              "🎉 Tutorial completed! You're now ready to use CipherGuard effectively.")
            self.tutorial_active = False
    
    def update_status(self, message):
        """Update status bar message"""
        self.status_text.config(text=message)
        self.root.update_idletasks()
    
    # Handler setter methods (updated for unified interface)
    def set_email_handlers(self, generate_keys, encrypt, decrypt):
        self._email_generate = generate_keys
        self._email_encrypt = encrypt
        self._email_decrypt = decrypt
        
        # Store last encrypted result for decryption
        original_encrypt = encrypt
        def encrypt_wrapper(content):
            result = original_encrypt(content)
            if result['status'] == 'success':
                self.last_encrypted_result = result
            return result
        self._email_encrypt = encrypt_wrapper
    
    # Placeholder methods for backward compatibility
    def generate_email_keys(self):
        """Backward compatibility method"""
        return self.generate_secure_keys()
    
    def encrypt_email(self):
        """Backward compatibility method"""
        return self.encrypt_and_save()
    
    def decrypt_email(self):
        """Backward compatibility method"""
        return self.decrypt_message()
    
    def generate_file_keys(self):
        """Backward compatibility method"""
        return self.generate_secure_keys()
    
    def encrypt_selected_file(self):
        """Backward compatibility method"""
        return self.encrypt_and_save()
    
    def decrypt_selected_file(self):
        """Backward compatibility method"""
        return self.decrypt_message()
    
    def generate_and_display_key(self):
        """Generate a new encryption key and display it"""
        try:
            import secrets
            import base64
            
            # Generate a 256-bit (32 byte) key
            key_bytes = secrets.token_bytes(32)
            key_b64 = base64.b64encode(key_bytes).decode('utf-8')
            
            # Display in key text area
            self.key_text_area.delete('1.0', 'end')
            self.key_text_area.insert('1.0', key_b64)
            
            self.secure_results.insert('end', "🔑 New encryption key generated successfully!\n")
            self.secure_results.insert('end', "Key displayed in the text area above.\n")
            self.secure_results.insert('end', "💡 Save this key to use for decryption later.\n\n")
            self.secure_results.see('end')
            
            self.update_status("New encryption key generated")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key: {str(e)}")
    
    def save_key_to_file(self):
        """Save the current key to a file"""
        try:
            key_content = self.key_text_area.get('1.0', 'end-1c').strip()
            if not key_content:
                messagebox.showwarning("Warning", "No key to save. Generate or enter a key first.")
                return
            
            filename = filedialog.asksaveasfilename(
                title="Save Encryption Key",
                defaultextension=".key",
                filetypes=[("Key files", "*.key"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'w') as f:
                    f.write(key_content)
                
                self.secure_results.insert('end', f"💾 Key saved to: {os.path.basename(filename)}\n")
                self.secure_results.insert('end', "Keep this file secure for decryption operations.\n\n")
                self.secure_results.see('end')
                
                self.update_status(f"Key saved to {os.path.basename(filename)}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save key: {str(e)}")
    
    def load_key_from_file(self):
        """Load encryption key from a file"""
        try:
            filename = filedialog.askopenfilename(
                title="Load Encryption Key",
                filetypes=[("Key files", "*.key"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'r') as f:
                    key_content = f.read().strip()
                
                # Display in key text area
                self.key_text_area.delete('1.0', 'end')
                self.key_text_area.insert('1.0', key_content)
                
                self.secure_results.insert('end', f"📥 Key loaded from: {os.path.basename(filename)}\n")
                self.secure_results.insert('end', "Ready for encryption/decryption operations.\n\n")
                self.secure_results.see('end')
                
                self.update_status(f"Key loaded from {os.path.basename(filename)}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load key: {str(e)}")
    
    def refresh_message_list(self):
        """Refresh the list of saved encrypted messages"""
        try:
            if self._message_storage:
                messages = self._message_storage.list_saved_messages()
                
                # Clear existing items
                for item in self.message_tree.get_children():
                    self.message_tree.delete(item)
                
                # Sort messages by creation date (newest first)
                messages.sort(key=lambda x: x['created_at'], reverse=True)
                
                # Add messages to tree with enhanced display
                for msg in messages:
                    # Format date for better readability
                    try:
                        from datetime import datetime
                        date_obj = datetime.fromisoformat(msg['created_at'].replace('Z', '+00:00'))
                        formatted_date = date_obj.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        formatted_date = msg['created_at']
                    
                    # Extract type from metadata
                    metadata = msg.get('metadata', {})
                    msg_type = metadata.get('type', 'unknown').title()
                    
                    # Format metadata for display
                    metadata_display = ""
                    if metadata.get('original_filename'):
                        metadata_display = f"File: {metadata['original_filename']}"
                    elif metadata.get('subject'):
                        metadata_display = f"Subject: {metadata['subject']}"
                    elif metadata.get('sender'):
                        metadata_display = f"From: {metadata['sender']}"
                    else:
                        metadata_display = str(metadata)
                    
                    self.message_tree.insert('', 'end', values=(
                        msg['filename'],
                        formatted_date,
                        msg_type,
                        metadata_display
                    ))
                
                self.update_status(f"Refreshed message list - {len(messages)} messages found")
            else:
                # Try to scan directory directly if storage handler not available
                self.scan_encrypted_messages_directory()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh message list: {str(e)}")
    
    def scan_encrypted_messages_directory(self):
        """Scan encrypted messages directory directly"""
        try:
            import json
            messages_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'encrypted_messages')
            
            if not os.path.exists(messages_dir):
                os.makedirs(messages_dir)
                return
            
            # Clear existing items
            for item in self.message_tree.get_children():
                self.message_tree.delete(item)
            
            messages = []
            for filename in os.listdir(messages_dir):
                if filename.endswith('.enc'):
                    try:
                        filepath = os.path.join(messages_dir, filename)
                        with open(filepath, 'r') as f:
                            data = json.load(f)
                        
                        # Format date
                        created_at = data.get('created_at', 'Unknown')
                        try:
                            date_obj = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                            formatted_date = date_obj.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            formatted_date = created_at
                        
                        # Extract metadata
                        metadata = data.get('metadata', {})
                        msg_type = metadata.get('type', 'unknown').title()
                        
                        metadata_display = ""
                        if metadata.get('original_filename'):
                            metadata_display = f"File: {metadata['original_filename']}"
                        elif metadata.get('subject'):
                            metadata_display = f"Subject: {metadata['subject']}"
                        else:
                            metadata_display = str(metadata)
                        
                        messages.append({
                            'filename': filename,
                            'created_at': created_at,
                            'formatted_date': formatted_date,
                            'type': msg_type,
                            'metadata_display': metadata_display
                        })
                    except Exception as e:
                        # Skip corrupted files
                        continue
            
            # Sort by creation date (newest first)
            messages.sort(key=lambda x: x['created_at'], reverse=True)
            
            # Add to tree
            for msg in messages:
                self.message_tree.insert('', 'end', values=(
                    msg['filename'],
                    msg['formatted_date'],
                    msg['type'],
                    msg['metadata_display']
                ))
            
            self.update_status(f"Found {len(messages)} encrypted messages")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan messages directory: {str(e)}")
    
    def on_tab_changed(self, event):
        """Handle tab change events"""
        try:
            selected_tab = event.widget.tab('current')['text']
            if '💾 Message Storage' in selected_tab:
                # Auto-refresh when storage tab is opened
                self.refresh_message_list()
            elif '✍️ Digital Signatures' in selected_tab:
                # Auto-refresh signed documents when signature tab is opened
                self.refresh_signed_documents()
        except:
            pass
    
    def delete_selected_message(self):
        """Delete selected encrypted message"""
        try:
            selection = self.message_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a message to delete")
                return
            
            item = self.message_tree.item(selection[0])
            filename = item['values'][0]
            
            # Confirm deletion
            result = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{filename}'?")
            if result:
                messages_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'encrypted_messages')
                filepath = os.path.join(messages_dir, filename)
                
                if os.path.exists(filepath):
                    os.remove(filepath)
                    self.refresh_message_list()
                    self.update_status(f"Deleted message: {filename}")
                else:
                    messagebox.showerror("Error", "File not found")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete message: {str(e)}")
    
    def load_selected_message(self):
        """Load selected message from storage"""
        try:
            selection = self.message_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a message to load")
                return
            
            item = self.message_tree.item(selection[0])
            filename = item['values'][0]
            
            if self._message_storage:
                message_data = self._message_storage.load_encrypted_message(filename)
                
                # Store for decryption
                self.last_encrypted_result = {
                    'message': message_data['message'],
                    'key': message_data['key'], 
                    'iv': message_data['iv'],
                    'auth_tag': message_data.get('auth_tag'),
                    'signature': message_data.get('signature')
                }
                
                messagebox.showinfo("Success", f"Message '{filename}' loaded and ready for decryption")
                self.update_status(f"Loaded message: {filename}")
            else:
                messagebox.showwarning("Warning", "Message storage not available")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load message: {str(e)}")
    
    # VPN simulation methods
    def init_vpn(self):
        """Initialize VPN simulation"""
        if self._vpn_init:
            result = self._vpn_init()
            self.vpn_status.config(text="🟡 Status: Initializing...", fg=self.colors['warning'])
            self.traffic_log.insert('end', "🔧 VPN initialization started...\n")
        else:
            self.vpn_status.config(text="🟡 Status: Initialized (Simulation)", fg=self.colors['warning'])
            self.traffic_log.insert('end', "🔧 VPN initialized (simulation mode)\n")
        self.traffic_log.see('end')
    
    def start_vpn(self):
        """Start VPN tunnel"""
        if self._vpn_start:
            result = self._vpn_start()
            self.vpn_status.config(text="🟢 Status: Connected", fg=self.colors['success'])
            self.traffic_log.insert('end', "🚀 VPN tunnel established\n")
        else:
            self.vpn_status.config(text="🟢 Status: Connected (Simulation)", fg=self.colors['success'])
            self.traffic_log.insert('end', "🚀 VPN tunnel started (simulation)\n")
        self.traffic_log.see('end')
    
    def stop_vpn(self):
        """Stop VPN tunnel"""
        if self._vpn_stop:
            result = self._vpn_stop()
        self.vpn_status.config(text="🔴 Status: Disconnected", fg=self.colors['danger'])
        self.traffic_log.insert('end', "🛑 VPN tunnel stopped\n")
        self.traffic_log.see('end')
    
    # Digital signature methods
    def generate_signature_keys(self):
        """Generate keys for digital signatures"""
        if self._sig_generate:
            result = self._sig_generate()
            self.signature_display.insert('end', "🔑 Signature keys generated successfully\n")
        else:
            self.signature_display.insert('end', "🔑 Signature keys generated (simulation)\n")
        self.signature_display.see('end')
    
    def sign_document(self):
        """Sign document with digital signature"""
        content = self.doc_content.get('1.0', 'end-1c').strip()
        if not content:
            messagebox.showwarning("Warning", "Please enter document content to sign")
            return
        
        if self._sig_sign:
            try:
                result = self._sig_sign(content)
                if result['status'] == 'success':
                    self.last_signature_data = result
                    self.signature_display.insert('end', f"✍️ Document signed successfully\n")
                    self.signature_display.insert('end', f"📄 Content: {content[:50]}...\n")
                    self.signature_display.insert('end', f"🔑 Signature: {result['signature'][:50]}...\n")
                    self.signature_display.insert('end', f"#️⃣ Hash: {result['document_hash'][:50]}...\n")
                    self.signature_display.insert('end', f"💡 Use 'Verify Signature' to validate this document\n")
                else:
                    self.signature_display.insert('end', f"❌ Signing failed: {result.get('message', 'Unknown error')}\n")
            except Exception as e:
                self.signature_display.insert('end', f"❌ Signing error: {str(e)}\n")
        else:
            # Store mock signature data for simulation
            self.last_signature_data = {
                'signature': 'mock_signature_data',
                'document_hash': 'mock_hash_data'
            }
            self.signature_display.insert('end', f"✍️ Document signed (simulation)\n")
            self.signature_display.insert('end', f"📄 Content: {content[:50]}...\n")
        self.signature_display.see('end')
    
    def verify_signature(self):
        """Verify digital signature"""
        content = self.doc_content.get('1.0', 'end-1c').strip()
        if not content:
            messagebox.showwarning("Warning", "Please enter document content to verify signature")
            return
            
        if self._sig_verify and hasattr(self, 'last_signature_data'):
            try:
                result = self._sig_verify(content, self.last_signature_data)
                if result['status'] == 'success':
                    if result['verified']:
                        self.signature_display.insert('end', "✅ Signature verification: VALID\n")
                        self.signature_display.insert('end', "🔒 Document integrity confirmed\n")
                        self.signature_display.insert('end', "👤 Sender authenticity verified\n")
                    else:
                        self.signature_display.insert('end', "❌ Signature verification: INVALID\n")
                        self.signature_display.insert('end', "⚠️ Document may have been tampered with\n")
                else:
                    self.signature_display.insert('end', f"❌ Verification failed: {result.get('message', 'Unknown error')}\n")
            except Exception as e:
                self.signature_display.insert('end', f"❌ Verification error: {str(e)}\n")
        else:
            self.signature_display.insert('end', "✅ Signature verified (simulation)\n")
            self.signature_display.insert('end', "🔒 Document integrity: VALID\n")
            self.signature_display.insert('end', "👤 Sender authenticity: VERIFIED\n")
        self.signature_display.see('end')
    
    # Enhanced digital signature methods for document management
    def save_signed_document(self):
        """Save the currently signed document with metadata"""
        if not hasattr(self, 'last_signature_data') or not self.last_signature_data:
            messagebox.showwarning("Warning", "No signed document to save. Please sign a document first.")
            return
        
        content = self.doc_content.get('1.0', 'end-1c').strip()
        if not content:
            messagebox.showwarning("Warning", "No document content to save.")
            return
        
        # Get document name from user
        from tkinter import simpledialog
        document_name = simpledialog.askstring(
            "Save Signed Document",
            "Enter a name for this signed document:",
            initialvalue=f"document_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if document_name:
            if hasattr(self, '_sig_save_document') and self._sig_save_document:
                try:
                    result = self._sig_save_document(content, self.last_signature_data, document_name)
                    if result['status'] == 'success':
                        self.signature_display.insert('end', f"💾 Document saved as: {result['filename']}\n")
                        self.signature_display.insert('end', f"📁 Location: {result['filepath']}\n")
                        self.signature_display.insert('end', "💡 Document can now be verified later or shared\n")
                        # Refresh the signed documents list
                        self.refresh_signed_documents()
                    else:
                        self.signature_display.insert('end', f"❌ Save failed: {result.get('message', 'Unknown error')}\n")
                except Exception as e:
                    self.signature_display.insert('end', f"❌ Save error: {str(e)}\n")
            else:
                self.signature_display.insert('end', f"💾 Document '{document_name}' saved (simulation)\n")
        
        self.signature_display.see('end')
    
    def load_signed_document_dialog(self):
        """Show dialog to load a signed document from storage"""
        filename = filedialog.askopenfilename(
            title="Load Signed Document",
            filetypes=[("Signed documents", "*.signed"), ("All files", "*.*")]
        )
        
        if filename:
            self.load_signed_document_file(filename)
    
    def load_signed_document_file(self, filepath):
        """Load a specific signed document file"""
        if hasattr(self, '_sig_load_document') and self._sig_load_document:
            try:
                filename = os.path.basename(filepath)
                result = self._sig_load_document(filename)
                
                if result['status'] == 'success':
                    doc_data = result['data']
                    
                    # Load document content into text area
                    self.doc_content.delete('1.0', 'end')
                    self.doc_content.insert('1.0', doc_data['document_content'])
                    
                    # Store signature data for verification
                    self.last_signature_data = {
                        'signature': doc_data['signature'],
                        'document_hash': doc_data.get('document_hash')
                    }
                    
                    # Store the full document data for external verification
                    self.current_loaded_document = doc_data
                    
                    self.signature_display.insert('end', f"📂 Loaded document: {doc_data['document_name']}\n")
                    self.signature_display.insert('end', f"📅 Created: {doc_data.get('created_at', 'Unknown')}\n")
                    self.signature_display.insert('end', f"📄 Content loaded into editor above\n")
                    self.signature_display.insert('end', f"✅ Ready for verification\n")
                else:
                    self.signature_display.insert('end', f"❌ Load failed: {result.get('message', 'Unknown error')}\n")
            except Exception as e:
                self.signature_display.insert('end', f"❌ Load error: {str(e)}\n")
        else:
            self.signature_display.insert('end', f"📂 Document loaded (simulation)\n")
        
        self.signature_display.see('end')
    
    def upload_external_signed_document(self):
        """Upload and verify an external signed document"""
        filename = filedialog.askopenfilename(
            title="Upload External Signed Document",
            filetypes=[("Signed documents", "*.signed"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                import json
                with open(filename, 'r') as f:
                    signed_doc_data = json.load(f)
                
                if hasattr(self, '_sig_verify_external') and self._sig_verify_external:
                    result = self._sig_verify_external(signed_doc_data)
                    
                    if result['status'] == 'success':
                        # Load content into editor
                        self.doc_content.delete('1.0', 'end')
                        self.doc_content.insert('1.0', signed_doc_data['document_content'])
                        
                        self.signature_display.insert('end', f"📤 External document uploaded: {result['document_name']}\n")
                        
                        if result['verified']:
                            self.signature_display.insert('end', "✅ SIGNATURE VERIFICATION: VALID\n")
                            self.signature_display.insert('end', "🔒 Document integrity: CONFIRMED\n")
                            self.signature_display.insert('end', "👤 Sender authenticity: VERIFIED\n")
                            if result.get('hash_valid', True):
                                self.signature_display.insert('end', "#️⃣ Document hash: VALID\n")
                            else:
                                self.signature_display.insert('end', "⚠️ Document hash: INVALID\n")
                        else:
                            self.signature_display.insert('end', "❌ SIGNATURE VERIFICATION: INVALID\n")
                            self.signature_display.insert('end', "⚠️ Document may have been tampered with or corrupted\n")
                    else:
                        self.signature_display.insert('end', f"❌ Verification failed: {result.get('message', 'Unknown error')}\n")
                else:
                    self.signature_display.insert('end', f"📤 External document uploaded (simulation)\n")
                    
            except Exception as e:
                self.signature_display.insert('end', f"❌ Upload error: {str(e)}\n")
        
        self.signature_display.see('end')
    
    def export_public_key(self):
        """Export public key to a file for sharing"""
        if hasattr(self, '_sig_export_key') and self._sig_export_key:
            try:
                result = self._sig_export_key()
                if result['status'] == 'success':
                    self.signature_display.insert('end', f"🔑📤 Public key exported: {result['filename']}\n")
                    self.signature_display.insert('end', f"📁 Location: {result['filepath']}\n")
                    self.signature_display.insert('end', "💡 Share this key with others to verify your signatures\n")
                else:
                    self.signature_display.insert('end', f"❌ Export failed: {result.get('message', 'Unknown error')}\n")
            except Exception as e:
                self.signature_display.insert('end', f"❌ Export error: {str(e)}\n")
        else:
            self.signature_display.insert('end', "🔑📤 Public key exported (simulation)\n")
        
        self.signature_display.see('end')
    
    def import_public_key(self):
        """Import a public key from file"""
        filename = filedialog.askopenfilename(
            title="Import Public Key",
            filetypes=[("PEM files", "*.pem"), ("Key files", "*.key"), ("All files", "*.*")]
        )
        
        if filename:
            if hasattr(self, '_sig_import_key') and self._sig_import_key:
                try:
                    result = self._sig_import_key(filename)
                    if result['status'] == 'success':
                        self.signature_display.insert('end', f"🔑📥 Public key imported from: {os.path.basename(filename)}\n")
                        self.signature_display.insert('end', "💡 You can now verify documents signed with this key\n")
                        
                        # Store the imported key for verification
                        self.imported_public_key = result['public_key']
                    else:
                        self.signature_display.insert('end', f"❌ Import failed: {result.get('message', 'Unknown error')}\n")
                except Exception as e:
                    self.signature_display.insert('end', f"❌ Import error: {str(e)}\n")
            else:
                self.signature_display.insert('end', f"🔑📥 Public key imported (simulation)\n")
        
        self.signature_display.see('end')
    
    def refresh_signed_documents(self):
        """Refresh the list of saved signed documents"""
        try:
            if hasattr(self, '_sig_list_documents') and self._sig_list_documents:
                result = self._sig_list_documents()
                if result['status'] == 'success':
                    # Clear existing items
                    for item in self.signed_docs_tree.get_children():
                        self.signed_docs_tree.delete(item)
                    
                    # Add documents to tree
                    for doc in result['documents']:
                        # Format date for better readability
                        try:
                            date_obj = datetime.fromisoformat(doc['created_at'].replace('Z', '+00:00'))
                            formatted_date = date_obj.strftime('%Y-%m-%d %H:%M')
                        except:
                            formatted_date = doc['created_at']
                        
                        self.signed_docs_tree.insert('', 'end', values=(
                            doc['document_name'],
                            formatted_date,
                            doc['content_preview']
                        ), text=doc['filename'])
                    
                    self.update_status(f"Found {len(result['documents'])} signed documents")
                else:
                    messagebox.showerror("Error", f"Failed to refresh: {result.get('message', 'Unknown error')}")
            else:
                # Simulation mode - add some dummy data
                for item in self.signed_docs_tree.get_children():
                    self.signed_docs_tree.delete(item)
                
                self.signed_docs_tree.insert('', 'end', values=(
                    "Sample Document",
                    datetime.now().strftime('%Y-%m-%d %H:%M'),
                    "This is a sample signed document..."
                ), text="sample.signed")
                
                self.update_status("Signed documents refreshed (simulation)")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh signed documents: {str(e)}")
    
    def load_selected_signed_document(self):
        """Load the selected signed document from the browser"""
        try:
            selection = self.signed_docs_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a signed document to load")
                return
            
            item = self.signed_docs_tree.item(selection[0])
            filename = item['text']
            
            if hasattr(self, '_sig_load_document') and self._sig_load_document:
                result = self._sig_load_document(filename)
                
                if result['status'] == 'success':
                    doc_data = result['data']
                    
                    # Load document content into text area
                    self.doc_content.delete('1.0', 'end')
                    self.doc_content.insert('1.0', doc_data['document_content'])
                    
                    # Store signature data for verification
                    self.last_signature_data = {
                        'signature': doc_data['signature'],
                        'document_hash': doc_data.get('document_hash')
                    }
                    
                    # Store the full document data
                    self.current_loaded_document = doc_data
                    
                    self.signature_display.insert('end', f"📋 Loaded from browser: {doc_data['document_name']}\n")
                    self.signature_display.insert('end', f"📅 Created: {doc_data.get('created_at', 'Unknown')}\n")
                    self.signature_display.insert('end', "✅ Ready for verification or editing\n")
                    
                    self.update_status(f"Loaded signed document: {filename}")
                else:
                    messagebox.showerror("Error", f"Failed to load document: {result.get('message', 'Unknown error')}")
            else:
                self.signature_display.insert('end', f"📋 Loaded document: {filename} (simulation)\n")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load selected document: {str(e)}")
        
        self.signature_display.see('end')
    
    def delete_selected_signed_document(self):
        """Delete the selected signed document"""
        try:
            selection = self.signed_docs_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select a signed document to delete")
                return
            
            item = self.signed_docs_tree.item(selection[0])
            filename = item['text']
            document_name = item['values'][0]
            
            # Confirm deletion
            result = messagebox.askyesno(
                "Confirm Delete", 
                f"Are you sure you want to delete the signed document '{document_name}'?\n\nFile: {filename}"
            )
            
            if result:
                if hasattr(self, '_sig_delete_document') and self._sig_delete_document:
                    delete_result = self._sig_delete_document(filename)
                    if delete_result['status'] == 'success':
                        self.signature_display.insert('end', f"🗑️ Deleted document: {document_name}\n")
                        self.refresh_signed_documents()
                        self.update_status(f"Deleted signed document: {filename}")
                    else:
                        messagebox.showerror("Error", f"Failed to delete: {delete_result.get('message', 'Unknown error')}")
                else:
                    # Simulation mode - just remove from tree
                    self.signed_docs_tree.delete(selection[0])
                    self.signature_display.insert('end', f"🗑️ Deleted document: {document_name} (simulation)\n")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete document: {str(e)}")
        
        self.signature_display.see('end')
    
    # Comparison analysis method
    def run_comparison(self):
        """Run VPN Encryption vs Digital Signatures comparison analysis"""
        if self._run_comparison:
            try:
                fig = self._run_comparison()
                if fig:
                    # Clear current plot and update with new comparison chart
                    self.ax.clear()
                    
                    # Create VPN vs Digital Signatures comparison as per SRS requirement
                    methods = ['VPN Encryption', 'Digital Signatures']
                    
                    # Performance Overhead (lower is better - inverted for display)
                    performance_overhead = [25, 85]  # VPN has lower overhead
                    
                    # Confidentiality Score (higher is better)
                    confidentiality = [95, 40]  # VPN excels in confidentiality
                    
                    # Authenticity Score (higher is better) 
                    authenticity = [60, 95]  # Digital Signatures excel in authenticity
                    
                    # Implementation Ease (higher is better)
                    implementation = [70, 80]  # Digital signatures slightly easier
                    
                    x = [0, 1]
                    width = 0.2
                    
                    self.ax.bar([i - 1.5*width for i in x], performance_overhead, width, 
                              label='Performance', color=self.colors['primary'])
                    self.ax.bar([i - 0.5*width for i in x], confidentiality, width, 
                              label='Confidentiality', color=self.colors['secondary'])
                    self.ax.bar([i + 0.5*width for i in x], authenticity, width, 
                              label='Authenticity', color=self.colors['success'])
                    self.ax.bar([i + 1.5*width for i in x], implementation, width, 
                              label='Implementation Ease', color=self.colors['warning'])
                    
                    self.ax.set_xlabel('Security Methods')
                    self.ax.set_ylabel('Effectiveness Score (0-100)')
                    self.ax.set_title('VPN Encryption vs Digital Signatures Comparison')
                    self.ax.set_xticks(x)
                    self.ax.set_xticklabels(methods)
                    self.ax.legend()
                    self.ax.grid(True, alpha=0.3)
                    
                    self.fig.canvas.draw()
                    
                    # Add analysis text
                    analysis_text = """
COMPARISON ANALYSIS - VPN ENCRYPTION VS DIGITAL SIGNATURES

🌐 VPN ENCRYPTION:
• Strength: Excellent confidentiality (95/100)
• Weakness: Moderate authenticity (60/100) 
• Use Case: Securing data transmission channels
• Performance: Low overhead, efficient for bulk data

✍️ DIGITAL SIGNATURES:
• Strength: Excellent authenticity (95/100)
• Weakness: Limited confidentiality (40/100)
• Use Case: Verifying message integrity and sender identity
• Performance: Higher overhead, ideal for verification

🏆 RECOMMENDATION:
For CONFIDENTIALITY: VPN Encryption is superior
For AUTHENTICITY: Digital Signatures are superior
Best Practice: Use BOTH together for complete security
"""
                    
                    # Update comparison results area if it exists
                    if hasattr(self, 'comparison_results'):
                        self.comparison_results.delete('1.0', 'end')
                        self.comparison_results.insert('end', analysis_text)
                        
            except Exception as e:
                self.ax.clear()
                self.ax.text(0.5, 0.5, f'Comparison Error: {str(e)}', 
                           horizontalalignment='center', verticalalignment='center')
                self.fig.canvas.draw()
        else:
            # Fallback comparison when backend not available
            methods = ['VPN Encryption', 'Digital Signatures']
            overall_scores = [85, 80]  # Overall effectiveness scores
            
            self.ax.clear()
            bars = self.ax.bar(methods, overall_scores, 
                             color=[self.colors['primary'], self.colors['secondary']])
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                self.ax.text(bar.get_x() + bar.get_width()/2., height + 1,
                           f'{height}%', ha='center', va='bottom')
            
            self.ax.set_title('VPN Encryption vs Digital Signatures\nOverall Effectiveness Comparison')
            self.ax.set_ylabel('Overall Effectiveness Score')
            self.ax.set_ylim(0, 100)
            self.ax.grid(True, alpha=0.3)
            
            self.fig.canvas.draw()
    
    # Tool integration methods
    def demo_openssl_keygen(self):
        """Demo OpenSSL key generation"""
        self.tools_output.insert('end', "🔐 OpenSSL Key Generation Demo\n")
        self.tools_output.insert('end', "$ openssl genrsa -out private.pem 2048\n")
        self.tools_output.insert('end', "Generating RSA private key, 2048 bit...\n")
        self.tools_output.insert('end', "✅ Private key generated successfully\n\n")
        self.tools_output.see('end')
    
    def demo_gnupg_email(self):
        """Demo GnuPG email encryption"""
        self.tools_output.insert('end', "📧 GnuPG Email Encryption Demo\n")
        self.tools_output.insert('end', "$ gpg --encrypt --recipient user@example.com message.txt\n")
        self.tools_output.insert('end', "✅ Email encrypted with GnuPG\n\n")
        self.tools_output.see('end')
    
    def demo_wireshark_vpn(self):
        """Demo Wireshark VPN analysis"""
        self.tools_output.insert('end', "🌐 Wireshark VPN Traffic Analysis\n")
        self.tools_output.insert('end', "Capturing packets on interface eth0...\n")
        self.tools_output.insert('end', "✅ VPN tunnel traffic analyzed\n\n")
        self.tools_output.see('end')
    
    def demo_bash_workflow(self, workflow_type):
        """Demo bash workflow for different security operations"""
        workflows = {
            'email': "📧 Email Security Workflow\n$ gpg --gen-key\n$ gpg --encrypt message.txt\n✅ Secure email workflow completed\n\n",
            'vpn': "🌐 VPN Setup Workflow\n$ openvpn --config client.ovpn\n✅ VPN connection established\n\n",
            'signature': "✍️ Digital Signature Workflow\n$ openssl dgst -sha256 -sign private.pem document.txt\n✅ Document signed successfully\n\n"
        }
        
        self.tools_output.insert('end', workflows.get(workflow_type, "Unknown workflow\n"))
        self.tools_output.see('end')
    
    def set_vpn_handlers(self, init_vpn, start_vpn, stop_vpn, get_status):
        self._vpn_init = init_vpn
        self._vpn_start = start_vpn
        self._vpn_stop = stop_vpn
        self._vpn_status = get_status
    
    def set_signature_handlers(self, generate_keys, sign, verify, save_document=None, load_document=None, 
                             list_documents=None, verify_external=None, export_key=None, import_key=None, delete_document=None):
        self._sig_generate = generate_keys
        self._sig_sign = sign
        self._sig_verify = verify
        self._sig_save_document = save_document
        self._sig_load_document = load_document
        self._sig_list_documents = list_documents
        self._sig_verify_external = verify_external
        self._sig_export_key = export_key
        self._sig_import_key = import_key
        self._sig_delete_document = delete_document
    
    def set_comparison_handler(self, run_comparison):
        self._run_comparison = run_comparison

    def set_message_storage_handler(self, message_storage):
        self._message_storage = message_storage
    
    def toggle_input_method(self):
        """Toggle between message composition and file upload modes"""
        if self.input_method.get() == "message":
            # Show message section, hide file section
            self.message_section.pack(fill='x', padx=10, pady=10, after=self.secure_comm_frame.winfo_children()[1])
            self.file_section.pack_forget()
            self.secure_results.delete('1.0', 'end')
            self.secure_results.insert('end', "📝 Message Composition Mode\n")
            self.secure_results.insert('end', "=" * 30 + "\n\n")
            self.secure_results.insert('end', "Type your message above and use 'Encrypt & Save As...' to choose where to save.\n\n")
        else:
            # Show file section, hide message section  
            self.file_section.pack(fill='x', padx=10, pady=10, after=self.secure_comm_frame.winfo_children()[1])
            self.message_section.pack_forget()
            self.secure_results.delete('1.0', 'end')
            self.secure_results.insert('end', "📁 File Upload Mode\n")
            self.secure_results.insert('end', "=" * 30 + "\n\n")
            self.secure_results.insert('end', "Select a .txt, .eml, or .enc file and choose custom save locations.\n\n")
    
    def generate_secure_keys(self):
        """Generate encryption keys for secure communication (backward compatibility)"""
        return self.generate_and_display_key()
    
    def encrypt_and_save(self):
        """Encrypt content (message or file) and save in unified format"""
        try:
            self.update_status("Encrypting content...")
            self.secure_progress.start()
            
            content = ""
            content_type = ""
            metadata = {}
            
            if self.input_method.get() == "message":
                content = self.message_content.get('1.0', 'end-1c').strip()
                if not content:
                    messagebox.showwarning("Warning", "Please enter a message to encrypt")
                    self.secure_progress.stop()
                    return
                content_type = "message"
                metadata = {
                    "type": "message",
                    "sender": "user@cipherguard.local",
                    "subject": "Secure Message"
                }
            else:
                if not hasattr(self, 'selected_file_path'):
                    messagebox.showwarning("Warning", "Please select a file to encrypt")
                    self.secure_progress.stop()
                    return
                
                # Read file content
                with open(self.selected_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                content_type = "file"
                file_ext = os.path.splitext(self.selected_file_path)[1].lower()
                metadata = {
                    "type": "file",
                    "original_filename": os.path.basename(self.selected_file_path),
                    "file_extension": file_ext,
                    "file_size": len(content)
                }
            
            self.secure_results.insert('end', f"🔒 Encrypting {content_type}...\n")
            self.secure_results.insert('end', f"Content length: {len(content)} characters\n")
            
            # Check if user has entered a key
            user_key = self.key_text_area.get('1.0', 'end-1c').strip()
            if not user_key:
                messagebox.showwarning("Warning", "Please generate or enter an encryption key first")
                self.secure_progress.stop()
                return
            
            # Use simple encryption with user's key
            try:
                import base64
                from cryptography.fernet import Fernet
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                
                # Derive encryption key from user key
                salt = b'cipherguard_salt_2024'  # Fixed salt for consistency
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(user_key.encode()))
                fernet = Fernet(key)
                
                encrypted_content = fernet.encrypt(content.encode())
                
                # Create result in expected format
                result = {
                    'status': 'success',
                    'message': base64.b64encode(encrypted_content).decode(),
                    'key': user_key,
                    'iv': 'fernet_builtin',
                    'signature': 'user_key_signature'
                }
                
                # Store for decryption
                self.last_encrypted_result = result
                
                # Save using message storage in unified format
                if self._message_storage:
                    filename = self._message_storage.save_encrypted_message(result, metadata)
                    
                    self.secure_results.insert('end', f"✓ Encryption successful!\n")
                    self.secure_results.insert('end', f"💾 Saved as: {filename}\n")
                    self.secure_results.insert('end', f"🔐 Method: AES-256 encryption with user key\n")
                    self.secure_results.insert('end', f"🔑 Key: {user_key[:20]}...\n")
                    self.secure_results.insert('end', f"📅 Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    # Clear content after successful encryption
                    if self.input_method.get() == "message":
                        self.message_content.delete('1.0', 'end')
                    
                    self.update_status(f"Content encrypted and saved as {filename}")
                else:
                    # Fallback - save to file directly
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"message_{timestamp}.enc"
                    
                    # Save encrypted data
                    encrypted_data = {
                        'encrypted_content': result,
                        'metadata': metadata,
                        'created_at': datetime.now().isoformat()
                    }
                    
                    import json
                    with open(f"src/encrypted_messages/{filename}", 'w') as f:
                        json.dump(encrypted_data, f, indent=2)
                    
                    self.secure_results.insert('end', f"✓ Encryption successful!\n")
                    self.secure_results.insert('end', f"💾 Saved as: {filename}\n")
                    self.secure_results.insert('end', f"🔐 Method: AES-256 encryption\n\n")
                    
                    # Store for decryption
                    self.last_encrypted_result = result
                    
                    self.update_status(f"Content encrypted and saved as {filename}")
                    
            except Exception as enc_error:
                raise Exception(f"Encryption failed: {str(enc_error)}")
            else:
                # Fallback simulation
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"message_{timestamp}.enc"
                
                self.secure_results.insert('end', f"✓ Content encrypted (simulation)\n")
                self.secure_results.insert('end', f"💾 Saved as: {filename}\n\n")
                self.update_status("Content encrypted (simulation)")
            
            self.secure_progress.stop()
            self.secure_results.see('end')
            
        except Exception as e:
            self.secure_progress.stop()
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.update_status("Encryption failed")
    
    def decrypt_message(self):
        """Decrypt a selected encrypted message"""
        try:
            self.update_status("Decrypting message...")
            self.secure_progress.start()
            
            # Check if user has entered the decryption key
            user_key = self.key_text_area.get('1.0', 'end-1c').strip()
            if not user_key:
                messagebox.showwarning("Warning", "Please enter the decryption key first")
                self.secure_progress.stop()
                return
            
            # Try to decrypt the last encrypted content if available
            if hasattr(self, 'last_encrypted_result'):
                try:
                    import base64
                    from cryptography.fernet import Fernet
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                    
                    # Derive decryption key from user key
                    salt = b'cipherguard_salt_2024'
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(user_key.encode()))
                    fernet = Fernet(key)
                    
                    # Decrypt the content
                    encrypted_data = base64.b64decode(self.last_encrypted_result['message'])
                    decrypted_content = fernet.decrypt(encrypted_data).decode()
                    
                    self.secure_results.insert('end', "🔓 Message Decrypted Successfully!\n")
                    self.secure_results.insert('end', "=" * 40 + "\n")
                    self.secure_results.insert('end', f"Content: {decrypted_content[:200]}{'...' if len(decrypted_content) > 200 else ''}\n")
                    self.secure_results.insert('end', f"Key Used: {user_key[:20]}...\n")
                    self.secure_results.insert('end', f"Status: Decryption successful\n\n")
                    
                    # Display decrypted content in message area
                    if self.input_method.get() == "message":
                        self.message_content.delete('1.0', 'end')
                        self.message_content.insert('1.0', decrypted_content)
                    
                    self.update_status("Message decrypted successfully")
                    
                except Exception as dec_error:
                    self.secure_results.insert('end', f"❌ Decryption failed: {str(dec_error)}\n")
                    self.secure_results.insert('end', "💡 Make sure you're using the correct key\n\n")
                    self.update_status("Decryption failed - check key")
            else:
                messagebox.showinfo("Info", "No encrypted message available. Please encrypt a message first or load from storage.")
            
            self.secure_progress.stop()
            self.secure_results.see('end')
            
        except Exception as e:
            self.secure_progress.stop()
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.update_status("Decryption failed")
    
    def save_current_message(self):
        """Save current message content in encrypted format (backward compatibility)"""
        return self.encrypt_and_save_as()
    
    def select_file(self):
        """Select file for encryption/decryption"""
        try:
            filetypes = [
                ("Supported files", "*.txt;*.eml;*.enc"),
                ("Text files", "*.txt"), 
                ("Email files", "*.eml"),
                ("Encrypted files", "*.enc"),
                ("All files", "*.*")
            ]
            title = "Select File (.txt, .eml, or .enc)"
            
            filename = filedialog.askopenfilename(title=title, filetypes=filetypes)
            
            if filename:
                self.selected_file_path = filename
                file_ext = os.path.splitext(filename)[1].lower()
                self.file_path_var.set(os.path.basename(filename))
                self.update_status(f"Selected file: {os.path.basename(filename)}")
                
                # Show file info
                file_size = os.path.getsize(filename)
                self.secure_results.insert('end', f"\n📁 File Selected: {os.path.basename(filename)}\n")
                self.secure_results.insert('end', f"📍 Path: {filename}\n")
                self.secure_results.insert('end', f"📏 Size: {file_size} bytes\n")
                self.secure_results.insert('end', f"📅 Modified: {datetime.fromtimestamp(os.path.getmtime(filename))}\n")
                
                # Show file type specific info
                if file_ext == '.enc':
                    self.secure_results.insert('end', f"🔒 Type: Encrypted file (ready for decryption)\n\n")
                elif file_ext in ['.txt', '.eml']:
                    self.secure_results.insert('end', f"📄 Type: {file_ext.upper()} file (ready for encryption)\n\n")
                else:
                    self.secure_results.insert('end', f"📄 Type: {file_ext.upper()} file\n\n")
                    
                self.secure_results.see('end')
                return True
            return False
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to select file: {str(e)}")
            return False
    
    def encrypt_and_save_as(self):
        """Encrypt content and save with user-chosen name and location"""
        try:
            # Get content first
            content = ""
            content_type = ""
            metadata = {}
            
            if self.input_method.get() == "message":
                content = self.message_content.get('1.0', 'end-1c').strip()
                if not content:
                    messagebox.showwarning("Warning", "Please enter a message to encrypt")
                    return
                content_type = "message"
                default_name = "secure_message.enc"
                metadata = {
                    "type": "message",
                    "sender": "user@cipherguard.local",
                    "subject": "Secure Message"
                }
            else:
                if not hasattr(self, 'selected_file_path'):
                    messagebox.showwarning("Warning", "Please select a file to encrypt")
                    return
                
                with open(self.selected_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                content_type = "file"
                original_name = os.path.splitext(os.path.basename(self.selected_file_path))[0]
                default_name = f"{original_name}_encrypted.enc"
                file_ext = os.path.splitext(self.selected_file_path)[1].lower()
                metadata = {
                    "type": "file",
                    "original_filename": os.path.basename(self.selected_file_path),
                    "file_extension": file_ext,
                    "file_size": len(content)
                }
            
            # Check for encryption key
            user_key = self.key_text_area.get('1.0', 'end-1c').strip()
            if not user_key:
                messagebox.showwarning("Warning", "Please generate or enter an encryption key first")
                return
            
            # Let user choose save location and name
            save_path = filedialog.asksaveasfilename(
                title="Save Encrypted File As",
                defaultextension=".enc",
                initialfile=default_name,
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
            )
            
            if not save_path:
                return  # User cancelled
            
            self.update_status("Encrypting content...")
            self.secure_progress.start()
            
            # Encrypt the content
            import base64
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            
            salt = b'cipherguard_salt_2024'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(user_key.encode()))
            fernet = Fernet(key)
            
            encrypted_content = fernet.encrypt(content.encode())
            
            # Create encrypted data structure
            encrypted_data = {
                'encrypted_content': {
                    'message': base64.b64encode(encrypted_content).decode(),
                    'key': user_key,
                    'iv': 'fernet_builtin',
                    'signature': 'user_key_signature'
                },
                'metadata': metadata,
                'created_at': datetime.now().isoformat()
            }
            
            # Save to chosen location
            import json
            with open(save_path, 'w') as f:
                json.dump(encrypted_data, f, indent=2)
            
            # Store for decryption
            self.last_encrypted_result = encrypted_data['encrypted_content']
            
            self.secure_results.insert('end', f"✓ Encryption successful!\n")
            self.secure_results.insert('end', f"💾 Saved as: {os.path.basename(save_path)}\n")
            self.secure_results.insert('end', f"📍 Location: {save_path}\n")
            self.secure_results.insert('end', f"🔐 Method: AES-256 encryption\n")
            self.secure_results.insert('end', f"📅 Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Clear content after successful encryption
            if self.input_method.get() == "message":
                self.message_content.delete('1.0', 'end')
            
            self.secure_progress.stop()
            self.secure_results.see('end')
            self.update_status(f"Content encrypted and saved to {os.path.basename(save_path)}")
            
        except Exception as e:
            self.secure_progress.stop()
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.update_status("Encryption failed")
    
    def decrypt_and_save_as(self):
        """Decrypt content and save with user-chosen name and location"""
        try:
            # Check for decryption key
            user_key = self.key_text_area.get('1.0', 'end-1c').strip()
            if not user_key:
                messagebox.showwarning("Warning", "Please enter the decryption key first")
                return
            
            # Check if we have encrypted content to decrypt
            if not hasattr(self, 'last_encrypted_result') or not self.last_encrypted_result:
                # Try to load from selected .enc file
                if hasattr(self, 'selected_file_path') and self.selected_file_path.endswith('.enc'):
                    try:
                        import json
                        with open(self.selected_file_path, 'r') as f:
                            file_data = json.load(f)
                        
                        if 'encrypted_content' in file_data:
                            self.last_encrypted_result = file_data['encrypted_content']
                        else:
                            raise ValueError("Invalid encrypted file format")
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to load encrypted file: {str(e)}")
                        return
                else:
                    messagebox.showwarning("Warning", "No encrypted content available. Please encrypt something first or select an .enc file.")
                    return
            
            self.update_status("Decrypting content...")
            self.secure_progress.start()
            
            # Decrypt the content
            import base64
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            
            salt = b'cipherguard_salt_2024'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(user_key.encode()))
            fernet = Fernet(key)
            
            encrypted_data = base64.b64decode(self.last_encrypted_result['message'])
            decrypted_content = fernet.decrypt(encrypted_data).decode()
            
            # Determine default filename
            if hasattr(self, 'selected_file_path') and self.selected_file_path:
                base_name = os.path.splitext(os.path.basename(self.selected_file_path))[0]
                if base_name.endswith('_encrypted'):
                    base_name = base_name[:-10]
                default_name = f"{base_name}_decrypted.txt"
            else:
                default_name = "decrypted_message.txt"
            
            # Let user choose save location and name
            save_path = filedialog.asksaveasfilename(
                title="Save Decrypted Content As",
                defaultextension=".txt",
                initialfile=default_name,
                filetypes=[("Text files", "*.txt"), ("Email files", "*.eml"), ("All files", "*.*")]
            )
            
            if not save_path:
                self.secure_progress.stop()
                return  # User cancelled
            
            # Save decrypted content
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(decrypted_content)
            
            self.secure_results.insert('end', "🔓 Decryption successful!\n")
            self.secure_results.insert('end', f"💾 Saved as: {os.path.basename(save_path)}\n")
            self.secure_results.insert('end', f"📍 Location: {save_path}\n")
            self.secure_results.insert('end', f"📏 Content length: {len(decrypted_content)} characters\n")
            self.secure_results.insert('end', f"📅 Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Display decrypted content in message area if in message mode
            if self.input_method.get() == "message":
                self.message_content.delete('1.0', 'end')
                self.message_content.insert('1.0', decrypted_content)
            
            self.secure_progress.stop()
            self.secure_results.see('end')
            self.update_status(f"Content decrypted and saved to {os.path.basename(save_path)}")
            
        except Exception as e:
            self.secure_progress.stop()
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.update_status("Decryption failed - check key and file")