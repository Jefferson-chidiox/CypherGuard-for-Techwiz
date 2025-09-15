import tkinter as tk
from tkinter import ttk
import threading
import time

class CipherGuardSplashScreen:
    def __init__(self, main_window_callback=None):
        self.main_window_callback = main_window_callback
        self.splash_root = tk.Tk()
        self.setup_splash_screen()
        
    def setup_splash_screen(self):
        """Setup the splash screen with professional styling"""
        self.splash_root.title("CipherGuard")
        self.splash_root.geometry("600x300")
        self.splash_root.resizable(False, False)
        self.splash_root.configure(bg='#1e2a3a')
        
        self.splash_root.overrideredirect(True)
        
        self.splash_root.update_idletasks()
        width = self.splash_root.winfo_width()
        height = self.splash_root.winfo_height()
        x = (self.splash_root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.splash_root.winfo_screenheight() // 2) - (height // 2)
        self.splash_root.geometry(f'{width}x{height}+{x}+{y}')
        
        self.colors = {
            'bg': '#1e2a3a',
            'primary': '#3498db',
            'text': '#ffffff',
            'subtext': '#bdc3c7'
        }
        
        self.create_splash_content()
        
    def create_splash_content(self):
        """Create sleek professional splash screen content"""
        main_frame = tk.Frame(self.splash_root, bg=self.colors['bg'])
        main_frame.pack(fill='both', expand=True)
        
        center_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        center_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        title_label = tk.Label(center_frame,
                              text="🛡️ CipherGuard",
                              font=('Segoe UI', 42, 'bold'),
                              fg=self.colors['text'],
                              bg=self.colors['bg'])
        title_label.pack(pady=(0, 15))
        
        subtitle_label = tk.Label(center_frame,
                                 text="Advanced Cryptographic Security & Education Platform",
                                 font=('Segoe UI', 16),
                                 fg=self.colors['primary'],
                                 bg=self.colors['bg'])
        subtitle_label.pack(pady=(0, 10))
        
        # Version info
        version_label = tk.Label(center_frame,
                                text="Version 1.0 - Educational Use Only",
                                font=('Segoe UI', 11),
                                fg=self.colors['subtext'],
                                bg=self.colors['bg'])
        version_label.pack()
        
    def start_timer(self):
        """Start 3-second timer before launching main app"""
        self.splash_root.after(3000, self.launch_main_application)
        
    def launch_main_application(self):
        """Launch the main CipherGuard application"""
        self.splash_root.destroy()
        if self.main_window_callback:
            self.main_window_callback()
    
    def show(self):
        """Display the splash screen for 3 seconds"""
        self.start_timer()
        self.splash_root.mainloop()


