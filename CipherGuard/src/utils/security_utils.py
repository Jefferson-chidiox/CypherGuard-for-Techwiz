import os
import re
from pathlib import Path

class SecurityUtils:
    """Security utilities for input validation and sanitization"""
    
    @staticmethod
    def sanitize_filename(filename):
        """Sanitize filename to prevent path traversal attacks"""
        # Remove path separators and dangerous characters
        filename = re.sub(r'[<>:"/\\|?*]', '', filename)
        filename = re.sub(r'\.\.', '', filename)  # Remove .. sequences
        
        # Ensure filename is not empty and has reasonable length
        if not filename or len(filename) > 255:
            raise ValueError("Invalid filename")
            
        return filename
    
    @staticmethod
    def validate_file_path(filepath, base_directory):
        """Validate file path is within base directory"""
        try:
            base_path = Path(base_directory).resolve()
            file_path = Path(filepath).resolve()
            
            # Check if file path is within base directory
            if not str(file_path).startswith(str(base_path)):
                raise ValueError("Path traversal attempt detected")
                
            return str(file_path)
        except Exception:
            raise ValueError("Invalid file path")
    
    @staticmethod
    def validate_command_args(args):
        """Validate command line arguments to prevent injection"""
        dangerous_chars = ['&', '|', ';', '$', '`', '(', ')', '<', '>']
        
        for arg in args:
            if any(char in str(arg) for char in dangerous_chars):
                raise ValueError("Potentially dangerous command argument")
        
        return args