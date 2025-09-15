import time
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import os

class SecurityMethodComparison:
    def __init__(self):
        self.metrics = {}
        self.test_data = os.urandom(10000)  # 10KB of random data
    
    def benchmark_encryption_methods(self):
        """Compare performance of different encryption methods with real encryption"""
        methods = {
            'RSA-2048': self._benchmark_rsa,
            'AES-256': self._benchmark_aes,
            'ChaCha20': self._benchmark_chacha20
        }
        
        performance_data = {}
        for method_name, benchmark_func in methods.items():
            start_time = time.time()
            security_level = self._assess_security_level(method_name)
            speed = benchmark_func()
            end_time = time.time()
            
            performance_data[method_name] = {
                'speed': speed,
                'security': security_level,
                'complexity': self._calculate_complexity(method_name),
                'time': end_time - start_time
            }
        
        self.metrics = performance_data
        return performance_data
    
    def _benchmark_rsa(self):
        """Benchmark RSA encryption"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            
            # RSA can only encrypt small chunks
            chunk_size = 190
            chunks = [self.test_data[i:i+chunk_size] for i in range(0, len(self.test_data), chunk_size)]
            
            start = time.time()
            for chunk in chunks:
                encrypted = public_key.encrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            duration = time.time() - start
            
            return 100 - (duration * 10)  # Convert to 0-100 scale
        except Exception as e:
            print(f"RSA benchmark error: {str(e)}")
            return 0
    
    def _benchmark_aes(self):
        """Benchmark AES encryption"""
        try:
            key = os.urandom(32)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            
            start = time.time()
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(self.test_data) + encryptor.finalize()
            duration = time.time() - start
            
            return 100 - (duration * 10)
        except Exception as e:
            print(f"AES benchmark error: {str(e)}")
            return 0
    
    def _benchmark_chacha20(self):
        """Benchmark ChaCha20 encryption"""
        try:
            key = os.urandom(32)
            nonce = os.urandom(16)
            algorithm = algorithms.ChaCha20(key, nonce)
            cipher = Cipher(algorithm, mode=None)
            
            start = time.time()
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(self.test_data)
            duration = time.time() - start
            
            return 100 - (duration * 10)
        except Exception as e:
            print(f"ChaCha20 benchmark error: {str(e)}")
            return 0
    
    def _assess_security_level(self, method):
        """Assess security level of encryption method"""
        security_levels = {
            'RSA-2048': 95,  # Very secure for current standards
            'AES-256': 90,   # Industry standard
            'ChaCha20': 88   # Modern and secure
        }
        return security_levels.get(method, 50)
    
    def _calculate_complexity(self, method):
        """Calculate implementation complexity"""
        complexity_levels = {
            'RSA-2048': 85,  # More complex due to key management
            'AES-256': 70,   # Moderate complexity
            'ChaCha20': 65   # Relatively simple
        }
        return complexity_levels.get(method, 50)
    
    def generate_comparison_chart(self):
        """Generate VPN Encryption vs Digital Signatures comparison"""
        # Focus on VPN Encryption vs Digital Signatures comparison
        vpn_analysis = self._analyze_vpn_encryption()
        signature_analysis = self._analyze_digital_signatures()
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 8))
        
        # Comparison metrics
        categories = ['Performance\nOverhead', 'Confidentiality', 'Authenticity', 'Implementation\nEase']
        vpn_scores = [90, 95, 60, 70]  # VPN strengths: low overhead, high confidentiality
        sig_scores = [70, 40, 95, 80]  # Signature strengths: high authenticity
        
        x = range(len(categories))
        width = 0.35
        
        # Bar chart comparison
        ax1.bar([i - width/2 for i in x], vpn_scores, width, label='VPN Encryption', 
               color='#3498db', alpha=0.8)
        ax1.bar([i + width/2 for i in x], sig_scores, width, label='Digital Signatures', 
               color='#e74c3c', alpha=0.8)
        
        ax1.set_xlabel('Security Aspects')
        ax1.set_ylabel('Effectiveness Score (0-100)')
        ax1.set_title('VPN Encryption vs Digital Signatures\nComparative Analysis')
        ax1.set_xticks(x)
        ax1.set_xticklabels(categories, rotation=45, ha='right')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Radar chart for comprehensive view
        angles = [i * 360 / len(categories) for i in range(len(categories))]
        angles += [angles[0]]  # Complete the circle
        
        vpn_scores_radar = vpn_scores + [vpn_scores[0]]
        sig_scores_radar = sig_scores + [sig_scores[0]]
        
        ax2 = plt.subplot(122, projection='polar')
        ax2.plot([a * 3.14159 / 180 for a in angles], vpn_scores_radar, 'o-', 
                linewidth=2, label='VPN Encryption', color='#3498db')
        ax2.fill([a * 3.14159 / 180 for a in angles], vpn_scores_radar, alpha=0.25, color='#3498db')
        
        ax2.plot([a * 3.14159 / 180 for a in angles], sig_scores_radar, 'o-', 
                linewidth=2, label='Digital Signatures', color='#e74c3c')
        ax2.fill([a * 3.14159 / 180 for a in angles], sig_scores_radar, alpha=0.25, color='#e74c3c')
        
        ax2.set_xticks([a * 3.14159 / 180 for a in angles[:-1]])
        ax2.set_xticklabels(categories)
        ax2.set_ylim(0, 100)
        ax2.set_title('Security Methods\nRadar Comparison', pad=20)
        ax2.legend(loc='upper right', bbox_to_anchor=(1.2, 1.0))
        ax2.grid(True)
        
        plt.tight_layout()
        return fig
    
    def _analyze_vpn_encryption(self):
        """Analyze VPN encryption characteristics"""
        return {
            'performance_overhead': 90,  # Low overhead
            'confidentiality': 95,       # Excellent for data privacy
            'authenticity': 60,          # Moderate sender verification
            'implementation_ease': 70,    # Requires infrastructure setup
            'use_cases': ['Secure tunneling', 'Remote access', 'Network privacy'],
            'strengths': ['Data confidentiality', 'Network-level protection', 'Scalable'],
            'weaknesses': ['Complex setup', 'Infrastructure dependent', 'Limited authenticity']
        }
    
    def _analyze_digital_signatures(self):
        """Analyze digital signature characteristics"""
        return {
            'performance_overhead': 70,  # Higher computational cost
            'confidentiality': 40,       # No data encryption
            'authenticity': 95,          # Excellent sender verification
            'implementation_ease': 80,    # Straightforward implementation
            'use_cases': ['Document integrity', 'Identity verification', 'Non-repudiation'],
            'strengths': ['Strong authenticity', 'Non-repudiation', 'Integrity verification'],
            'weaknesses': ['No confidentiality', 'Key management', 'Processing overhead']
        }
    
    def get_comparison_analysis(self):
        """Generate comparison analysis"""
        vpn_data = self._analyze_vpn_encryption()
        sig_data = self._analyze_digital_signatures()
        
        analysis = {
            'conclusion': 'VPN Encryption is better for CONFIDENTIALITY, Digital Signatures are better for AUTHENTICITY',
            'vpn_encryption': {
                'best_for': 'Securing data transmission channels and ensuring privacy',
                'effectiveness': 85,
                'primary_benefit': 'Confidentiality',
                'metrics': vpn_data
            },
            'digital_signatures': {
                'best_for': 'Verifying message integrity and sender authenticity',
                'effectiveness': 80,
                'primary_benefit': 'Authenticity and Non-repudiation',
                'metrics': sig_data
            },
            'recommendation': {
                'for_confidentiality': 'VPN Encryption',
                'for_authenticity': 'Digital Signatures',
                'best_practice': 'Use both methods together for comprehensive security',
                'specific_goals': {
                    'data_privacy': 'VPN Encryption (95/100)',
                    'sender_verification': 'Digital Signatures (95/100)',
                    'performance_efficiency': 'VPN Encryption (90/100)',
                    'implementation_simplicity': 'Digital Signatures (80/100)'
                }
            }
        }
        
        return analysis
