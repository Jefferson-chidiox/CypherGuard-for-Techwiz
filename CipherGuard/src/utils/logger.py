import logging
import datetime
import json
import os

class SimulationLogger:
    def __init__(self, log_file="logs/cipherguard.log"):
        self.log_file = log_file
        self.setup_logger()
        self.simulation_data = []
    
    def setup_logger(self):
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('CipherGuard')
    
    def log_encryption_event(self, event_type, details):
        """Log encryption/decryption events"""
        event = {
            'timestamp': datetime.datetime.now().isoformat(),
            'event_type': event_type,
            'details': details
        }
        self.simulation_data.append(event)
        self.logger.info(f"{event_type}: {details}")
    
    def generate_report(self):
        """Generate comprehensive simulation report"""
        report = {
            'simulation_summary': {
                'total_events': len(self.simulation_data),
                'start_time': self.simulation_data[0]['timestamp'] if self.simulation_data else None,
                'end_time': self.simulation_data[-1]['timestamp'] if self.simulation_data else None
            },
            'events': self.simulation_data
        }
        
        # Ensure logs directory exists
        if not os.path.exists('logs'):
            os.makedirs('logs')
            
        with open('logs/simulation_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report