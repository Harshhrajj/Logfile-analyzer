import os
import re
import json
import logging
from datetime import datetime
from collections import defaultdict
from flask import Flask, request, render_template, jsonify, send_file
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'log', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class LogAnalyzer:
    def __init__(self):
        self.stats = {
            'total_attacks': 0,
            'sql_injection_count': 0,
            'xss_count': 0,
            'ddos_count': 0,
            'brute_force_count': 0,
            'unique_ips': set()
        }
        self.ip_frequency = defaultdict(int)
        self.attacks = {
            'sql_injection': [],
            'xss': [],
            'ddos': [],
            'brute_force': []
        }
        
    def analyze_line(self, line, line_number):
        # Extract IP address if present
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        ip = ip_match.group(0) if ip_match else None
        
        if ip:
            self.stats['unique_ips'].add(ip)
            self.ip_frequency[ip] += 1
        
        # Check for SQL injection attempts
        if re.search(r'(?i)(union\s+select|select.*from|drop\s+table|--\s*$)', line):
            self.stats['sql_injection_count'] += 1
            self.attacks['sql_injection'].append({
                'line': line_number,
                'ip': ip,
                'content': line.strip()
            })
        
        # Check for XSS attempts
        if re.search(r'(?i)(<script>|alert\(|onload=|onerror=|javascript:)', line):
            self.stats['xss_count'] += 1
            self.attacks['xss'].append({
                'line': line_number,
                'ip': ip,
                'content': line.strip()
            })
        
        # Check for potential DDoS (high frequency from same IP)
        if ip and self.ip_frequency[ip] > 100:
            if not any(attack['ip'] == ip for attack in self.attacks['ddos']):
                self.stats['ddos_count'] += 1
                self.attacks['ddos'].append({
                    'line': line_number,
                    'ip': ip,
                    'count': self.ip_frequency[ip]
                })
        
        # Check for brute force attempts
        if re.search(r'(?i)(failed login|authentication failure|invalid password)', line):
            self.stats['brute_force_count'] += 1
            self.attacks['brute_force'].append({
                'line': line_number,
                'ip': ip,
                'content': line.strip()
            })
    
    def analyze_file(self, file):
        line_number = 0
        for line in file:
            line_number += 1
            if isinstance(line, bytes):
                line = line.decode('utf-8', errors='ignore')
            self.analyze_line(line, line_number)
        
        self.stats['total_attacks'] = (
            self.stats['sql_injection_count'] +
            self.stats['xss_count'] +
            self.stats['ddos_count'] +
            self.stats['brute_force_count']
        )
        
        return {
            'stats': {
                'total_attacks': self.stats['total_attacks'],
                'sql_injection_count': self.stats['sql_injection_count'],
                'xss_count': self.stats['xss_count'],
                'ddos_count': self.stats['ddos_count'],
                'brute_force_count': self.stats['brute_force_count'],
                'unique_ips': len(self.stats['unique_ips'])
            },
            'ip_frequency': dict(self.ip_frequency),
            'sql_injection': self.attacks['sql_injection'],
            'xss': self.attacks['xss'],
            'ddos': self.attacks['ddos'],
            'brute_force': self.attacks['brute_force']
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Invalid file type'})
    
    try:
        analyzer = LogAnalyzer()
        results = analyzer.analyze_file(file)
        
        # Save results to a file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        result_filename = f'analysis_result_{timestamp}.json'
        result_path = os.path.join(app.config['UPLOAD_FOLDER'], result_filename)
        
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        with open(result_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        return jsonify({
            'success': True,
            'results': results
        })
    
    except Exception as e:
        logging.error(f'Error analyzing file: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/download/<format>')
def download_results(format):
    try:
        # Get the most recent analysis result
        result_files = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if f.startswith('analysis_result_')]
        if not result_files:
            return jsonify({'success': False, 'error': 'No analysis results found'})
        
        latest_result = max(result_files)
        result_path = os.path.join(app.config['UPLOAD_FOLDER'], latest_result)
        
        if format == 'json':
            return send_file(result_path, mimetype='application/json', as_attachment=True)
        else:
            return jsonify({'success': False, 'error': 'Invalid format requested'})
    
    except Exception as e:
        logging.error(f'Error downloading results: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True) 