# Security Log Analyzer

A Flask-based web application for analyzing security log files to detect potential cyber attacks. The application provides a modern user interface for uploading log files and visualizes the analysis results using interactive charts.

## Features

- Upload and analyze security log files
- Detect multiple types of attacks:
  - SQL Injection attempts
  - Cross-Site Scripting (XSS)
  - DDoS attacks
  - Brute Force attempts
- Interactive visualizations using Chart.js
- Detailed attack analysis with timestamps and IP addresses
- Download analysis results in JSON or CSV format
- Drag-and-drop file upload interface

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/security-log-analyzer.git
cd security-log-analyzer
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the Flask application:
```bash
python app.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

3. Upload a log file using one of these methods:
   - Click the upload area and select a file
   - Drag and drop a file onto the upload area

4. View the analysis results:
   - Attack distribution chart
   - IP frequency chart
   - Detailed attack table
   - Statistics summary

5. Download results:
   - Click "Download JSON" for raw data
   - Click "Download CSV" for spreadsheet format

## Supported Log Formats

The analyzer supports common log formats including:
- Apache access logs
- Nginx access logs
- Custom log formats with timestamps and IP addresses

## Security Considerations

- Maximum file size: 16MB
- Allowed file extensions: .log, .txt
- Files are processed in memory without permanent storage
- Input sanitization for XSS prevention
- Secure file handling using Werkzeug

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
