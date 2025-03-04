# Log File Analyzer with AI-Powered Security Analysis

A sophisticated web-based security log analyzer that leverages OpenAI's GPT models to provide intelligent security analysis and actionable recommendations. The application analyzes various log formats for security threats, utilizing both pattern matching and AI-driven contextual analysis.

## Features

### Core Functionality
- **Multi-format Log Analysis**: Supports `.log`, `.txt`, `.csv`, `.json`, `.evtx`, `.syslog`, and `.bin` files
- **AI-Powered Analysis**: Uses OpenAI's GPT models for:
  - Contextual threat analysis
  - Advanced pattern recognition
  - Natural language security recommendations
  - Risk assessment and prioritization
- **Comprehensive Security Detection**: Identifies multiple attack types including:
  - Brute Force Attempts
  - DDoS Attacks
  - Malware Detection
  - SQL/XSS Injection
  - Privilege Escalation
  - Data Leaks
  - Reconnaissance Activities

### User Interface
- **Dual Theme Support**: Toggle between dark (midnight blue) and light themes
- **Responsive Design**: Works on desktop and mobile devices
- **Interactive Dashboard**: Real-time analysis updates and visualizations
- **Multiple File Processing**: Analyze multiple log files in a single session

### Visualization & Analysis
- **Interactive Charts**: Visual representation using Chart.js
  - Attack Type Distribution
  - Severity Level Distribution
  - Event Timeline
  - Source Distribution
- **AI-Enhanced Recommendations**: Context-aware security advice
- **Risk Assessment**: AI-driven threat evaluation and prioritization

## Setup

### Prerequisites
- Modern web browser
- Node.js (for local development)
- OpenAI API key

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/log-file-analyzer.git
   cd log-file-analyzer
   ```

2. **Environment Setup**
   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # Edit .env with your OpenAI API key and preferences
   nano .env
   ```

3. **Configure OpenAI API**
   - Get your API key from [OpenAI's platform](https://platform.openai.com)
   - Add it to the `.env` file:
     ```
     OPENAI_API_KEY=your_api_key_here
     ```

4. **Install Dependencies**
   ```bash
   npm install
   ```

5. **Start the Application**
   ```bash
   npm start
   ```

### Environment Configuration

Key environment variables in `.env`:
```env
# OpenAI API Configuration
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4  # or gpt-3.5-turbo

# Security Analysis Configuration
MAX_TOKENS=1000
TEMPERATURE=0.7
LOG_BATCH_SIZE=50

# Application Configuration
DEBUG_MODE=false
ENABLE_DETAILED_LOGGING=true
```

## Usage Guide

### Basic Usage
1. Open the application in your web browser
2. Upload log files using drag-and-drop or file selection
3. Click "Analyze Logs" to start the analysis
4. Review AI-enhanced security recommendations and visualizations

### Advanced Features
1. **AI Analysis Settings**
   - Adjust analysis depth in `.env`
   - Configure token usage and rate limiting
   - Enable detailed logging for debugging

2. **Filtering and Exploration**
   - Filter results by severity or attack type
   - Sort recommendations by priority
   - Export analysis reports

3. **Theme Customization**
   - Toggle between light and dark themes
   - Customize theme colors in `styles.css`

## API Rate Limiting

The application includes built-in rate limiting for OpenAI API calls:
- Default: 60 requests per minute
- Configurable through `.env` settings
- Batch processing for large log files

## Security Considerations

1. **API Key Security**
   - Never commit your `.env` file
   - Use environment variables in production
   - Rotate API keys periodically

2. **Data Privacy**
   - Log data is processed locally
   - Only relevant excerpts are sent to OpenAI
   - No sensitive data is stored permanently

## Troubleshooting

Common issues and solutions:
1. **API Rate Limits**: Adjust `MAX_REQUESTS_PER_MINUTE` in `.env`
2. **Memory Issues**: Modify `LOG_BATCH_SIZE` for large files
3. **Analysis Timeout**: Check network connection and API status

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is available under the MIT License. See LICENSE file for details.

## Acknowledgments

- OpenAI for providing the GPT API
- Chart.js for visualization capabilities
- Contributors and community members
