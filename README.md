# Log File Analyzer

The Log File Analyzer is a web-based tool for detecting and analyzing cybersecurity threats like DDoS attacks and Brute Force attempts from server logs. Users can upload log files through an intuitive dashboard, and the system highlights suspicious activities, providing detailed results and visualizations. Built with HTML, CSS, and JavaScript.

## Features

### Core Functionality
- **Multi-format Log Analysis**: Supports various log formats including `.log`, `.txt`, `.csv`, `.json`, `.evtx`, `.syslog`, and `.bin` files
- **Automatic Format Detection**: Identifies and parses log formats based on file extension
- **Comprehensive Security Analysis**: Detects multiple attack types including:
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
- **Drag-and-Drop Upload**: Easy file upload with drag-and-drop functionality
- **Multiple File Processing**: Analyze multiple log files in a single session
- **Loading Animations**: Visual feedback during analysis process
- **Auto-scrolling**: Automatically scrolls to results after analysis

### Visualization
- **Interactive Charts**: Visual representation of analysis results using Chart.js
  - Attack Type Distribution
  - Severity Level Distribution
  - Event Timeline
  - Source Distribution
- **Filtering Options**: Filter results by severity level or attack type
- **Security Recommendations**: Contextual security recommendations based on detected threats

## Usage Guide

### Getting Started
1. **Access the Application**: Open `index.html` in a modern web browser
2. **Choose Theme**: Use the theme toggle button (bottom right) to switch between dark and light themes

### Analyzing Log Files
1. **Upload Files**:
   - Drag and drop log files onto the designated area, or
   - Click "Choose Files" to select files from your device
   - Supported formats: `.log`, `.txt`, `.csv`, `.json`, `.evtx`, `.syslog`, and `.bin`

2. **Start Analysis**:
   - Click the "Analyze Logs" button
   - A loading animation will appear during processing

3. **View Results**:
   - The page will automatically scroll to the results section
   - Review the summary statistics at the top of the page
   - Explore the visual charts for attack distribution and severity

4. **Filter and Explore**:
   - Use the dropdown filters to focus on specific severity levels or attack types
   - Review detailed security events in the list below the charts
   - Check the recommendations section for security advice

### Understanding the Results
- **Statistics Header**:
  - Total Events: All log entries analyzed
  - Critical Events: High-priority security concerns
  - Warnings: Medium-priority security concerns

- **Charts**:
  - Attack Types: Distribution of different attack categories
  - Severity Levels: Proportion of critical, high, medium, and low severity events
  - Timeline: Chronological distribution of events
  - Sources: Origin points of detected attacks

- **Security Events List**:
  - Each event shows the line number, attack type, and severity
  - Color-coded for quick severity assessment
  - Includes the raw log line for reference

- **Recommendations**:
  - Actionable security advice based on detected threats
  - Prioritized by severity and attack type

## Technical Documentation

### Architecture
The application follows a simple front-end architecture with three main components:
- **HTML (index.html)**: Structure and content
- **CSS (styles.css)**: Styling and theming
- **JavaScript (script.js)**: Logic and functionality

### Key Components

#### Log Parsing System
- Format-specific parsers for different log types
- Automatic format detection based on file extension
- Fallback to text parsing for unknown formats

```javascript
const FILE_HANDLERS = {
    'csv': parseCsvLog,
    'json': parseJsonLog,
    'evtx': parseEvtxLog,
    'syslog': parseSyslog,
    'bin': parseBinaryLog,
    'txt': parseTextLog,
    'log': parseTextLog
};
```

#### Security Pattern Detection
- Regular expression patterns for various attack types
- Severity classification for each attack category
- Extensible pattern system for adding new threat types

```javascript
const SECURITY_PATTERNS = {
    bruteforce: {
        patterns: [
            /failed login attempt/i,
            /authentication failure/i,
            // Additional patterns...
        ],
        severity: 'high'
    },
    // Additional attack types...
};
```

#### Theming System
- CSS variables for theme colors and properties
- Theme persistence using localStorage
- Dynamic chart updates when theme changes

```javascript
// Theme toggle functionality
themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
    // Additional theme handling...
});
```

#### Visualization Engine
- Chart.js for data visualization
- Theme-aware chart rendering
- Responsive chart layouts

```javascript
function updateCharts() {
    // Chart initialization and updates...
}
```

### Data Flow
1. User uploads log file(s)
2. File content is read and parsed based on format
3. Log entries are analyzed against security patterns
4. Results are aggregated and statistics are calculated
5. UI is updated with results and visualizations
6. Charts are rendered with appropriate theming

## Extending the Application

### Adding New Log Formats
To add support for a new log format:
1. Create a parser function in `script.js`
2. Add the format to the `FILE_HANDLERS` object
3. Ensure proper timestamp extraction

### Adding New Attack Patterns
To add detection for new attack types:
1. Add a new entry to the `SECURITY_PATTERNS` object
2. Define regex patterns and severity level
3. Add corresponding recommendation in the `getRecommendation` function

### Customizing Themes
To modify the theme colors:
1. Update the CSS variables in the `:root` section of `styles.css`
2. Adjust both dark and light theme variables as needed

## Browser Compatibility
- Chrome (latest)
- Firefox (latest)
- Edge (latest)
- Safari (latest)

## Dependencies
- [Chart.js](https://www.chartjs.org/) - For data visualization
- [Font Awesome](https://fontawesome.com/) - For icons

## License
This project is available for personal and commercial use.
