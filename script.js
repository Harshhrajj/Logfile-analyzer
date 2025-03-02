/**
 * Log File Analyzer - Main JavaScript
 * 
 * This file contains the core functionality for the Log File Analyzer application,
 * including log parsing, security analysis, and visualization.
 */

/**
 * File format handlers - Maps file extensions to their respective parser functions
 * @type {Object.<string, Function>}
 */
const FILE_HANDLERS = {
    'csv': parseCsvLog,
    'json': parseJsonLog,
    'evtx': parseEvtxLog,
    'syslog': parseSyslog,
    'bin': parseBinaryLog,
    'txt': parseTextLog,
    'log': parseTextLog
};

/**
 * Security patterns for detecting various types of attacks
 * Each attack type contains regex patterns and a severity level
 * @type {Object.<string, {patterns: RegExp[], severity: string}>}
 */
const SECURITY_PATTERNS = {
    bruteforce: {
        patterns: [
            /failed login attempt/i,
            /authentication failure/i,
            /invalid password/i,
            /failed password/i,
            /multiple login failures/i,
            /brute force attempt/i,
            /password guessing/i
        ],
        severity: 'high'
    },
    ddos: {
        patterns: [
            /connection flood/i,
            /too many requests/i,
            /rate limit exceeded/i,
            /denial of service/i,
            /high traffic detected/i,
            /traffic spike/i,
            /bandwidth exceeded/i
        ],
        severity: 'critical'
    },
    malware: {
        patterns: [
            /malicious file detected/i,
            /virus found/i,
            /suspicious executable/i,
            /malware signature/i,
            /ransomware/i,
            /trojan detected/i,
            /backdoor attempt/i,
            /suspicious process/i
        ],
        severity: 'critical'
    },
    injection: {
        patterns: [
            /sql injection/i,
            /xss attempt/i,
            /script injection/i,
            /command injection/i,
            /code injection/i,
            /shell command execution/i,
            /remote code execution/i
        ],
        severity: 'critical'
    },
    privEsc: {
        patterns: [
            /privilege escalation/i,
            /unauthorized sudo/i,
            /permission violation/i,
            /unauthorized access/i,
            /root access attempt/i,
            /admin rights violation/i,
            /elevation of privilege/i
        ],
        severity: 'high'
    },
    dataLeak: {
        patterns: [
            /data breach/i,
            /information disclosure/i,
            /sensitive data exposure/i,
            /unauthorized data access/i,
            /data exfiltration/i
        ],
        severity: 'critical'
    },
    reconnaissance: {
        patterns: [
            /port scan/i,
            /network scan/i,
            /vulnerability scan/i,
            /probe attempt/i,
            /enumeration attempt/i
        ],
        severity: 'medium'
    }
};

/**
 * Statistics object to track analysis results
 * @type {Object}
 */
let stats = {
    totalEvents: 0,
    criticalEvents: 0,
    warningEvents: 0,
    attackTypes: {},
    severityLevels: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    },
    timeline: {},
    sources: {},
    destinations: {},
    protocols: {}
};

// Initialize charts
let attackChart = null;
let severityChart = null;
let timelineChart = null;
let sourceChart = null;

// Setup drag and drop
const dropZone = document.getElementById('dropZone');

['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, preventDefaults, false);
});

/**
 * Prevents default browser behavior for drag and drop events
 * @param {Event} e - The event object
 */
function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, highlight, false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, unhighlight, false);
});

/**
 * Highlights the drop zone when files are dragged over
 * @param {Event} e - The event object
 */
function highlight(e) {
    dropZone.classList.add('highlight');
}

/**
 * Removes highlight from the drop zone
 * @param {Event} e - The event object
 */
function unhighlight(e) {
    dropZone.classList.remove('highlight');
}

dropZone.addEventListener('drop', handleDrop, false);

/**
 * Handles file drop events
 * @param {DragEvent} e - The drag event object
 */
function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    handleFiles(files);
}

// Handle file selection
document.getElementById('logFile').addEventListener('change', function(e) {
    handleFiles(this.files);
});

/**
 * Theme management
 */
const themeToggle = document.getElementById('themeToggle');
const themeIcon = themeToggle.querySelector('i');
let currentTheme = localStorage.getItem('theme') || 'dark';

// Apply saved theme on load
if (currentTheme === 'light') {
    document.body.classList.add('light-theme');
    themeIcon.classList.replace('fa-moon', 'fa-sun');
}

/**
 * Theme toggle functionality
 * Switches between light and dark themes and updates charts
 */
themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
    
    if (document.body.classList.contains('light-theme')) {
        themeIcon.classList.replace('fa-moon', 'fa-sun');
        currentTheme = 'light';
    } else {
        themeIcon.classList.replace('fa-sun', 'fa-moon');
        currentTheme = 'dark';
    }
    
    localStorage.setItem('theme', currentTheme);
    
    // Update charts with new theme
    updateCharts();
});

// Loading overlay and functions
const loadingOverlay = document.querySelector('.loading-overlay');

/**
 * Shows the loading overlay
 */
function showLoading() {
    loadingOverlay.classList.add('active');
}

/**
 * Hides the loading overlay
 */
function hideLoading() {
    loadingOverlay.classList.remove('active');
}

/**
 * Scrolls to the results section
 */
function scrollToResults() {
    const resultsSection = document.getElementById('results');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Analyzes a single log file
 * @param {File} file - The file object to analyze
 */
function analyzeFile(file) {
    showLoading();
    const reader = new FileReader();
    
    reader.onload = function(e) {
        const content = e.target.result;
        const fileExt = file.name.split('.').pop().toLowerCase();
        const parser = FILE_HANDLERS[fileExt] || parseTextLog;
        
        let logEntries;
        try {
            logEntries = parser(content);
        } catch (error) {
            console.error(`Error parsing ${fileExt} file:`, error);
            alert(`Error parsing ${file.name}. Please check the file format.`);
            hideLoading();
            return;
        }

        const analysis = analyzeLogs(logEntries);
        updateUI(analysis);
        hideLoading();
        // Add small delay before scrolling to ensure UI is updated
        setTimeout(scrollToResults, 100);
    };

    reader.onerror = function() {
        console.error('Error reading file');
        alert('Error reading file. Please try again.');
        hideLoading();
    };

    if (file.name.endsWith('.bin')) {
        reader.readAsArrayBuffer(file);
    } else {
        reader.readAsText(file);
    }
}

/**
 * Handles multiple files sequentially
 * @param {FileList} files - The list of files to process
 * @returns {Promise<void>}
 */
async function handleFiles(files) {
    showLoading();
    
    // Process files sequentially
    for (const file of Array.from(files)) {
        await new Promise(resolve => {
            const reader = new FileReader();
            
            reader.onload = async function(e) {
                const content = e.target.result;
                const fileExt = file.name.split('.').pop().toLowerCase();
                const parser = FILE_HANDLERS[fileExt] || parseTextLog;
                
                try {
                    const logEntries = parser(content);
                    const analysis = analyzeLogs(logEntries);
                    updateUI(analysis);
                } catch (error) {
                    console.error(`Error processing ${file.name}:`, error);
                }
                resolve();
            };
            
            reader.onerror = () => {
                console.error(`Error reading ${file.name}`);
                resolve();
            };
            
            if (file.name.endsWith('.bin')) {
                reader.readAsArrayBuffer(file);
            } else {
                reader.readAsText(file);
            }
        });
    }
    
    hideLoading();
    setTimeout(scrollToResults, 100);
}

// Main analysis function
document.getElementById('analyzeBtn').addEventListener('click', () => {
    const fileInput = document.getElementById('logFile');
    if (!fileInput.files.length) {
        alert("Please upload a log file to analyze.");
        return;
    }
    Array.from(fileInput.files).forEach(analyzeFile);
});

/**
 * Parses CSV format logs
 * @param {string} content - The raw log content
 * @returns {Array<Object>} - Array of parsed log entries
 */
function parseCsvLog(content) {
    const lines = content.split('\n');
    const headers = lines[0].split(',');
    return lines.slice(1).map(line => {
        const values = line.split(',');
        const entry = {};
        headers.forEach((header, index) => {
            entry[header.trim()] = values[index]?.trim();
        });
        return entry;
    });
}

/**
 * Parses JSON format logs
 * @param {string} content - The raw log content
 * @returns {Array<Object>} - Array of parsed log entries
 */
function parseJsonLog(content) {
    try {
        const data = JSON.parse(content);
        return Array.isArray(data) ? data : [data];
    } catch (e) {
        console.error('Invalid JSON format:', e);
        return [];
    }
}

/**
 * Parses Windows Event (EVTX) logs
 * @param {string} content - The raw log content
 * @returns {Array<Object>} - Array of parsed log entries
 */
function parseEvtxLog(content) {
    // For EVTX files, we'll parse the text representation
    return content.split('\n').map(line => ({
        raw: line,
        timestamp: extractTimestamp(line),
        message: line
    }));
}

/**
 * Parses Syslog format logs
 * @param {string} content - The raw log content
 * @returns {Array<Object>} - Array of parsed log entries
 */
function parseSyslog(content) {
    return content.split('\n').map(line => {
        const match = line.match(/^<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+)/);
        if (match) {
            return {
                priority: match[1],
                timestamp: match[2],
                host: match[3],
                message: match[4]
            };
        }
        return { raw: line, message: line };
    });
}

/**
 * Parses binary log data
 * @param {ArrayBuffer} content - The raw binary content
 * @returns {Array<Object>} - Array of parsed log entries
 */
function parseBinaryLog(content) {
    // For binary logs, convert to hex and look for readable patterns
    const textDecoder = new TextDecoder('utf-8');
    try {
        return content.split('').map(char => char.charCodeAt(0).toString(16))
            .join('')
            .match(/.{1,32}/g)
            .map(line => ({
                raw: line,
                text: textDecoder.decode(new Uint8Array(line.match(/.{1,2}/g).map(byte => parseInt(byte, 16))))
            }));
    } catch (e) {
        console.error('Binary parsing error:', e);
        return [];
    }
}

/**
 * Parses plain text logs
 * @param {string} content - The raw log content
 * @returns {Array<Object>} - Array of parsed log entries
 */
function parseTextLog(content) {
    return content.split('\n').map(line => ({
        raw: line,
        timestamp: extractTimestamp(line),
        message: line
    }));
}

/**
 * Extracts timestamp from a log line
 * @param {string} line - The log line
 * @returns {string|null} - Extracted timestamp or null if not found
 */
function extractTimestamp(line) {
    const patterns = [
        /\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/,
        /\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}:\d{2}/,
        /\w+\s+\d+\s+\d{2}:\d{2}:\d{2}/
    ];

    for (const pattern of patterns) {
        const match = line.match(pattern);
        if (match) return match[0];
    }
    return null;
}

/**
 * Main log analysis function
 * @param {Array<Object>} logEntries - Array of parsed log entries
 * @returns {Object} - Analysis results
 */
function analyzeLogs(logEntries) {
    resetStats();
    
    const results = {
        events: [],
        recommendations: new Set(),
        timeline: new Map(),
        sources: new Map()
    };

    logEntries.forEach((entry, index) => {
        const message = entry.message || entry.raw;
        if (!message?.trim()) return;

        stats.totalEvents++;
        const analysis = analyzeLogLine(message, index + 1);
        
        // Update severity stats
        if (analysis.severity === 'critical') {
            stats.criticalEvents++;
        } else if (analysis.severity === 'high') {
            stats.warningEvents++;
        }

        if (analysis.attackType) {
            // Update attack type stats
            stats.attackTypes[analysis.attackType] = (stats.attackTypes[analysis.attackType] || 0) + 1;
            stats.severityLevels[analysis.severity]++;

            // Update timeline stats
            const timestamp = entry.timestamp || 'Unknown';
            const timeKey = timestamp.split(' ')[0];
            stats.timeline[timeKey] = (stats.timeline[timeKey] || 0) + 1;

            // Update source stats if available
            if (entry.host || entry.source) {
                const source = entry.host || entry.source;
                stats.sources[source] = (stats.sources[source] || 0) + 1;
            }

            results.events.push({
                line: message,
                lineNumber: index + 1,
                attackType: analysis.attackType,
                severity: analysis.severity,
                timestamp: timestamp
            });

            results.recommendations.add(getRecommendation(analysis.attackType));
        }
    });

    return results;
}

/**
 * Analyzes a single log line for security issues
 * @param {string} line - The log line to analyze
 * @param {number} lineNumber - The line number in the log file
 * @returns {Object} - Analysis result with attack type and severity
 */
function analyzeLogLine(line, lineNumber) {
    let result = {
        severity: 'low',
        attackType: null
    };

    for (const [attackType, config] of Object.entries(SECURITY_PATTERNS)) {
        for (const pattern of config.patterns) {
            if (pattern.test(line)) {
                result.attackType = attackType;
                result.severity = config.severity;
                break;
            }
        }
        if (result.attackType) break;
    }

    return result;
}

/**
 * Returns security recommendations based on attack type
 * @param {string} attackType - The type of attack detected
 * @returns {string} - Security recommendation
 */
function getRecommendation(attackType) {
    const recommendations = {
        bruteforce: "Implement account lockout policies and strong password requirements. Consider adding multi-factor authentication.",
        ddos: "Deploy DDoS protection services and configure rate limiting on your servers. Monitor traffic patterns for anomalies.",
        malware: "Keep antivirus software updated, implement application whitelisting, and regularly scan for malware.",
        injection: "Use parameterized queries, input validation, and escape special characters. Keep web application frameworks updated.",
        privEsc: "Regularly audit user permissions, implement principle of least privilege, and monitor privileged account usage.",
        dataLeak: "Implement data access controls, encrypt sensitive data, and monitor data access patterns.",
        reconnaissance: "Implement network monitoring and intrusion detection systems. Monitor for unusual network activity."
    };

    return recommendations[attackType] || "Monitor system logs regularly and keep all software updated.";
}

/**
 * Updates the UI with analysis results
 * @param {Object} analysis - The analysis results
 */
function updateUI(analysis) {
    const results = document.getElementById('results');
    const output = document.getElementById('output');
    const recommendationsList = document.getElementById('recommendationsList');
    
    results.classList.remove('hidden');
    
    // Update event list
    output.innerHTML = analysis.events.map(event => `
        <p class="event-item ${event.severity}">
            <strong>Line ${event.lineNumber}</strong> - 
            <span class="attack-type">${event.attackType.toUpperCase()}</span>
            <span class="severity-badge ${event.severity}">${event.severity}</span><br>
            <code>${event.line}</code>
        </p>
    `).join('');

    // Update recommendations
    recommendationsList.innerHTML = Array.from(analysis.recommendations)
        .map(rec => `<div class="recommendation-item"><i class="fas fa-shield-alt"></i> ${rec}</div>`)
        .join('');

    // Update statistics display
    document.getElementById('totalEvents').textContent = stats.totalEvents;
    document.getElementById('criticalEvents').textContent = stats.criticalEvents;
    document.getElementById('warningEvents').textContent = stats.warningEvents;

    // Update charts
    updateCharts();
}

/**
 * Returns theme-specific chart options
 * @returns {Object} - Chart.js options object
 */
function getChartThemeOptions() {
    const isDarkTheme = currentTheme === 'dark';
    
    return {
        plugins: {
            legend: {
                labels: {
                    color: isDarkTheme ? '#ffffff' : '#212121'
                }
            },
            title: {
                color: isDarkTheme ? '#ffffff' : '#212121'
            }
        },
        scales: {
            x: {
                ticks: { color: isDarkTheme ? '#e0e0e0' : '#424242' },
                grid: { color: isDarkTheme ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)' }
            },
            y: {
                ticks: { color: isDarkTheme ? '#e0e0e0' : '#424242' },
                grid: { color: isDarkTheme ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)' }
            }
        }
    };
}

/**
 * Returns theme-specific chart colors
 * @returns {Object} - Object containing color arrays for different chart types
 */
function getChartColors() {
    const isDarkTheme = currentTheme === 'dark';
    
    return {
        attackTypes: [
            '#5c6bc0', // Blue
            '#ff5252', // Red
            '#4caf50', // Green
            '#ffab00', // Amber
            '#9c27b0', // Purple
            '#00bcd4', // Cyan
            '#ff9800'  // Orange
        ],
        severityLevels: [
            '#ff5252', // Critical - Red
            '#ffab00', // High - Amber
            '#5c6bc0', // Medium - Blue
            '#4caf50'  // Low - Green
        ],
        timeline: isDarkTheme ? '#5c6bc0' : '#3f51b5',
        sources: [
            '#4caf50', // Green
            '#ff5252', // Red
            '#ffab00', // Amber
            '#5c6bc0', // Blue
            '#9c27b0'  // Purple
        ]
    };
}

/**
 * Updates all chart visualizations
 */
function updateCharts() {
    const attackCtx = document.getElementById('attackChart').getContext('2d');
    const severityCtx = document.getElementById('severityChart').getContext('2d');
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    const sourceCtx = document.getElementById('sourceChart').getContext('2d');
    
    const chartOptions = getChartThemeOptions();
    const chartColors = getChartColors();

    // Destroy existing charts
    [attackChart, severityChart, timelineChart, sourceChart].forEach(chart => {
        if (chart) chart.destroy();
    });

    // Attack types chart
    attackChart = new Chart(attackCtx, {
        type: 'bar',
        data: {
            labels: Object.keys(stats.attackTypes).map(type => type.toUpperCase()),
            datasets: [{
                label: 'Attack Types',
                data: Object.values(stats.attackTypes),
                backgroundColor: chartColors.attackTypes
            }]
        },
        options: {
            ...chartOptions,
            responsive: true,
            plugins: {
                ...chartOptions.plugins,
                title: {
                    display: true,
                    text: 'Attack Types Distribution',
                    color: chartOptions.plugins.title.color
                }
            }
        }
    });

    // Severity levels chart
    severityChart = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(stats.severityLevels).map(level => level.toUpperCase()),
            datasets: [{
                data: Object.values(stats.severityLevels),
                backgroundColor: chartColors.severityLevels
            }]
        },
        options: {
            ...chartOptions,
            responsive: true,
            plugins: {
                ...chartOptions.plugins,
                title: {
                    display: true,
                    text: 'Severity Levels Distribution',
                    color: chartOptions.plugins.title.color
                }
            }
        }
    });

    // Timeline chart
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: Object.keys(stats.timeline),
            datasets: [{
                label: 'Events Over Time',
                data: Object.values(stats.timeline),
                borderColor: chartColors.timeline,
                backgroundColor: currentTheme === 'dark' 
                    ? 'rgba(92, 107, 192, 0.2)' 
                    : 'rgba(63, 81, 181, 0.2)',
                tension: 0.1,
                fill: true
            }]
        },
        options: {
            ...chartOptions,
            responsive: true,
            plugins: {
                ...chartOptions.plugins,
                title: {
                    display: true,
                    text: 'Event Timeline',
                    color: chartOptions.plugins.title.color
                }
            }
        }
    });

    // Source distribution chart
    sourceChart = new Chart(sourceCtx, {
        type: 'pie',
        data: {
            labels: Object.keys(stats.sources),
            datasets: [{
                data: Object.values(stats.sources),
                backgroundColor: chartColors.sources
            }]
        },
        options: {
            ...chartOptions,
            responsive: true,
            plugins: {
                ...chartOptions.plugins,
                title: {
                    display: true,
                    text: 'Event Sources Distribution',
                    color: chartOptions.plugins.title.color
                }
            }
        }
    });
}

/**
 * Resets all statistics counters
 */
function resetStats() {
    stats = {
        totalEvents: 0,
        criticalEvents: 0,
        warningEvents: 0,
        attackTypes: {},
        severityLevels: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        },
        timeline: {},
        sources: {},
        destinations: {},
        protocols: {}
    };
}

// Filter functionality
document.getElementById('severityFilter').addEventListener('change', function(e) {
    filterResults('severity', e.target.value);
});

document.getElementById('attackTypeFilter').addEventListener('change', function(e) {
    filterResults('attack-type', e.target.value);
});

/**
 * Filters displayed events based on criteria
 * @param {string} filterType - The type of filter ('severity' or 'attack-type')
 * @param {string} value - The filter value
 */
function filterResults(filterType, value) {
    const events = document.querySelectorAll('.event-item');
    
    events.forEach(event => {
        if (value === 'all') {
            event.style.display = 'block';
        } else {
            const matchesFilter = filterType === 'severity' 
                ? event.querySelector(`.severity-badge`).textContent === value
                : event.querySelector(`.attack-type`).textContent.toLowerCase() === value.toUpperCase();
            
            event.style.display = matchesFilter ? 'block' : 'none';
        }
    });
}
