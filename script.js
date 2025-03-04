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
 * Enhanced security patterns with context and impact information
 * @type {Object.<string, {patterns: RegExp[], severity: string, context: string[], impact: string[], mitigations: string[]}>}
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
        severity: 'high',
        context: [
            'Authentication system',
            'User login endpoints',
            'Admin interfaces'
        ],
        impact: [
            'Unauthorized access',
            'Account compromise',
            'Service disruption'
        ],
        mitigations: [
            'Implement progressive delays between login attempts',
            'Use CAPTCHA after failed attempts',
            'Enable multi-factor authentication',
            'Monitor IP-based login patterns',
            'Set up account lockout policies'
        ]
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
        severity: 'critical',
        context: [
            'Network infrastructure',
            'Web services',
            'Application endpoints'
        ],
        impact: [
            'Service unavailability',
            'Resource exhaustion',
            'Financial losses',
            'Reputation damage'
        ],
        mitigations: [
            'Implement rate limiting',
            'Use CDN services',
            'Configure traffic filtering',
            'Deploy DDoS protection services',
            'Set up traffic monitoring and alerting'
        ]
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
        severity: 'critical',
        context: [
            'File systems',
            'Email attachments',
            'Download endpoints',
            'System processes'
        ],
        impact: [
            'Data encryption/loss',
            'System compromise',
            'Information theft',
            'Service disruption'
        ],
        mitigations: [
            'Keep antivirus software updated',
            'Implement application whitelisting',
            'Regular system scanning',
            'Email attachment filtering',
            'User security awareness training'
        ]
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
        severity: 'critical',
        context: [
            'Web applications',
            'Database queries',
            'User input handling',
            'Command execution'
        ],
        impact: [
            'Data breach',
            'Unauthorized data access',
            'System compromise',
            'Code execution'
        ],
        mitigations: [
            'Use parameterized queries',
            'Implement input validation',
            'Apply output encoding',
            'Regular security testing',
            'Web application firewall'
        ]
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
        severity: 'high',
        context: [
            'System permissions',
            'User privileges',
            'Administrative access',
            'Service accounts'
        ],
        impact: [
            'Unauthorized admin access',
            'System compromise',
            'Data breach',
            'Security bypass'
        ],
        mitigations: [
            'Implement principle of least privilege',
            'Regular permission audits',
            'Monitor privileged accounts',
            'Use role-based access control',
            'Security patch management'
        ]
    },
    dataLeak: {
        patterns: [
            /data breach/i,
            /information disclosure/i,
            /sensitive data exposure/i,
            /unauthorized data access/i,
            /data exfiltration/i
        ],
        severity: 'critical',
        context: [
            'Data storage',
            'Data transmission',
            'User information',
            'Sensitive records'
        ],
        impact: [
            'Privacy violation',
            'Financial loss',
            'Legal consequences',
            'Reputation damage'
        ],
        mitigations: [
            'Implement data encryption',
            'Access control policies',
            'Data classification',
            'Regular security audits',
            'Data loss prevention tools'
        ]
    },
    reconnaissance: {
        patterns: [
            /port scan/i,
            /network scan/i,
            /vulnerability scan/i,
            /probe attempt/i,
            /enumeration attempt/i
        ],
        severity: 'medium',
        context: [
            'Network perimeter',
            'Service discovery',
            'System enumeration'
        ],
        impact: [
            'Information disclosure',
            'Attack preparation',
            'Vulnerability mapping'
        ],
        mitigations: [
            'Configure firewall rules',
            'Implement IDS/IPS',
            'Regular vulnerability scanning',
            'Network segmentation',
            'Security monitoring'
        ]
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
 * Analyzes security patterns and generates AI-driven recommendations
 * @param {Object} analysis - The analysis results
 * @returns {Object} - Enhanced analysis with AI recommendations
 */
function generateAIRecommendations(analysis) {
    const attackPatterns = {};
    const recommendations = new Set();
    const criticalIssues = [];
    const timeBasedPatterns = new Map();

    // Analyze attack patterns and frequency
    analysis.events.forEach(event => {
        const attackType = event.attackType;
        attackPatterns[attackType] = (attackPatterns[attackType] || 0) + 1;

        // Track time-based patterns
        const eventTime = event.timestamp || 'Unknown';
        if (!timeBasedPatterns.has(attackType)) {
            timeBasedPatterns.set(attackType, new Map());
        }
        const typePatterns = timeBasedPatterns.get(attackType);
        typePatterns.set(eventTime, (typePatterns.get(eventTime) || 0) + 1);

        // Track critical issues
        if (event.severity === 'critical') {
            criticalIssues.push({
                type: attackType,
                timestamp: eventTime,
                context: SECURITY_PATTERNS[attackType].context
            });
        }
    });

    // Generate context-aware recommendations
    Object.entries(attackPatterns).forEach(([attackType, frequency]) => {
        const pattern = SECURITY_PATTERNS[attackType];
        const timePattern = timeBasedPatterns.get(attackType);
        
        // Analyze attack frequency and patterns
        const isHighFrequency = frequency > 5;
        const isRecent = Array.from(timePattern.keys()).some(time => 
            new Date(time) > new Date(Date.now() - 24 * 60 * 60 * 1000));
        
        // Generate prioritized recommendations
        const priority = pattern.severity === 'critical' ? 'Immediate' :
                        isHighFrequency ? 'High' :
                        isRecent ? 'Medium' : 'Low';

        // Add context-aware recommendations
        recommendations.add({
            type: attackType,
            priority: priority,
            frequency: frequency,
            context: pattern.context,
            impact: pattern.impact,
            mitigations: pattern.mitigations,
            description: generateSecurityAdvice(attackType, frequency, isRecent)
        });
    });

    return {
        ...analysis,
        aiRecommendations: Array.from(recommendations),
        riskAssessment: {
            criticalIssues: criticalIssues.length,
            uniqueAttackTypes: Object.keys(attackPatterns).length,
            highFrequencyAttacks: Object.entries(attackPatterns)
                .filter(([_, freq]) => freq > 5)
                .map(([type]) => type)
        }
    };
}

/**
 * Generates detailed security advice based on attack patterns
 * @param {string} attackType - The type of attack
 * @param {number} frequency - Attack frequency
 * @param {boolean} isRecent - Whether the attack is recent
 * @returns {string} - Detailed security advice
 */
function generateSecurityAdvice(attackType, frequency, isRecent) {
    const pattern = SECURITY_PATTERNS[attackType];
    const urgency = isRecent ? "immediate" : "planned";
    const impact = frequency > 5 ? "significant" : "moderate";

    return `${pattern.severity.toUpperCase()} PRIORITY: ${attackType} attacks detected with ${impact} impact. ` +
           `Requires ${urgency} attention. This affects ${pattern.context.join(", ")}. ` +
           `Potential impacts include ${pattern.impact.join(", ")}. ` +
           `Recommended actions:\n` +
           pattern.mitigations.map((m, i) => `${i + 1}. ${m}`).join("\n");
}

/**
 * Updates the UI with enhanced security analysis
 * @param {Object} analysis - The analysis results with AI recommendations
 */
function updateUI(analysis) {
    const results = document.getElementById('results');
    const output = document.getElementById('output');
    const recommendationsList = document.getElementById('recommendationsList');
    
        results.classList.remove('hidden');
    
    // Add AI-driven analysis
    const enhancedAnalysis = generateAIRecommendations(analysis);
    
    // Update event list with enhanced context
    output.innerHTML = enhancedAnalysis.events.map(event => `
        <p class="event-item ${event.severity}">
            <strong>Line ${event.lineNumber}</strong> - 
            <span class="attack-type">${event.attackType.toUpperCase()}</span>
            <span class="severity-badge ${event.severity}">${event.severity}</span>
            <span class="timestamp">${event.timestamp || 'Unknown'}</span><br>
            <code>${event.line}</code>
        </p>
    `).join('');

    // Update recommendations with AI-driven insights
    recommendationsList.innerHTML = enhancedAnalysis.aiRecommendations
        .sort((a, b) => getPriorityWeight(b.priority) - getPriorityWeight(a.priority))
        .map(rec => `
            <div class="recommendation-item ${rec.priority.toLowerCase()}">
                <div class="rec-header">
                    <i class="fas fa-shield-alt"></i>
                    <span class="priority-badge">${rec.priority}</span>
                    <strong>${rec.type.toUpperCase()}</strong>
                    <span class="frequency-badge">Frequency: ${rec.frequency}</span>
                </div>
                <div class="rec-content">
                    <p>${rec.description}</p>
                    <div class="impact-section">
                        <strong>Potential Impact:</strong>
                        <ul>${rec.impact.map(i => `<li>${i}</li>`).join('')}</ul>
                    </div>
                    <div class="mitigation-section">
                        <strong>Recommended Actions:</strong>
                        <ul>${rec.mitigations.map(m => `<li>${m}</li>`).join('')}</ul>
                    </div>
                </div>
            </div>
        `).join('');

    // Update statistics display
    document.getElementById('totalEvents').textContent = stats.totalEvents;
    document.getElementById('criticalEvents').textContent = stats.criticalEvents;
    document.getElementById('warningEvents').textContent = stats.warningEvents;

    // Update charts
    updateCharts();
}

/**
 * Gets the weight of a priority level for sorting
 * @param {string} priority - The priority level
 * @returns {number} - Priority weight
 */
function getPriorityWeight(priority) {
    const weights = {
        'Immediate': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1
    };
    return weights[priority] || 0;
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

// Add mascot interaction functions
function updateMascotMessage(message) {
    const speechBubble = document.querySelector('.mascot-speech-bubble');
    if (speechBubble) {
        speechBubble.textContent = message;
    }
}

function updateRecommendations(recommendations) {
    const recommendationsDiv = document.getElementById('recommendations');
    
    if (!recommendations || recommendations.length === 0) {
        recommendationsDiv.className = 'recommendations-empty';
        recommendationsDiv.innerHTML = 'No security concerns detected yet. Upload some logs and I\'ll analyze them for you! 🔍';
        updateMascotMessage('Officer Whiskers here! Everything looks good! Keep those logs coming! 😺');
        return;
    }

    recommendationsDiv.className = 'recommendations-list';
    recommendationsDiv.innerHTML = '';

    recommendations.forEach(rec => {
        const recElement = document.createElement('div');
        recElement.className = `recommendation-item ${rec.priority.toLowerCase()}`;
        recElement.innerHTML = `
            <div class="rec-header">
                <span class="rec-priority">${rec.priority}</span>
                <span class="rec-type">${rec.type}</span>
            </div>
            <div class="rec-content">
                <div class="impact-section">
                    <strong>Impact:</strong> ${rec.impact}
                </div>
                <div class="mitigation-section">
                    <strong>Mitigation:</strong> ${rec.mitigation}
                </div>
            </div>
        `;
        recommendationsDiv.appendChild(recElement);
    });

    // Update mascot message based on highest priority recommendation
    const highestPriority = recommendations.reduce((max, rec) => {
        const priorities = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
        return Math.max(max, priorities[rec.priority] || 0);
    }, 0);

    const mascotMessages = {
        4: 'Officer Whiskers here! Critical security issues detected! Let\'s address these right away! 🚨',
        3: 'Officer Whiskers reporting! Found some important security concerns. Time to take action! 🛡️',
        2: 'Officer Whiskers here! Some security improvements recommended. Better safe than sorry! 😺',
        1: 'Officer Whiskers reporting! Minor security suggestions available. Keep up the good work! 👍',
        0: 'Officer Whiskers here! Everything looks good! Keep those logs coming! 😺'
    };

    updateMascotMessage(mascotMessages[highestPriority]);
}

// Update the analyzeSecurityEvents function to handle empty results
async function analyzeSecurityEvents(events) {
    try {
        const openAIClient = new OpenAIClient(process.env.OPENAI_API_KEY);
        const result = await openAIClient.analyzeSecurityEvents(events);
        
        if (!result || !result.recommendations || result.recommendations.length === 0) {
            updateRecommendations([]);
            return;
        }

        updateRecommendations(result.recommendations);
    } catch (error) {
        console.error('Error analyzing security events:', error);
        updateMascotMessage('Officer Whiskers here! Oops! Had some trouble analyzing those logs. Try again? 😿');
        updateRecommendations([]);
    }
}

// Add mascot animation on file upload
function handleFiles(files) {
    if (files.length > 0) {
        updateMascotMessage('Officer Whiskers here! Analyzing your logs with my keen feline instincts! 🔍');
    }
    // ... rest of the existing handleFiles function
}
