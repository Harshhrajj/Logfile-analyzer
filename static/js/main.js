// Theme handling
const themeToggle = document.getElementById('themeToggle');
const body = document.body;
const icon = themeToggle.querySelector('i');

// Load saved theme
const savedTheme = localStorage.getItem('theme') || 'light';
body.classList.toggle('dark-theme', savedTheme === 'dark');
updateThemeIcon();

themeToggle.addEventListener('click', () => {
    body.classList.toggle('dark-theme');
    updateThemeIcon();
    localStorage.setItem('theme', body.classList.contains('dark-theme') ? 'dark' : 'light');
});

function updateThemeIcon() {
    const isDark = body.classList.contains('dark-theme');
    icon.className = isDark ? 'fas fa-sun' : 'fas fa-moon';
}

// Chart instances
let attackChart = null;
let ipChart = null;

// Initialize drag and drop
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const analyzeBtn = document.getElementById('analyzeBtn');
let selectedFile = null;

['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, preventDefaults, false);
});

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

function highlight(e) {
    dropZone.classList.add('dragover');
}

function unhighlight(e) {
    dropZone.classList.remove('dragover');
}

// Handle file selection
dropZone.addEventListener('drop', handleDrop, false);
dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', handleFiles, false);

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length) {
        selectedFile = files[0];
        dropZone.innerHTML = `<i class="fas fa-file-alt"></i><p>Selected: ${selectedFile.name}</p>`;
    }
}

function handleFiles(e) {
    const files = e.target.files;
    if (files.length) {
        selectedFile = files[0];
        dropZone.innerHTML = `<i class="fas fa-file-alt"></i><p>Selected: ${selectedFile.name}</p>`;
    }
}

// File upload and analysis
async function uploadFile(file) {
    if (!file) {
        alert('Please select a file first');
        return;
    }

    // Show loading spinner
    document.getElementById('loadingSpinner').classList.remove('d-none');
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayResults(data.results);
            // Reset file selection after successful analysis
            selectedFile = null;
            dropZone.innerHTML = `<i class="fas fa-cloud-upload-alt"></i><p>Drag and drop log files here or click to select</p>`;
        } else {
            alert(data.error || 'Error analyzing file');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error uploading file');
    } finally {
        document.getElementById('loadingSpinner').classList.add('d-none');
    }
}

// Add analyze button event listener
analyzeBtn.addEventListener('click', () => {
    uploadFile(selectedFile);
});

// Update Officer Whiskers
function updateOfficerWhiskers(issueCount) {
    const speechBubble = document.querySelector('.speech-bubble');
    const issueCountElement = document.getElementById('issueCount');
    
    issueCountElement.textContent = issueCount;
    speechBubble.classList.remove('d-none');
    
    // Add animation class
    speechBubble.classList.add('animate__animated', 'animate__bounceIn');
    
    // Remove animation class after animation ends
    setTimeout(() => {
        speechBubble.classList.remove('animate__animated', 'animate__bounceIn');
    }, 1000);
}

// Display analysis results
function displayResults(results) {
    // Show results section
    document.getElementById('resultsSection').classList.remove('d-none');
    
    // Update statistics
    document.getElementById('totalAttacks').textContent = results.stats.total_attacks;
    document.getElementById('sqlInjectionCount').textContent = results.stats.sql_injection_count;
    document.getElementById('xssCount').textContent = results.stats.xss_count;
    document.getElementById('uniqueIPs').textContent = results.stats.unique_ips;
    
    // Update charts
    updateCharts(results);
    
    // Update detailed results table
    updateDetailedResults(results);
}

// Update charts with new data
function updateCharts(results) {
    const attackCtx = document.getElementById('attackChart').getContext('2d');
    const ipCtx = document.getElementById('ipChart').getContext('2d');
    
    // Destroy existing charts
    if (attackChart) attackChart.destroy();
    if (ipChart) ipChart.destroy();
    
    // Attack distribution chart
    attackChart = new Chart(attackCtx, {
        type: 'bar',
        data: {
            labels: ['SQL Injection', 'XSS', 'DDoS', 'Brute Force'],
            datasets: [{
                label: 'Number of Attacks',
                data: [
                    results.stats.sql_injection_count,
                    results.stats.xss_count,
                    results.stats.ddos_count,
                    results.stats.brute_force_count
                ],
                backgroundColor: [
                    '#dc3545',
                    '#fd7e14',
                    '#6610f2',
                    '#0dcaf0'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Attack Type Distribution',
                    color: getComputedStyle(document.body).getPropertyValue('--text-primary')
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: getComputedStyle(document.body).getPropertyValue('--text-primary')
                    },
                    grid: {
                        color: getComputedStyle(document.body).getPropertyValue('--border-color')
                    }
                },
                y: {
                    ticks: {
                        color: getComputedStyle(document.body).getPropertyValue('--text-primary')
                    },
                    grid: {
                        color: getComputedStyle(document.body).getPropertyValue('--border-color')
                    }
                }
            }
        }
    });
    
    // IP frequency chart
    const ipData = Object.entries(results.ip_frequency)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
    
    ipChart = new Chart(ipCtx, {
        type: 'pie',
        data: {
            labels: ipData.map(([ip]) => ip),
            datasets: [{
                data: ipData.map(([_, count]) => count),
                backgroundColor: [
                    '#0d6efd',
                    '#6610f2',
                    '#6f42c1',
                    '#d63384',
                    '#dc3545',
                    '#fd7e14',
                    '#ffc107',
                    '#198754',
                    '#20c997',
                    '#0dcaf0'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: getComputedStyle(document.body).getPropertyValue('--text-primary')
                    }
                },
                title: {
                    display: true,
                    text: 'Top 10 IP Addresses by Activity',
                    color: getComputedStyle(document.body).getPropertyValue('--text-primary')
                }
            }
        }
    });
}

// Update detailed results table
function updateDetailedResults(results) {
    const tbody = document.getElementById('detailedResults');
    tbody.innerHTML = '';
    
    // Combine all attack types
    const attacks = [
        ...results.sql_injection.map(attack => ({ type: 'SQL Injection', ...attack })),
        ...results.xss.map(attack => ({ type: 'XSS', ...attack })),
        ...results.ddos.map(attack => ({ type: 'DDoS', ...attack })),
        ...results.brute_force.map(attack => ({ type: 'Brute Force', ...attack }))
    ];
    
    // Sort by line number
    attacks.sort((a, b) => a.line - b.line);
    
    attacks.forEach(attack => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>
                <span class="badge bg-${getBadgeClass(attack.type)}">${attack.type}</span>
            </td>
            <td>${attack.line}</td>
            <td>${attack.ip || '-'}</td>
            <td>${getAttackDetails(attack)}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Helper functions
function getBadgeClass(attackType) {
    const classes = {
        'SQL Injection': 'danger',
        'XSS': 'warning',
        'DDoS': 'primary',
        'Brute Force': 'info'
    };
    return classes[attackType] || 'secondary';
}

function getAttackDetails(attack) {
    if (attack.content) {
        return `<code>${escapeHtml(attack.content)}</code>`;
    } else if (attack.count) {
        return `${attack.count} requests`;
    } else if (attack.attempts) {
        return `${attack.attempts} failed attempts`;
    }
    return '-';
}

function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Download results
async function downloadResults(format) {
    try {
        const response = await fetch(`/download/${format}`);
        if (!response.ok) throw new Error('Download failed');
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `analysis_results.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (error) {
        console.error('Error:', error);
        alert('Error downloading results');
    }
} 