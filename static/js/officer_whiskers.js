// Create Officer Whiskers elements
function createOfficerWhiskers() {
    const container = document.createElement('div');
    container.className = 'officer-whiskers-container';
    
    const speechBubble = document.createElement('div');
    speechBubble.className = 'speech-bubble';
    speechBubble.innerHTML = '<p>Meow! I detected <span class="issue-count">0</span> security issues!</p>';
    
    const officerWhiskers = document.createElement('div');
    officerWhiskers.className = 'officer-whiskers';
    
    container.appendChild(speechBubble);
    container.appendChild(officerWhiskers);
    document.body.appendChild(container);
    
    return { container, speechBubble, officerWhiskers };
}

// Initialize Officer Whiskers
const elements = createOfficerWhiskers();

// Update security issues count
function updateSecurityIssues(count) {
    const issueCount = elements.speechBubble.querySelector('.issue-count');
    issueCount.textContent = count;
    
    elements.speechBubble.classList.add('show');
    elements.officerWhiskers.classList.add('alert');
    
    // Hide speech bubble after 5 seconds
    setTimeout(() => {
        elements.speechBubble.classList.remove('show');
        elements.officerWhiskers.classList.remove('alert');
    }, 5000);
}

// Show speech bubble on hover
elements.officerWhiskers.addEventListener('mouseenter', () => {
    elements.speechBubble.classList.add('show');
});

elements.officerWhiskers.addEventListener('mouseleave', () => {
    // Only hide if not showing alert
    if (!elements.officerWhiskers.classList.contains('alert')) {
        elements.speechBubble.classList.remove('show');
    }
});

// Listen for security issues updates
document.addEventListener('securityIssuesDetected', (event) => {
    updateSecurityIssues(event.detail.count);
}); 