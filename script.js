document.getElementById('analyzeBtn').addEventListener('click', () => {
    const fileInput = document.getElementById('logFile');
    const output = document.getElementById('output');
    const results = document.getElementById('results');
    const chartCanvas = document.getElementById('attackChart').getContext('2d');

    // Reset previous results
    output.innerHTML = '';
    results.classList.add('hidden');

    if (!fileInput.files.length) {
        alert("Please upload a log file to analyze.");
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function (e) {
        const logContent = e.target.result;
        const analysis = analyzeLogs(logContent);

        if (analysis.totalLines === 0) {
            alert("The log file is empty or could not be processed.");
            return;
        }

        // Display detailed analysis
        results.classList.remove('hidden');
        output.innerHTML = analysis.details;

        // Render chart
        new Chart(chartCanvas, {
            type: 'bar',
            data: {
                labels: ['Brute Force', 'DDoS', 'Other'],
                datasets: [{
                    label: 'Attack Count',
                    data: analysis.counts,
                    backgroundColor: ['#007bff', '#dc3545', '#ffc107']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    };

    reader.readAsText(file);
});

function analyzeLogs(logData) {
    const lines = logData.split('\n');
    let bruteForceCount = 0;
    let ddosCount = 0;
    let otherCount = 0;
    let details = "";
    let totalLines = 0;

    lines.forEach((line, index) => {
        if (line.trim()) {
            totalLines++;
            if (line.toLowerCase().includes("brute force")) {
                bruteForceCount++;
                details += `<p>Line ${index + 1}: Brute Force attack detected. Log: ${line}</p>`;
            } else if (line.toLowerCase().includes("ddos")) {
                ddosCount++;
                details += `<p>Line ${index + 1}: DDoS attack detected. Log: ${line}</p>`;
            } else {
                otherCount++;
                details += `<p>Line ${index + 1}: Unrecognized activity. Log: ${line}</p>`;
            }
        }
    });

    return {
        details: details || "<p>No attacks detected in the log file.</p>",
        counts: [bruteForceCount, ddosCount, otherCount],
        totalLines: totalLines
    };
}
