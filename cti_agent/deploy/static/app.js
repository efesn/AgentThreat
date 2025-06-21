// Main JavaScript file for the AgentThreat dashboard

// DOM elements
const runAgentBtn = document.getElementById('runAgentBtn');
const clearLogsBtn = document.getElementById('clearLogsBtn');
const logBox = document.getElementById('logBox');
const threatTable = document.getElementById('threatTable');

// Log display function
function updateLogs() {
    fetch('/get-logs')
        .then(response => response.json())
        .then(logs => {
            if (logs.length === 0) {
                logBox.innerHTML = '<div class="log-entry">No logs available</div>';
                return;
            }
            
            logBox.innerHTML = '';
            logs.forEach(log => {
                const logEntry = document.createElement('div');
                logEntry.className = `log-entry log-${log.level.toLowerCase()}`;
                logEntry.innerHTML = `<span class="log-time">${log.timestamp}</span> <span class="log-level">[${log.level}]</span> ${log.message}`;
                logBox.appendChild(logEntry);
            });
            
            // Auto-scroll to bottom
            logBox.scrollTop = logBox.scrollHeight;
        })
        .catch(error => {
            console.error('Error fetching logs:', error);
            logBox.innerHTML = `<div class="log-entry log-error">Error fetching logs: ${error.message}</div>`;
        });
}

// Load threats from BigQuery
function loadThreats(useSimulation = false) {
    const endpoint = useSimulation ? '/simulate-bigquery' : '/get-threats';
    
    // Show loading state
    const tbody = threatTable.querySelector('tbody');
    tbody.innerHTML = '<tr><td colspan="7" class="loading-message">Loading threat data...</td></tr>';
    
    fetch(endpoint)
        .then(response => response.json())
        .then(data => {
            // Handle error response
            if (data.error) {
                tbody.innerHTML = `<tr><td colspan="7" class="error-message">Error: ${data.error}</td></tr>`;
                return;
            }
            
            // No data case
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="empty-message">No threat data available</td></tr>';
                return;
            }
            
            // Populate table with threat data
            tbody.innerHTML = '';
            data.forEach(row => {
                // Parse and format data
                let iocs = {};
                let mitreTechniques = [];
                
                try {
                    if (row.iocs) {
                        iocs = JSON.parse(row.iocs);
                    }
                    
                    if (row.mitre_techniques) {
                        mitreTechniques = JSON.parse(row.mitre_techniques);
                    }
                } catch (e) {
                    console.error('Error parsing JSON:', e);
                }
                
                // Format the date
                const publishedDate = row.published ? new Date(row.published).toLocaleString() : 'N/A';
                
                // Create the table row
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>
                        <a href="${row.link}" target="_blank" title="${row.title}">${truncateText(row.title, 50)}</a>
                    </td>
                    <td>${publishedDate}</td>
                    <td>${row.threat_category || 'Unknown'}</td>
                    <td>${row.threat_actor || 'Unknown'}</td>
                    <td>${formatIOCs(iocs)}</td>
                    <td>${truncateText(row.summary, 100)}</td>
                    <td>${formatMitreTechniques(mitreTechniques)}</td>
                `;
                tbody.appendChild(tr);
            });
        })
        .catch(error => {
            console.error('Error loading threats:', error);
            tbody.innerHTML = `<tr><td colspan="7" class="error-message">Error loading threat data: ${error.message}</td></tr>`;
        });
}

// Helper function to truncate text
function truncateText(text, maxLength) {
    if (!text) return '';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}

// Format IOCs for display
function formatIOCs(iocs) {
    if (Object.keys(iocs).length === 0) return 'None';
    
    let iocHtml = '<div class="ioc-container">';
    
    // Show limited number of IOCs with counts
    let totalCount = 0;
    
    for (const [type, values] of Object.entries(iocs)) {
        if (values && values.length > 0) {
            totalCount += values.length;
            if (iocHtml.length < 150) {
                iocHtml += `<div class="ioc-item">${type}: ${values[0]}</div>`;
            }
        }
    }
    
    if (totalCount > 1) {
        iocHtml += `<div class="ioc-count">+${totalCount - 1} more</div>`;
    }
    
    iocHtml += '</div>';
    return iocHtml;
}

// Format MITRE ATT&CK techniques for display
function formatMitreTechniques(techniques) {
    if (!techniques || techniques.length === 0) return 'None';
    
    return techniques.slice(0, 3).map(t => {
        return `<span class="mitre-technique">${t}</span>`;
    }).join(' ') + (techniques.length > 3 ? ` +${techniques.length - 3} more` : '');
}

// Run the agent workflow
function runAgent() {
    // Update UI
    runAgentBtn.disabled = true;
    runAgentBtn.textContent = '⏳ Running...';
    
    // Start periodic log updates
    const logInterval = setInterval(updateLogs, 1000);
    
    // Send request to run agent
    fetch('/run-agent', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            clearInterval(logInterval); // Stop automatic log updates
            updateLogs(); // One final log update
            
            // Reset button
            runAgentBtn.disabled = false;
            runAgentBtn.textContent = '▶️ Run Threat Analysis Workflow';
            
            // Refresh the threat table
            loadThreats();
        })
        .catch(error => {
            console.error('Error running agent:', error);
            clearInterval(logInterval);
            updateLogs();
            
            // Reset button
            runAgentBtn.disabled = false;
            runAgentBtn.textContent = '▶️ Run Threat Analysis Workflow';
        });
}

// Clear logs
function clearLogs() {
    fetch('/clear-logs', { method: 'POST' })
        .then(() => {
            updateLogs();
        })
        .catch(error => {
            console.error('Error clearing logs:', error);
        });
}

// Initialize the dashboard
function initDashboard() {
    // Load initial logs
    updateLogs();
    
    // Set up event listeners
    runAgentBtn.addEventListener('click', runAgent);
    clearLogsBtn.addEventListener('click', clearLogs);
    
    // Set up periodic log refreshes
    setInterval(updateLogs, 5000);
}

// Start the dashboard when the page loads
document.addEventListener('DOMContentLoaded', initDashboard);