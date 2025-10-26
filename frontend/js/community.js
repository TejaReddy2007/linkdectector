const API_BASE_URL = 'http://localhost:8080/api';
const token = localStorage.getItem('token');
const username = localStorage.getItem('username');

if (!token) window.location.href = 'login.html';

document.getElementById('usernameDisplay').textContent = username;

document.getElementById('logoutBtn').addEventListener('click', (e) => {
    e.preventDefault();
    localStorage.clear();
    window.location.href = 'login.html';
});

// Load reports
loadReports();

// Submit report
document.getElementById('reportForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const url = document.getElementById('reportUrl').value;
    const status = document.getElementById('reportStatus').value;
    const comment = document.getElementById('reportComment').value;
    const messageDiv = document.getElementById('reportMessage');

    try {
        const response = await fetch(`${API_BASE_URL}/community/report`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ url, status, comment })
        });

        const data = await response.json();

        if (response.ok) {
            messageDiv.textContent = 'Report submitted successfully!';
            messageDiv.className = 'message success';
            document.getElementById('reportForm').reset();
            loadReports();
        } else {
            messageDiv.textContent = data.message || 'Failed to submit';
            messageDiv.className = 'message error';
        }
    } catch (error) {
        messageDiv.textContent = 'Connection error';
        messageDiv.className = 'message error';
    }
});

async function loadReports() {
    const reportsDiv = document.getElementById('communityReports');
    reportsDiv.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const response = await fetch(`${API_BASE_URL}/community/reports`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();

        if (response.ok && data.length > 0) {
            reportsDiv.innerHTML = data.map(report => `
                <div class="report-item">
                    <h3>${report.url}</h3>
                    <p>${report.comment || 'No comment'}</p>
                    <div class="report-meta">
                        <span class="status-badge ${report.status}">
                            ${report.status.toUpperCase()}
                        </span>
                        <span>By: ${report.username}</span>
                        <span>${new Date(report.createdAt).toLocaleString()}</span>
                    </div>
                </div>
            `).join('');
        } else {
            reportsDiv.innerHTML = '<div class="loading">No reports yet</div>';
        }
    } catch (error) {
        reportsDiv.innerHTML = '<div class="loading">Error loading reports</div>';
    }
}
