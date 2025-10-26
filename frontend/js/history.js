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

// Load history
loadHistory();

document.getElementById('filterStatus').addEventListener('change', loadHistory);

async function loadHistory() {
    const filter = document.getElementById('filterStatus').value;
    const historyList = document.getElementById('historyList');
    historyList.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const response = await fetch(`${API_BASE_URL}/history?filter=${filter}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();

        if (response.ok && data.length > 0) {
            historyList.innerHTML = data.map(item => `
                <div class="history-item ${item.safe ? 'safe' : 'unsafe'}">
                    <h3>${item.url}</h3>
                    <div class="history-meta">
                        <span class="status-badge ${item.safe ? 'safe' : 'unsafe'}">
                            ${item.safe ? 'Safe' : 'Unsafe'}
                        </span>
                        <span>${new Date(item.scannedAt).toLocaleString()}</span>
                    </div>
                </div>
            `).join('');
        } else {
            historyList.innerHTML = '<div class="loading">No history found</div>';
        }
    } catch (error) {
        historyList.innerHTML = '<div class="loading">Error loading history</div>';
    }
}
