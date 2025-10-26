const API_BASE_URL = 'http://localhost:8080/api';

// Check authentication
const token = localStorage.getItem('token');
const username = localStorage.getItem('username');

if (!token) {
    window.location.href = 'login.html';
}

document.getElementById('usernameDisplay').textContent = username;

// Logout
document.getElementById('logoutBtn').addEventListener('click', (e) => {
    e.preventDefault();
    localStorage.clear();
    window.location.href = 'login.html';
});

// Scan form
document.getElementById('scanForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const url = document.getElementById('urlInput').value;
    const resultsDiv = document.getElementById('scanResults');
    const btnText = document.querySelector('.btn-text');
    const btnLoader = document.querySelector('.btn-loader');

    btnText.style.display = 'none';
    btnLoader.style.display = 'inline';

    try {
        const response = await fetch(`${API_BASE_URL}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (response.ok) {
            displayResults(data);
            resultsDiv.style.display = 'block';
        } else {
            alert('Scan failed: ' + (data.message || 'Unknown error'));
        }
    } catch (error) {
        alert('Connection error');
    } finally {
        btnText.style.display = 'inline';
        btnLoader.style.display = 'none';
    }
});

function displayResults(data) {
    const overallResult = document.querySelector('.overall-result');
    const overallStatus = document.getElementById('overallStatus');
    const overallMessage = document.getElementById('overallMessage');
    
    if (data.safe) {
        overallResult.className = 'result-card overall-result safe';
        overallStatus.textContent = '✅ Link is Safe';
        overallMessage.textContent = 'No threats detected';
    } else {
        overallResult.className = 'result-card overall-result unsafe';
        overallStatus.textContent = '⚠️ Link is Unsafe';
        overallMessage.textContent = 'Potential threats detected';
    }

    document.getElementById('vtResult').innerHTML = formatResult(data.virusTotalResult);
    document.getElementById('gsbResult').innerHTML = formatResult(data.googleSafeBrowsingResult);
    document.getElementById('heuristicResult').innerHTML = formatResult(data.heuristicResult);
}

function formatResult(result) {
    if (!result) return '<p>No data</p>';
    return `<p>${result}</p>`;
}
