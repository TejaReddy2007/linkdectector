const API_BASE_URL = 'http://localhost:8080/api';

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
        
        btn.classList.add('active');
        const tab = btn.dataset.tab;
        document.getElementById(`${tab}Form`).classList.add('active');
    });
});

// Login
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    const messageDiv = document.getElementById('loginMessage');

    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('username', data.username);
            messageDiv.textContent = 'Login successful!';
            messageDiv.className = 'message success';
            setTimeout(() => window.location.href = 'index.html', 1000);
        } else {
            messageDiv.textContent = data.message || 'Login failed';
            messageDiv.className = 'message error';
        }
    } catch (error) {
        messageDiv.textContent = 'Connection error';
        messageDiv.className = 'message error';
    }
});

// Signup
document.getElementById('signupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('signupUsername').value;
    const password = document.getElementById('signupPassword').value;
    const confirmPassword = document.getElementById('signupConfirmPassword').value;
    const messageDiv = document.getElementById('signupMessage');

    if (password !== confirmPassword) {
        messageDiv.textContent = 'Passwords do not match';
        messageDiv.className = 'message error';
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            messageDiv.textContent = 'Account created! Please login.';
            messageDiv.className = 'message success';
            setTimeout(() => {
                document.querySelector('[data-tab="login"]').click();
            }, 1500);
        } else {
            messageDiv.textContent = data.message || 'Signup failed';
            messageDiv.className = 'message error';
        }
    } catch (error) {
        messageDiv.textContent = 'Connection error';
        messageDiv.className = 'message error';
    }
});
