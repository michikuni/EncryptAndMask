document.getElementById('signinForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const citizenId = document.getElementById('citizenId').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('/api/user/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                citizenIdentificationNumber: citizenId,
                password: password
            })
        });
        const data = await response.json();

        const messageDiv = document.getElementById('message');
        if (data.success) {
            messageDiv.innerHTML = '<div class="alert alert-success">Login successful! Token: ' + data.token + '</div>';
            localStorage.setItem('token', data.token);
            localStorage.setItem('citizenId', citizenId);
            document.cookie = `x-auth-token=${data.token}; path=/; max-age=1800`;
            setTimeout(() => window.location.href = '/home', 1000);
        } else {
            messageDiv.innerHTML = '<div class="alert alert-danger">' + data.mes + '</div>';
        }
    } catch (error) {
        document.getElementById('message').innerHTML = '<div class="alert alert-danger">Error: ' + error.message + '</div>';
    }
});