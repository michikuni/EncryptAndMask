document.getElementById('signinForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('id').value;
    const password = document.getElementById('password').value;
    const rememberMe = document.getElementById('rememberMe').checked;

    try{
        const response = await fetch('/api/user/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                citizenIdentificationNumber: id, 
                password: password })
        });
    
        const data = await response.json();
        if (data.success) {
            document.getElementById('message').innerHTML = '<div class="alert alert-success">Login successful!</div>';
            localStorage.setItem('token', data.token);
            localStorage.setItem('citizenId', id);
            document.cookie = `x-auth-token=${data.token}; path=/; max-age=1800`; // 1 year expiration for remember me
            setTimeout(() => {
                window.location.href = '/home';
            }, 1000);
        } else {
            document.getElementById('message').innerHTML = '<div class="alert alert-danger">' + data.mes + '</div>';
        }
    } catch (error) {
        document.getElementById('message').innerHTML = '<div class="alert alert-danger">Error: ' + error.message + '</div>';
    }
});