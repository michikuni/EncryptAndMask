document.getElementById('loginForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const response = await fetch('/api/user/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password })
    });

    const result = await response.json();
    const messageDiv = document.getElementById('message');

    if (result.success) {
        messageDiv.classList.remove('text-danger');
        messageDiv.classList.add('text-success');
        messageDiv.textContent = 'Đăng nhập thành công!';
        if (result.token) {
            localStorage.setItem('token', result.token);
        }
        setTimeout(() => window.location.href = '/home', 1000);
    } else {
        messageDiv.textContent = 'Đăng nhập thất bại: ' + (result.message || 'Kiểm tra thông tin đăng nhập');
    }
});