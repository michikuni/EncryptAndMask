document.getElementById('registerForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    const messageDiv = document.getElementById('message');

    if (password !== confirmPassword) {
        messageDiv.textContent = 'Mật khẩu không khớp!';
        return;
    }

    const response = await fetch('/api/user/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, email, password })
    });

    const result = await response.json();

    if (result.success) {
        messageDiv.classList.remove('text-danger');
        messageDiv.classList.add('text-success');
        messageDiv.textContent = 'Đăng ký thành công!';
        setTimeout(() => window.location.href = '/login', 2000);
    } else {
        messageDiv.textContent = 'Đăng ký thất bại: ' + (result.message || 'Kiểm tra thông tin');
    }
});