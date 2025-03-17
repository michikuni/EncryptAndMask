document.addEventListener('DOMContentLoaded', async function() {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = '/login';
        return;
    }

    // Gọi API để lấy thông tin cá nhân (thay 'id' bằng ID thực tế nếu cần)
    const response = await fetch('/api/user/getInfPersonal/id', {
        headers: {
            'x-auth-token': token
        }
    });

    if (response.ok) {
        const user = await response.json();
        if (user.success) {
            document.getElementById('welcomeMessage').textContent = `Xin chào, ${user.username || 'Người dùng'}!`;
        }
    }
});

document.getElementById('logoutBtn').addEventListener('click', async function() {
    await fetch('/api/user/logout', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    });
    localStorage.removeItem('token');
    window.location.href = '/login';
});