// Lấy token từ cookie
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

const token = getCookie('x-auth-token') || localStorage.getItem('token');
const citizenId = localStorage.getItem('citizenId');

if (!token || !citizenId) {
    window.location.href = '/signin';
}

// Load personal info
async function loadPersonalInfo() {
    try {
        const response = await fetch(`/api/user/getInfPersonal/${citizenId}`, {
            headers: { 'x-auth-token': token }
        });
        const data = await response.json();
        if (data.success && data.individual) {
            const info = data.individual;
            document.getElementById('userName').textContent = info.name || 'User';
            document.getElementById('userInfo').innerHTML = `
                <p><strong>Citizen ID:</strong> ${info.citizenIdentificationNumber}</p>
                <p><strong>Email:</strong> ${info.email}</p>
                <p><strong>Phone:</strong> ${info.phoneNumber}</p>
            `;
        }
    } catch (error) {
        console.error('Error loading personal info:', error);
    }
}

// Load all users
async function loadAllUsers() {
    try {
        const response = await fetch(`/api/user/getDataUsers/${citizenId}`, {
            headers: { 'x-auth-token': token }
        });
        const data = await response.json();
        if (data.success && data.listDataUser) {
            const userList = document.getElementById('userList');
            data.listDataUser.forEach(user => {
                userList.innerHTML += `
                    <div class="col-md-4 mb-3">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title">${user.name || 'Masked'}</h5>
                                <p class="card-text">ID: ${user.citizenIdentificationNumber}</p>
                                <p class="card-text">Email: ${user.email || 'Masked'}</p>
                            </div>
                        </div>
                    </div>
                `;
            });
        }
    } catch (error) {
        console.error('Error loading users:', error);
    }
}

// Logout
document.getElementById('logoutBtn').addEventListener('click', () => {
    localStorage.removeItem('token');
    localStorage.removeItem('citizenId');
    document.cookie = 'x-auth-token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'; // Xóa cookie
    window.location.href = '/signin';
});

// Load data on page load
loadPersonalInfo();
loadAllUsers();