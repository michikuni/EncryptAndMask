const token = localStorage.getItem('token') || sessionStorage.getItem('token');

// Kiểm tra token ngay lập tức
if (!token) {
    console.log('No token found, redirecting to signin');
    window.location.href = '/signin';
}

// Lấy ID từ token
function getIdFromToken() {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload).sub;
    } catch (e) {
        console.error('Error decoding token:', e);
        window.location.href = '/signin';
    }
}

async function loadData() {
    const id = getIdFromToken();
    if (!id) return;

    // Load personal info
    try {
        const personalResponse = await fetch(`/api/user/getInfPersonal/${id}`, {
            headers: { 'x-auth-token': token }
        });
        if (!personalResponse.ok) throw new Error('Failed to fetch personal info');
        const personalData = await personalResponse.json();
        const personalError = document.getElementById('personalError');
        personalError.style.display = 'none';
        if (personalData.success) {
            const info = personalData.individual;
            document.getElementById('personalInfo').innerHTML = `
                <p><strong>ID:</strong> ${info.citizenIdentificationNumber}</p>
                <p><strong>Name:</strong> ${info.name}</p>
                <p><strong>Email:</strong> ${info.email}</p>
                <p><strong>Phone:</strong> ${info.phoneNumber}</p>
                <p><strong>Address:</strong> ${info.address}</p>
                <p><strong>Birthday:</strong> ${info.birthday}</p>
                <p><strong>ATM:</strong> ${info.atm}</p>
            `;
            document.getElementById('updateUserId').value = info.citizenIdentificationNumber;
            document.getElementById('updateName').value = info.name;
            document.getElementById('updateEmail').value = info.email;
            document.getElementById('updatePhoneNumber').value = info.phoneNumber;
            document.getElementById('updateAddress').value = info.address;
            document.getElementById('updateBirthday').value = info.birthday;
            document.getElementById('updateAtm').value = info.atm;
        } else {
            personalError.textContent = 'Failed to load personal info: ' + personalData.mes;
            personalError.style.display = 'block';
        }
    } catch (error) {
        document.getElementById('personalError').textContent = 'Error: ' + error.message;
        document.getElementById('personalError').style.display = 'block';
    }

    // Load all users
    try {
        const allUsersResponse = await fetch(`/api/user/getDataUsers/${id}`, {
            headers: { 'x-auth-token': token }
        });
        if (!allUsersResponse.ok) throw new Error('Failed to fetch all users');
        const allUsersData = await allUsersResponse.json();
        const usersError = document.getElementById('usersError');
        usersError.style.display = 'none';
        if (allUsersData.success) {
            const users = allUsersData.listDataUser;
            const tbody = document.getElementById('userTable');
            tbody.innerHTML = '';
            users.forEach(user => {
                tbody.innerHTML += `
                    <tr>
                        <td>${user.citizenIdentificationNumber}</td>
                        <td>${user.name}</td>
                        <td>${user.email}</td>
                        <td>${user.phoneNumber}</td>
                        <td>${user.address}</td>
                        <td>${user.birthday}</td>
                        <td>${user.atm}</td>
                    </tr>
                `;
            });
        } else {
            usersError.textContent = 'Failed to load users: ' + allUsersData.mes;
            usersError.style.display = 'block';
        }
    } catch (error) {
        document.getElementById('usersError').textContent = 'Error: ' + error.message;
        document.getElementById('usersError').style.display = 'block';
    }

    // Load permissions
    await loadPermissions();
}

async function loadPermissions() {
    const id = getIdFromToken();
    try {
        const response = await fetch(`/api/user/getDecentralization/${id}`, {
            headers: { 'x-auth-token': token }
        });
        if (!response.ok) throw new Error('Failed to fetch permissions');
        const data = await response.json();
        const permissionsError = document.getElementById('permissionsError');
        permissionsError.style.display = 'none';
        if (data.success) {
            const permissions = data.listDataUserAuthorizations || [];
            const tbody = document.getElementById('permissionTable');
            tbody.innerHTML = '';
            permissions.forEach(perm => {
                tbody.innerHTML += `
                    <tr>
                        <td>${perm.id_main}</td>
                        <td>${perm.id_others}</td>
                        <td>${perm.columnName}</td>
                        <td>
                        <button class="btn btn-danger btn-sm" onclick="deletePermission('${perm.id_main}', '${perm.id_others}')">Delete</button>
                        <button class="btn btn-warning btn-sm me-2" onclick="showUpdatePermissionModal('${perm.id_main}', '${perm.id_others}', '${perm.columnName}')">Update</button>
                        </td>
                    </tr>
                `;
            });
        } else {
            permissionsError.textContent = 'Failed to load permissions: ' + data.mes;
            permissionsError.style.display = 'block';
        }
    } catch (error) {
        document.getElementById('permissionsError').textContent = 'Error: ' + error.message;
        document.getElementById('permissionsError').style.display = 'block';
    }
}

document.getElementById('addPermissionForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const idOthers = document.getElementById('idOthers').value;
    const columnName = document.getElementById('columnName').value;
    const permissionData = [{
        id_main: getIdFromToken(),
        id_others: idOthers,
        columnName: columnName
    }];

    try {
        const response = await fetch('/api/user/addDecentralization', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            },
            body: JSON.stringify(permissionData)
        });
        if (!response.ok) throw new Error('Failed to save permission');
        const data = await response.json();
        const formError = document.getElementById('formError');
        formError.style.display = 'none';
        if (data.success) {
            await loadPermissions();
            bootstrap.Modal.getInstance(document.getElementById('addPermissionModal')).hide();
            document.getElementById('addPermissionForm').reset();
        } else {
            formError.textContent = 'Failed to save: ' + data.mes;
            formError.style.display = 'block';
        }
    } catch (error) {
        document.getElementById('formError').textContent = 'Error: ' + error.message;
        document.getElementById('formError').style.display = 'block';
    }
});

document.getElementById('updateUserForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const userData = {
        citizenIdentificationNumber: document.getElementById('updateUserId').value,
        name: document.getElementById('updateName').value,
        email: document.getElementById('updateEmail').value,
        phoneNumber: document.getElementById('updatePhoneNumber').value,
        address: document.getElementById('updateAddress').value,
        birthday: document.getElementById('updateBirthday').value,
        atm: document.getElementById('updateAtm').value
    };

    try {
        const response = await fetch('/api/user/updateInfPersonal', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            },
            body: JSON.stringify(userData)
        });
        if (!response.ok) throw new Error('Failed to update user: ' + response.statusText);
        const data = await response.json();
        console.log('Update user response:', data);
        const formError = document.getElementById('updateUserError');
        formError.style.display = 'none';
        if (data.success) {
            await loadData(); // Reload thông tin người dùng
            const modalInstance = bootstrap.Modal.getInstance(document.getElementById('updateUserModal'));
            if (modalInstance) {
                modalInstance.hide();
            } else {
                console.error('Update user modal instance not found');
            }
        } else {
            formError.textContent = 'Failed to update: ' + data.mes;
            formError.style.display = 'block';
        }
    } catch (error) {
        console.error('Error updating user:', error);
        document.getElementById('updateUserError').textContent = 'Error: ' + error.message;
        document.getElementById('updateUserError').style.display = 'block';
    }
});

async function deletePermission(idMain, idOthers) {
    try {
        const response = await fetch('/api/user/deleteDecentralization', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            },
            body: JSON.stringify({ id_main: idMain, id_others: idOthers })
        });
        if (!response.ok) throw new Error('Failed to delete permission');
        const data = await response.json();
        if (data.success) {
            await loadPermissions();
            await loadData(); // Cập nhật lại danh sách người dùng để phản ánh thay đổi quyền
        } else {
            alert('Failed to delete permission: ' + data.mes);
        }
    } catch (error) {
        alert('Error deleting permission: ' + error.message);
    }
}

function showUpdatePermissionModal(idMain, idOthers, currentColumnName) {
    document.getElementById('updatePermissionLabel').innerText = `Update Permission for ${idMain} to ${idOthers}`;
    document.getElementById('updateIdMain').value = idMain;
    document.getElementById('updateIdOthers').value = idOthers;
    document.getElementById('updateIdOthersDisplay').value = idOthers; // Hiển thị ID Others
    document.getElementById('updatePermissionColumn').value = currentColumnName;
    const modal = new bootstrap.Modal(document.getElementById('updatePermissionModal'));
    modal.show();
}

document.getElementById('updatePermissionForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const idMain = document.getElementById('updateIdMain').value;
    const idOthers = document.getElementById('updateIdOthers').value;
    const columnName = document.getElementById('updatePermissionColumn').value;

    const updatePermissionData = {
        id_main: idMain,
        id_others: idOthers,
        dataChange: [{
            id_main: idMain,
            id_others: idOthers,
            columnName: columnName
        }]
    };

    try {
        const response = await fetch('/api/user/updateDecentralization', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            },
            body: JSON.stringify(updatePermissionData)
        });
        if (!response.ok) throw new Error('Failed to update permission');
        const data = await response.json();
        const formError = document.getElementById('updateFormError');
        formError.style.display = 'none';
        if (data.success) {
            await loadPermissions();
            await loadData();
            bootstrap.Modal.getInstance(document.getElementById('updatePermissionModal')).hide();
        } else {
            formError.textContent = 'Failed to update: ' + data.mes;
            formError.style.display = 'block';
        }
    } catch (error) {
        document.getElementById('updateFormError').textContent = 'Error: ' + error.message;
        document.getElementById('updateFormError').style.display = 'block';
    }
});


function logout() {
    localStorage.removeItem('token');
    sessionStorage.removeItem('token');
    window.location.href = '/signin';
}

// Khởi động
loadData();