document.getElementById('signupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = {
        citizenIdentificationNumber: document.getElementById('id').value,
        name: document.getElementById('name').value,
        password: document.getElementById('password').value,
        birthday: document.getElementById('birthday').value,
        email: document.getElementById('email').value,
        phoneNumber: document.getElementById('phone').value,
        address: document.getElementById('address').value,
        atm: document.getElementById('atm').value
    };

    const response = await fetch('/api/user/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
    });

    const data = await response.json();
    if (data.success) {
        alert('Registration successful! Please sign in.');
        window.location.href = '/signin';
    } else {
        alert('Registration failed: ' + data.mes);
    }
});