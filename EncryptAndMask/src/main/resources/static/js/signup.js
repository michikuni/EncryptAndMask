document.getElementById('signupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const citizenId = document.getElementById('citizenId').value;
    const name = document.getElementById('name').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const Dob = document.getElementById('birthday').value;
    const email = document.getElementById('email').value;
    const phone = document.getElementById('phone').value;
    const address = document.getElementById('address').value;
    const atm = document.getElementById('atm').value;

    if (password !== confirmPassword) {
        document.getElementById('message').innerHTML = '<div class="alert alert-danger">Passwords do not match!</div>';
        return;
    }
    try {
        const response = await fetch('/api/user/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                citizenIdentificationNumber: citizenId,
                name: name,
                password: password,
                birthday: Dob,
                email: email,
                phoneNumber: phone,
                address: address,
                atm: atm
            })
        });
        const data = await response.json();

        const messageDiv = document.getElementById('message');
        if (data.success) {
            messageDiv.innerHTML = '<div class="alert alert-success">Registration successful!</div>';
            setTimeout(() => window.location.href = '/signin', 1000);
        } else {
            messageDiv.innerHTML = '<div class="alert alert-danger">' + data.mes + '</div>';
        }
    } catch (error) {
        document.getElementById('message').innerHTML = '<div class="alert alert-danger">Error: ' + error.message + '</div>';
    }
});