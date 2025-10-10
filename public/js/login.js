document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email');
  const password = document.getElementById('password');
  const alertMessage = document.getElementById('alert-message');
  const loginBtn = document.getElementById('login-btn');
  const loginText = document.getElementById('login-text');
  const loginSpinner = document.getElementById('login-spinner');

  // Reset styles and show spinner
  email.classList.remove('is-invalid');
  password.classList.remove('is-invalid');
  alertMessage.innerHTML = '';
  alertMessage.classList.remove('d-none'); // Ensure alert container is visible
  loginText.classList.add('d-none');
  loginSpinner.classList.remove('d-none');
  loginBtn.disabled = true;

  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.value, password: password.value }),
    });
    const data = await response.json();

    if (response.ok) {
      localStorage.setItem('token', data.token);
      alertMessage.innerHTML = '<div class="alert alert-success alert-dismissible fade show" role="alert">Login successful! Redirecting...<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>';
      setTimeout(() => { window.location.href = '/profile'; }, 1000);
    } else {
      email.classList.add('is-invalid');
      password.classList.add('is-invalid');
      alertMessage.innerHTML = `<div class="alert alert-danger alert-dismissible fade show" role="alert">${data.message || 'Login failed'}<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>`;
    }
  } catch (error) {
    email.classList.add('is-invalid');
    password.classList.add('is-invalid');
    alertMessage.innerHTML = '<div class="alert alert-danger alert-dismissible fade show" role="alert">Error connecting to server<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>';
  } finally {
    loginText.classList.remove('d-none');
    loginSpinner.classList.add('d-none');
    loginBtn.disabled = false;
  }
});