document.getElementById('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email');
  const password = document.getElementById('password');
  const alertMessage = document.getElementById('alert-message');
  const registerBtn = document.getElementById('register-btn');
  const registerText = document.getElementById('register-text');
  const registerSpinner = document.getElementById('register-spinner');

  // Reset styles and show spinner
  email.classList.remove('is-invalid');
  password.classList.remove('is-invalid');
  alertMessage.innerHTML = '';
  alertMessage.classList.remove('d-none'); // Ensure alert container is visible
  registerText.classList.add('d-none');
  registerSpinner.classList.remove('d-none');
  registerBtn.disabled = true;

  try {
    const response = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.value, password: password.value }),
    });
    const data = await response.json();

    if (response.ok) {
      alertMessage.innerHTML = '<div class="alert alert-success alert-dismissible fade show" role="alert">Registration successful! Redirecting to login...<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>';
      setTimeout(() => { window.location.href = '/login'; }, 1000);
    } else {
      email.classList.add('is-invalid');
      password.classList.add('is-invalid');
      alertMessage.innerHTML = `<div class="alert alert-danger alert-dismissible fade show" role="alert">${data.message || 'Registration failed'}<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>`;
    }
  } catch (error) {
    email.classList.add('is-invalid');
    password.classList.add('is-invalid');
    alertMessage.innerHTML = '<div class="alert alert-danger alert-dismissible fade show" role="alert">Error connecting to server<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>';
  } finally {
    registerText.classList.remove('d-none');
    registerSpinner.classList.add('d-none');
    registerBtn.disabled = false;
  }
});