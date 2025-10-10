document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const errorMessage = document.getElementById('error-message');
  
    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await response.json();
  
      if (response.ok) {
        window.location.href = '/login';
      } else {
        errorMessage.textContent = data.message || 'Registration failed';
      }
    } catch (error) {
      errorMessage.textContent = 'Error connecting to server';
    }
  });