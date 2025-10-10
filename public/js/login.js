document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const errorMessage = document.getElementById('error-message');
  
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await response.json();
  
      if (response.ok) {
        localStorage.setItem('token', data.token);
        window.location.href = '/profile';
      } else {
        errorMessage.textContent = data.message || 'Login failed';
      }
    } catch (error) {
      errorMessage.textContent = 'Error connecting to server';
    }
  });