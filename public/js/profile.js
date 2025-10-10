document.addEventListener('DOMContentLoaded', async () => {
    const token = localStorage.getItem('token');
    const profileInfo = document.getElementById('profile-info');
    const errorMessage = document.getElementById('error-message');
  
    if (!token) {
      errorMessage.textContent = 'Please log in';
      return;
    }
  
    try {
      const response = await fetch('/api/user/profile', {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await response.json();
  
      if (response.ok) {
        profileInfo.innerHTML = `
          <p><strong>Message:</strong> ${data.message}</p>
          <p><strong>User ID:</strong> ${data.user.id}</p>
          <p><strong>Expiration:</strong> ${new Date(data.user.exp * 1000).toLocaleString()}</p>
        `;
      } else {
        errorMessage.textContent = data.message || 'Failed to load profile';
      }
    } catch (error) {
      errorMessage.textContent = 'Error connecting to server';
    }
  });
  
  document.getElementById('logout').addEventListener('click', () => {
    localStorage.removeItem('token');
    window.location.href = '/login';
  });