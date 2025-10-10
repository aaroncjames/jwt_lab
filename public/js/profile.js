document.addEventListener('DOMContentLoaded', async () => {
  const token = localStorage.getItem('token');
  const profileInfo = document.getElementById('profile-info');
  const alertMessage = document.getElementById('alert-message');

  if (!token) {
    alertMessage.innerHTML = '<div class="alert alert-danger">Please log in</div>';
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
      alertMessage.innerHTML = `<div class="alert alert-danger">${data.message || 'Failed to load profile'}</div>`;
    }
  } catch (error) {
    alertMessage.innerHTML = '<div class="alert alert-danger">Error connecting to server</div>';
  }
});

document.getElementById('logout').addEventListener('click', () => {
  localStorage.removeItem('token');
  window.location.href = '/login';
});