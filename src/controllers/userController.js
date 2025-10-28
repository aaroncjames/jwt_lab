

exports.getProfile = async (req, res) => {
  console.log('FULL req.user object:', req.user);
  console.log('req.user keys:', Object.keys(req.user));
  console.log('req.user.email:', req.user.email); 
  console.log('getProfile – req.user:', req.user);

  const { id, email, exp, iat } = req.user;

  if (!email) {
    return res.status(400).json({ message: 'Email missing in token' });
  }

  res.json({
    message: 'Protected profile page',
    user: {
      id,
      email,
      exp,
      expiresAt: new Date(exp * 1000).toISOString(),
      issuedAt: iat ? new Date(iat * 1000).toISOString() : null,
    },
  });
};