const DEBUG_JWT = process.env.DEBUG_JWT === 'true';
function debug(...args) {
  if (DEBUG_JWT) console.log('[JWT DEBUG]', ...args);
}

exports.getProfile = async (req, res) => {
  debug('FULL req.user object:', req.user);
  debug('req.user keys:', Object.keys(req.user));
  debug('req.user.email:', req.user.email); 
  debug('getProfile – req.user:', req.user);

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