exports.getProfile = (req, res) => {
  res.json({
    message: 'Protected profile page',
    user: req.user,
  });
};
