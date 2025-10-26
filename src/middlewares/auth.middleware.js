const { verifyAccessToken } = require('../utils/jwt');
const User = require('../models/User');

module.exports = async function auth(req, res, next) {
  try {
    const h = req.headers.authorization;
    if (!h) return res.status(401).json({ error: 'Missing Authorization' });
    const parts = h.split(' ');
    if (parts.length !== 2) return res.status(401).json({ error: 'Invalid Authorization' });
    const token = parts[1];

    const payload = verifyAccessToken(token);
    // payload should contain { id, email, role, tokenVersion }
    const user = await User.findById(payload.id);
    if (!user) return res.status(401).json({ error: 'User not found' });

    // tokenVersion check (useful for invalidating issued tokens when password reset)
    if (payload.tokenVersion !== undefined && payload.tokenVersion !== user.tokenVersion) {
      return res.status(401).json({ error: 'Token revoked' });
    }

    req.user = { id: user._id.toString(), email: user.email, role: user.role };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};
