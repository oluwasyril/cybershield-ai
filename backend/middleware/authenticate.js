const { auth } = require('../services/firebase');

const authenticate = async (req, res, next) => {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'Unauthorised — no token.' });
  }
  try {
    const decoded = await auth.verifyIdToken(header.split('Bearer ')[1]);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ success: false, error: 'Unauthorised — invalid token.' });
  }
};

module.exports = { authenticate };