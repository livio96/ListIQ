const pool = require('../db');
const { decrypt } = require('../crypto-utils');

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  return res.redirect('/login.html');
}

async function loadUserConfig(req, res, next) {
  if (!req.session || !req.session.userId) return next();
  try {
    const result = await pool.query(
      'SELECT ebay_token, ebay_client_id, ebay_client_secret FROM users WHERE id = $1',
      [req.session.userId]
    );
    if (result.rows.length === 0) {
      req.session.destroy();
      return res.status(401).json({ error: 'User not found' });
    }
    const row = result.rows[0];
    req.userConfig = {
      ebayToken:        decrypt(row.ebay_token) || '',
      ebayClientId:     decrypt(row.ebay_client_id) || '',
      ebayClientSecret: decrypt(row.ebay_client_secret) || '',
    };
    next();
  } catch (err) {
    console.error('loadUserConfig error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
}

module.exports = { requireAuth, loadUserConfig };
