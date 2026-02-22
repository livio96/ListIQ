const express = require('express');
const pool = require('../db');
const { encrypt, decrypt } = require('../crypto-utils');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

// GET /api/config — returns masked key previews
router.get('/', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT ebay_token, ebay_client_id, ebay_client_secret FROM users WHERE id = $1',
      [req.session.userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const row = result.rows[0];

    const mask = (enc) => {
      if (!enc) return { set: false, preview: '' };
      const plain = decrypt(enc);
      if (!plain) return { set: false, preview: '' };
      return { set: true, preview: plain.substring(0, 6) + '...' + plain.slice(-4) };
    };

    res.json({
      ebay_token:         mask(row.ebay_token),
      ebay_client_id:     mask(row.ebay_client_id),
      ebay_client_secret: mask(row.ebay_client_secret),
    });
  } catch (err) {
    console.error('Get config error:', err);
    res.status(500).json({ error: 'Failed to load config' });
  }
});

// PUT /api/config — save API keys (encrypt secrets)
router.put('/', requireAuth, async (req, res) => {
  const { ebay_token, ebay_client_id, ebay_client_secret } = req.body;
  try {
    const updates = [];
    const values = [];
    let idx = 1;

    const fields = [
      ['ebay_token', ebay_token, true],
      ['ebay_client_id', ebay_client_id, true],
      ['ebay_client_secret', ebay_client_secret, true],
    ];

    for (const [col, val, shouldEncrypt] of fields) {
      if (val !== undefined) {
        updates.push(`${col} = $${idx}`);
        values.push(val ? (shouldEncrypt ? encrypt(val) : val) : null);
        idx++;
      }
    }

    if (updates.length === 0) {
      return res.json({ success: true, message: 'No changes' });
    }

    updates.push('updated_at = NOW()');
    values.push(req.session.userId);

    await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${idx}`,
      values
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Save config error:', err);
    res.status(500).json({ error: 'Failed to save config' });
  }
});

module.exports = router;
