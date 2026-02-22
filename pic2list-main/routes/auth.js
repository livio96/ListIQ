const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('../db');
const router = express.Router();

const SALT_ROUNDS = 12;

// POST /api/auth/signup
router.post('/signup', async (req, res) => {
  const { first_name, last_name, company_name, username, password } = req.body;
  if (!first_name || !last_name || !username || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  try {
    const existing = await pool.query('SELECT id FROM users WHERE username = $1', [username.trim()]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Username already taken' });
    }
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await pool.query(
      `INSERT INTO users (first_name, last_name, company_name, username, password_hash)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, first_name, last_name, username`,
      [first_name.trim(), last_name.trim(), company_name?.trim() || null, username.trim(), hash]
    );
    req.session.userId = result.rows[0].id;
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }
  try {
    const result = await pool.query(
      'SELECT id, first_name, last_name, username, password_hash FROM users WHERE username = $1',
      [username.trim()]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    req.session.userId = user.id;
    res.json({ success: true, user: { id: user.id, first_name: user.first_name, last_name: user.last_name, username: user.username } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// GET /api/auth/me
router.get('/me', (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({ authenticated: true, userId: req.session.userId });
  }
  res.json({ authenticated: false });
});

module.exports = router;
