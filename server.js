'use strict';
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// Load a local .env file when running on your own computer. Real environment variables (e.g. on Render) always win.
(function loadEnv() {
  try {
    const txt = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
    for (const line of txt.split(/\r?\n/)) {
      if (line.trim().startsWith('#')) continue;
      const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/);
      if (!m) continue;
      let v = m[2];
      if (/^(["']).*\1$/.test(v)) v = v.slice(1, -1);
      if (process.env[m[1]] === undefined) process.env[m[1]] = v;
    }
  } catch (e) { /* no .env file: fine */ }
})();

const PROD = process.env.NODE_ENV === 'production';

const normEmail = (v) => String(v || '').trim().toLowerCase();
const emailOk = (v) => v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v);

/* ---------- small in-memory rate limiter (per IP) ---------- */
function limiter(max, ms) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now();
    if (hits.size > 5000) hits.clear();
    const arr = (hits.get(req.ip) || []).filter((t) => now - t < ms);
    if (arr.length >= max) return res.status(429).json({ error: 'Too many attempts. Please wait a few minutes and try again.' });
    arr.push(now);
    hits.set(req.ip, arr);
    next();
  };
}

async function init(pool) {
  await pool.query(`CREATE TABLE IF NOT EXISTS pg_owner_data (
    owner_id text PRIMARY KEY,
    data jsonb NOT NULL,
    version integer NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now()
  )`);
  // Password set through "Forgot password" (stored hashed) and one-time reset tokens (stored hashed).
  await pool.query(`CREATE TABLE IF NOT EXISTS owner_auth (
    owner_id text PRIMARY KEY,
    salt text NOT NULL,
    hash text NOT NULL,
    env_fp text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS pw_resets (
    token_hash text PRIMARY KEY,
    expires_at timestamptz NOT NULL
  )`);
  // One private pay link per tenant (unguessable token) + the tenant's latest answer for the current month.
  await pool.query(`CREATE TABLE IF NOT EXISTS pay_links (
    token text PRIMARY KEY,
    tenant_id text NOT NULL UNIQUE,
    snapshot jsonb NOT NULL,
    cycle text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS pay_responses (
    token text PRIMARY KEY,
    kind text NOT NULL,
    promise_date text,
    created_at timestamptz NOT NULL DEFAULT now()
  )`);
}

const isoDate = (v) => /^\d{4}-\d{2}-\d{2}$/.test(v) && !isNaN(new Date(v + 'T00:00:00Z')) && new Date(v + 'T00:00:00Z').toISOString().slice(0, 10) === v;
const TOKEN = /^[A-Za-z0-9_-]{20,64}$/;

function createApp(pool, cfg) {
  // The owner's login comes from OWNER_EMAIL / OWNER_PASSWORD. A password set with "Forgot password" is stored
  // (hashed) in the database and takes over, unless OWNER_PASSWORD is changed afterwards (the newest change wins).
  const envSalt = crypto.randomBytes(16);
  const envHash = crypto.scryptSync(String(cfg.password), envSalt, 64);
  const envFp = crypto.scryptSync(String(cfg.password), 'pg-env-fingerprint', 16).toString('hex');
  const hmac = (v) => crypto.createHmac('sha256', cfg.secret).update(v).digest('hex').slice(0, 16);
  const sha = (v) => crypto.createHash('sha256').update(v).digest('hex');
  let authCache = null;
  let fails = []; // timestamps of recent failed logins (any IP)
  let resetSends = []; // timestamps of reset emails, so nobody can flood the owner's inbox

  async function getAuthState() {
    if (authCache) return authCache;
    const r = await pool.query('SELECT salt, hash, env_fp FROM owner_auth WHERE owner_id = $1', [cfg.owner]);
    if (r.rowCount && r.rows[0].env_fp === envFp) {
      authCache = { salt: Buffer.from(r.rows[0].salt, 'hex'), hash: Buffer.from(r.rows[0].hash, 'hex'), pv: hmac('db:' + r.rows[0].hash) };
    } else {
      authCache = { salt: envSalt, hash: envHash, pv: hmac('env:' + cfg.password) }; // pv changes with the password, logging out old sessions
    }
    return authCache;
  }
  const checkPw = (pw, a) => crypto.timingSafeEqual(crypto.scryptSync(String(pw), a.salt, 64), a.hash);

  async function sendMail(to, subject, text, html) {
    if (!cfg.resendKey) { console.log(`[no email provider] ${subject}\n${text}`); return; }
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + cfg.resendKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: cfg.mailFrom || 'PG Manager <onboarding@resend.dev>', to: [to], subject, text, html }),
    });
    if (!r.ok) console.error('Email send failed:', r.status, await r.text().catch(() => ''));
  }

  const app = express();
  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'same-origin',
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
    });
    next();
  });
  app.use(express.json({ limit: '2mb' }));
  app.use(cookieParser());

  const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);
  const auth = async (req, res, next) => {
    let payload = null;
    try { payload = jwt.verify(req.cookies.pg_session || '', cfg.secret, { algorithms: ['HS256'] }); } catch (e) { payload = null; }
    if (!payload) return res.status(401).json({ error: 'Not logged in' });
    let a;
    try { a = await getAuthState(); } catch (e) { return next(e); }
    if (payload.sub !== cfg.owner || payload.pv !== a.pv) return res.status(401).json({ error: 'Not logged in' });
    req.email = cfg.owner;
    next();
  };

  app.get('/healthz', (req, res) => res.send('ok'));

  /* ----- owner login: email + password ----- */
  app.post('/api/auth/login', limiter(10, 15 * 60e3), wrap(async (req, res) => {
    const email = normEmail(req.body && req.body.email);
    const pw = String((req.body && req.body.password) || '');
    if (!emailOk(email)) return res.status(400).json({ error: 'Wrong email: enter a valid address like name@example.com.' });
    if (!pw) return res.status(400).json({ error: 'Please enter your password.' });

    const now = Date.now();
    fails = fails.filter((t) => now - t < 15 * 60e3);
    if (fails.length >= 20) return res.status(429).json({ error: 'Too many failed logins. Please wait 15 minutes and try again.' });

    const a = await getAuthState();
    const pwOk = checkPw(pw, a); // always computed, so timing does not reveal the email
    if (email !== cfg.owner || !pwOk) {
      fails.push(now);
      return res.status(401).json({ error: 'Wrong email or password.' });
    }
    fails = [];
    const token = jwt.sign({ sub: email, pv: a.pv }, cfg.secret, { algorithm: 'HS256', expiresIn: '30d' });
    res.cookie('pg_session', token, { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: 30 * 864e5 });
    res.json({ ok: true, email });
  }));

  /* ----- forgot / reset password (link sent to the owner's email) ----- */
  app.post('/api/auth/forgot', limiter(5, 15 * 60e3), wrap(async (req, res) => {
    const email = normEmail(req.body && req.body.email);
    if (!emailOk(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    const base = (cfg.publicUrl || (PROD ? '' : `${req.protocol}://${req.get('host')}`)).replace(/\/+$/, '');
    res.json({ ok: true }); // identical answer whether or not this is the owner's email
    if (email !== cfg.owner) return;
    (async () => {
      const now = Date.now();
      resetSends = resetSends.filter((t) => now - t < 36e5);
      if (resetSends.length >= 3) return;
      resetSends.push(now);
      const token = crypto.randomBytes(32).toString('base64url');
      await pool.query('DELETE FROM pw_resets'); // only the newest link works
      await pool.query('INSERT INTO pw_resets (token_hash, expires_at) VALUES ($1, $2)', [sha(token), new Date(now + 30 * 60e3)]);
      if (cfg.resendKey && !base) { console.error('Cannot email a reset link: set PUBLIC_URL to your site address.'); return; }
      const link = `${base}/reset#token=${token}`;
      await sendMail(cfg.owner, 'Reset your PG Manager password',
        `Open this link to choose a new password (valid for 30 minutes):\n\n${link}\n\nIf you did not ask for this, ignore this email.`,
        `<p>Open this link to choose a new password (valid for 30 minutes):</p><p><a href="${link}">Reset my password</a></p><p>If you did not ask for this, ignore this email.</p>`);
    })().catch((e) => console.error('Password reset failed:', e.message));
  }));

  app.post('/api/auth/reset', limiter(10, 15 * 60e3), wrap(async (req, res) => {
    const token = String((req.body && req.body.token) || '');
    const pw = String((req.body && req.body.password) || '');
    if (pw.length < 8 || pw.length > 200) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    const r = token.length >= 20 && token.length <= 100 ? await pool.query('SELECT expires_at FROM pw_resets WHERE token_hash = $1', [sha(token)]) : { rowCount: 0 };
    if (!r.rowCount || new Date(r.rows[0].expires_at).getTime() < Date.now()) {
      return res.status(400).json({ error: 'This reset link is invalid or has expired. Please request a new one.' });
    }
    const salt = crypto.randomBytes(16);
    const hash = crypto.scryptSync(pw, salt, 64);
    await pool.query('DELETE FROM owner_auth WHERE owner_id = $1', [cfg.owner]);
    await pool.query('INSERT INTO owner_auth (owner_id, salt, hash, env_fp) VALUES ($1, $2, $3, $4)', [cfg.owner, salt.toString('hex'), hash.toString('hex'), envFp]);
    await pool.query('DELETE FROM pw_resets'); // single use
    authCache = null; // new password -> new session fingerprint -> every old session is logged out
    fails = [];
    res.clearCookie('pg_session');
    res.json({ ok: true });
  }));

  app.get('/reset', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.sendFile(path.join(__dirname, 'public', 'reset.html'));
  });

  app.get('/api/me', auth, (req, res) => res.json({ email: req.email }));
  app.post('/api/logout', (req, res) => { res.clearCookie('pg_session'); res.json({ ok: true }); });

  /* ----- tenant data (one JSON document, with a version number to avoid overwriting newer data) ----- */
  app.get('/api/data', auth, wrap(async (req, res) => {
    const r = await pool.query('SELECT data, version FROM pg_owner_data WHERE owner_id = $1', [req.email]);
    if (!r.rowCount) return res.json({ rooms: [], past: [], upi: null, version: 0 });
    res.json({ ...r.rows[0].data, version: r.rows[0].version });
  }));

  app.put('/api/data', auth, wrap(async (req, res) => {
    const b = req.body || {};
    if (!Array.isArray(b.rooms) || !Array.isArray(b.past || [])) return res.status(400).json({ error: 'Invalid data' });
    const base = b.version;
    if (!Number.isInteger(base) || base < 0) return res.status(400).json({ error: 'Missing version' });
    const st = b.settings || {};
    const settings = {
      first: Number.isInteger(st.first) && st.first >= -30 && st.first <= 30 ? st.first : 7,
      repeat: Number.isInteger(st.repeat) && st.repeat >= 1 && st.repeat <= 30 ? st.repeat : 3,
    };
    const data = JSON.stringify({ rooms: b.rooms, past: b.past || [], upi: typeof b.upi === 'string' ? b.upi.slice(0, 100) : null, settings });
    let r;
    if (base === 0) {
      r = await pool.query('INSERT INTO pg_owner_data (owner_id, data) VALUES ($1, $2::jsonb) ON CONFLICT DO NOTHING RETURNING version', [req.email, data]);
    } else {
      r = await pool.query('UPDATE pg_owner_data SET data = $2::jsonb, version = version + 1, updated_at = now() WHERE owner_id = $1 AND version = $3 RETURNING version', [req.email, data, base]);
    }
    if (!r.rowCount) return res.status(409).json({ error: 'Data was changed on another device.' });
    res.json({ ok: true, version: r.rows[0].version });
  }));

  /* ----- tenant pay links (owner side) ----- */
  app.post('/api/links', auth, wrap(async (req, res) => {
    const items = Array.isArray(req.body && req.body.items) ? req.body.items.slice(0, 300) : null;
    if (!items) return res.status(400).json({ error: 'Invalid data' });
    const tokens = {};
    for (const it of items) {
      const tid = String((it && it.tenantId) || '').slice(0, 64);
      if (!tid) continue;
      const cycle = /^\d{4}-\d{2}$/.test(it.cycle) ? it.cycle : '';
      if (!cycle) continue;
      const snap = JSON.stringify({
        name: String(it.name || '').slice(0, 80),
        room: String(it.room || '').slice(0, 30),
        rent: Math.max(0, Number(it.rent) || 0),
        dueDate: isoDate(String(it.dueDate || '')) ? it.dueDate : null,
        upi: String(it.upi || '').slice(0, 100),
      });
      const ex = await pool.query('SELECT token, cycle FROM pay_links WHERE tenant_id = $1', [tid]);
      if (ex.rowCount) {
        const tk = ex.rows[0].token;
        if (ex.rows[0].cycle !== cycle) await pool.query('DELETE FROM pay_responses WHERE token = $1', [tk]); // new month: old answer no longer applies
        await pool.query('UPDATE pay_links SET snapshot = $2::jsonb, cycle = $3, updated_at = now() WHERE token = $1', [tk, snap, cycle]);
        tokens[tid] = tk;
      } else {
        const tk = crypto.randomBytes(18).toString('base64url');
        await pool.query('INSERT INTO pay_links (token, tenant_id, snapshot, cycle) VALUES ($1, $2, $3::jsonb, $4)', [tk, tid, snap, cycle]);
        tokens[tid] = tk;
      }
    }
    res.json({ tokens });
  }));

  app.get('/api/responses', auth, wrap(async (req, res) => {
    const r = await pool.query('SELECT l.tenant_id, l.cycle, r.kind, r.promise_date, r.created_at FROM pay_responses r JOIN pay_links l ON l.token = r.token');
    res.json({ responses: r.rows.map((x) => ({ tenantId: x.tenant_id, cycle: x.cycle, kind: x.kind, date: x.promise_date, at: x.created_at })) });
  }));

  app.delete('/api/responses/:tenantId', auth, wrap(async (req, res) => {
    const l = await pool.query('SELECT token FROM pay_links WHERE tenant_id = $1', [req.params.tenantId]);
    if (l.rowCount) await pool.query('DELETE FROM pay_responses WHERE token = $1', [l.rows[0].token]);
    res.json({ ok: true });
  }));

  /* ----- tenant side (no login; protected by the private token in the link) ----- */
  const noStore = (res) => res.set('Cache-Control', 'no-store');
  app.get('/pay/:token', (req, res) => {
    noStore(res);
    res.sendFile(path.join(__dirname, 'public', 'pay.html'));
  });

  app.get('/api/pay/:token', limiter(60, 15 * 60e3), wrap(async (req, res) => {
    noStore(res);
    if (!TOKEN.test(req.params.token)) return res.status(404).json({ error: 'This link is not valid.' });
    const l = await pool.query('SELECT snapshot, cycle FROM pay_links WHERE token = $1', [req.params.token]);
    if (!l.rowCount) return res.status(404).json({ error: 'This link is not valid.' });
    const r = await pool.query('SELECT kind, promise_date FROM pay_responses WHERE token = $1', [req.params.token]);
    res.json({ ...l.rows[0].snapshot, response: r.rowCount ? { kind: r.rows[0].kind, date: r.rows[0].promise_date } : null });
  }));

  app.post('/api/pay/:token', limiter(20, 15 * 60e3), wrap(async (req, res) => {
    noStore(res);
    if (!TOKEN.test(req.params.token)) return res.status(404).json({ error: 'This link is not valid.' });
    const l = await pool.query('SELECT token FROM pay_links WHERE token = $1', [req.params.token]);
    if (!l.rowCount) return res.status(404).json({ error: 'This link is not valid.' });
    const kind = req.body && req.body.kind;
    let date = null;
    if (kind === 'promise') {
      date = String(req.body.date || '');
      const now = Date.now(), t = new Date(date + 'T00:00:00Z').getTime();
      if (!isoDate(date)) return res.status(400).json({ error: 'Please choose a valid date.' });
      if (t < now - 2 * 864e5) return res.status(400).json({ error: 'The date cannot be in the past.' });
      if (t > now + 61 * 864e5) return res.status(400).json({ error: 'Please choose a date within the next 60 days.' });
    } else if (kind !== 'paid') {
      return res.status(400).json({ error: 'Invalid request.' });
    }
    await pool.query('DELETE FROM pay_responses WHERE token = $1', [req.params.token]);
    await pool.query('INSERT INTO pay_responses (token, kind, promise_date) VALUES ($1, $2, $3)', [req.params.token, kind, date]);
    res.json({ ok: true });
  }));

  app.use(express.static(path.join(__dirname, 'public')));
  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
  app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    if (err.status && err.status < 500) return res.status(err.status).json({ error: 'Bad request' });
    console.error(err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  });
  return app;
}

module.exports = { createApp, init, normEmail, emailOk };

if (require.main === module) {
  const need = ['DATABASE_URL', 'OWNER_EMAIL', 'OWNER_PASSWORD', 'SESSION_SECRET'].filter((k) => !process.env[k]);
  if (need.length) { console.error('Missing environment variables: ' + need.join(', ')); process.exit(1); }
  const owner = normEmail(process.env.OWNER_EMAIL);
  if (!emailOk(owner)) { console.error('OWNER_EMAIL is not a valid email address.'); process.exit(1); }
  if (process.env.OWNER_PASSWORD.length < 8) { console.error('OWNER_PASSWORD must be at least 8 characters.'); process.exit(1); }
  const { Pool } = require('pg');
  const url = process.env.DATABASE_URL;
  const ssl = process.env.PGSSL === 'disable' || /localhost|127\.0\.0\.1/.test(url) ? false : { rejectUnauthorized: false };
  const pool = new Pool({ connectionString: url, ssl, max: 4, idleTimeoutMillis: 10000, connectionTimeoutMillis: 15000 });
  pool.on('error', (err) => console.error('Database connection error:', err.message));
  const app = createApp(pool, {
    owner,
    password: process.env.OWNER_PASSWORD,
    secret: process.env.SESSION_SECRET,
    publicUrl: process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || '',
    resendKey: process.env.RESEND_API_KEY,
    mailFrom: process.env.MAIL_FROM,
  });
  init(pool)
    .then(() => app.listen(process.env.PORT || 3000, () => console.log('PG Manager running')))
    .catch((err) => { console.error('Database setup failed:', err.message); process.exit(1); });
}
