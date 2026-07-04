const crypto = require('crypto');

// Real secret values live in Vercel Environment Variables (Project Settings -> Environment Variables).
// The fallbacks below only exist so the site still works if you haven't set them yet — for real
// protection, set GATE_PIN, MAIN_PIN, and SESSION_SECRET in Vercel and remove reliance on these.
const GATE_PIN = process.env.GATE_PIN || 'aj2030@';
const MAIN_PIN = process.env.MAIN_PIN || '259282587273';
const SESSION_SECRET = process.env.SESSION_SECRET || 'please-change-this-secret';

function sign(payload) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
}

function readBody(req) {
  return new Promise((resolve) => {
    if (req.body) {
      try {
        resolve(typeof req.body === 'string' ? JSON.parse(req.body) : req.body);
      } catch (e) {
        resolve({});
      }
      return;
    }
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); } catch (e) { resolve({}); }
    });
  });
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ ok: false });
    return;
  }

  const { pin, gate } = await readBody(req);
  const expected = gate === 'secret' ? GATE_PIN : MAIN_PIN;

  if (!pin || String(pin).toLowerCase() !== String(expected).toLowerCase()) {
    res.status(401).json({ ok: false });
    return;
  }

  const expiry = Date.now() + 1000 * 60 * 60 * 6; // 6 hour session
  const payload = `${gate || 'main'}.${expiry}`;
  const token = `${payload}.${sign(payload)}`;

  const host = req.headers.host || '';
  const isLocal = host.startsWith('localhost') || host.startsWith('127.0.0.1');
  const cookieParts = [
    `bh_session=${encodeURIComponent(token)}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    'Max-Age=21600',
  ];
  if (!isLocal) cookieParts.push('Secure');

  res.setHeader('Set-Cookie', cookieParts.join('; '));
  res.status(200).json({ ok: true });
};
