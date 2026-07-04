const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SESSION_SECRET = process.env.SESSION_SECRET || 'please-change-this-secret';

const ALLOWED_FILES = new Set([
  'jhuka.jpg',
  'Bhawna_home.jpg',
  'bhawna3.jpg',
  'BNha.jpg',
  'photo_2026-05-19_23-44-00.jpg',
  'photo_2026-05-20_00-03-13.jpg',
  'BhAj.mp4',
]);

function sign(payload) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
}

function isValidSession(req) {
  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(/bh_session=([^;]+)/);
  if (!match) return false;

  const token = decodeURIComponent(match[1]);
  const parts = token.split('.');
  if (parts.length !== 3) return false;

  const [gate, expiry, sig] = parts;
  const payload = `${gate}.${expiry}`;
  if (sign(payload) !== sig) return false;
  if (Date.now() > Number(expiry)) return false;

  return true;
}

module.exports = (req, res) => {
  const name = req.query.name;

  if (!name || !ALLOWED_FILES.has(name)) {
    res.status(400).end('Bad request');
    return;
  }

  if (!isValidSession(req)) {
    res.status(403).end('Forbidden');
    return;
  }

  const filePath = path.join(__dirname, '_assets', name);
  if (!fs.existsSync(filePath)) {
    res.status(404).end('Not found');
    return;
  }

  const ext = path.extname(name).toLowerCase();
  const mime = ext === '.mp4' ? 'video/mp4' : 'image/jpeg';

  res.setHeader('Content-Type', mime);
  res.setHeader('Cache-Control', 'private, no-store');
  fs.createReadStream(filePath).pipe(res);
};
