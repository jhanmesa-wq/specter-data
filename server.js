'use strict';

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const dns = require('node:dns').promises;
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_INITIAL_PASSWORD = String(process.env.ADMIN_INITIAL_PASSWORD || '');
const TELEGRAM_USERNAME = String(process.env.TELEGRAM_USERNAME || 'specter_os').replace(/^@/, '').trim();
const COOKIE_NAME = 'specter_session';
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('Falta SESSION_SECRET o tiene menos de 32 caracteres. Configúrala en Render > Environment.');
  process.exit(1);
}
if ((ADMIN_EMAIL && !ADMIN_INITIAL_PASSWORD) || (!ADMIN_EMAIL && ADMIN_INITIAL_PASSWORD)) {
  console.error('Configura juntos ADMIN_EMAIL y ADMIN_INITIAL_PASSWORD, o deja ambos vacíos.');
  process.exit(1);
}
if (ADMIN_INITIAL_PASSWORD && ADMIN_INITIAL_PASSWORD.length < 12) {
  console.error('ADMIN_INITIAL_PASSWORD debe tener al menos 12 caracteres.');
  process.exit(1);
}

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'specter.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    credits INTEGER NOT NULL DEFAULT 0 CHECK (credits >= 0),
    is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0,1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS credit_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount INTEGER NOT NULL,
    action TEXT NOT NULL,
    note TEXT,
    actor_email TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_ledger_user ON credit_ledger(user_id, id DESC);
`);

// La primera configuración de Render crea o promueve la cuenta administradora.
// La contraseña inicial solo se aplica cuando la cuenta todavía no es admin.
if (ADMIN_EMAIL) {
  const existing = db.prepare('SELECT id, is_admin FROM users WHERE email = ?').get(ADMIN_EMAIL);
  if (!existing) {
    const hash = bcrypt.hashSync(ADMIN_INITIAL_PASSWORD, 12);
    db.prepare('INSERT INTO users (email, password_hash, credits, is_admin) VALUES (?, ?, 0, 1)')
      .run(ADMIN_EMAIL, hash);
    console.log(`Cuenta administradora inicial creada: ${ADMIN_EMAIL}`);
  } else if (!existing.is_admin) {
    const hash = bcrypt.hashSync(ADMIN_INITIAL_PASSWORD, 12);
    db.prepare('UPDATE users SET password_hash = ?, is_admin = 1 WHERE id = ?').run(hash, existing.id);
    console.log(`Cuenta administradora inicial habilitada: ${ADMIN_EMAIL}`);
  }
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  }
}));
app.use(express.json({ limit: '24kb' }));

function sameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (!origin) return next();
  try {
    if (new URL(origin).host !== req.get('host')) {
      return res.status(403).json({ error: 'Origen no permitido.' });
    }
  } catch {
    return res.status(403).json({ error: 'Origen no válido.' });
  }
  return next();
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Demasiados intentos. Espera unos minutos y vuelve a intentarlo.' }
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 35,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

function setSession(res, user) {
  const token = jwt.sign({ sub: user.id, email: user.email }, SESSION_SECRET, { expiresIn: '7d' });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: COOKIE_MAX_AGE
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies?.[COOKIE_NAME] || readCookie(req, COOKIE_NAME);
  if (!token) return res.status(401).json({ error: 'Inicia sesión para continuar.' });
  try {
    const payload = jwt.verify(token, SESSION_SECRET);
    const user = db.prepare('SELECT id, email, credits, is_admin FROM users WHERE id = ?').get(payload.sub);
    if (!user) return res.status(401).json({ error: 'La sesión ya no es válida.' });
    req.user = user;
    return next();
  } catch {
    return res.status(401).json({ error: 'La sesión expiró. Vuelve a ingresar.' });
  }
}

function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return decodeURIComponent(part.slice(index + 1).trim());
  }
  return '';
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.is_admin !== 1) {
    return res.status(403).json({ error: 'Esta función es exclusiva de administración.' });
  }
  return next();
}

function validEmail(value) {
  return typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function getPublicUser(id) {
  return db.prepare('SELECT id, email, credits, is_admin FROM users WHERE id = ?').get(id);
}

function chargeCredits(userId, amount, action, note) {
  const tx = db.transaction(() => {
    const user = db.prepare('SELECT credits FROM users WHERE id = ?').get(userId);
    if (!user || user.credits < amount) return false;
    db.prepare('UPDATE users SET credits = credits - ? WHERE id = ?').run(amount, userId);
    db.prepare(`INSERT INTO credit_ledger (user_id, amount, action, note) VALUES (?, ?, ?, ?)`)
      .run(userId, -amount, action, note);
    return true;
  });
  return tx();
}

app.get('/api/config', (req, res) => {
  res.json({ telegramUsername: TELEGRAM_USERNAME });
});

app.post('/api/auth/register', sameOrigin, authLimiter, (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (!validEmail(email)) return res.status(400).json({ error: 'Escribe un correo electrónico válido.' });
  if (password.length < 8 || password.length > 72) {
    return res.status(400).json({ error: 'La contraseña debe tener entre 8 y 72 caracteres.' });
  }
  if (ADMIN_EMAIL && email === ADMIN_EMAIL) {
    return res.status(403).json({ error: 'Esta cuenta está reservada para administración. Inicia sesión con la clave configurada en Render.' });
  }
  try {
    const hash = bcrypt.hashSync(password, 12);
    const result = db.prepare('INSERT INTO users (email, password_hash, credits) VALUES (?, ?, 0)').run(email, hash);
    const user = getPublicUser(result.lastInsertRowid);
    setSession(res, user);
    return res.status(201).json({ user: { email: user.email, credits: user.credits, isAdmin: false } });
  } catch (error) {
    if (String(error.code || '').includes('SQLITE_CONSTRAINT')) {
      return res.status(409).json({ error: 'Ese correo ya tiene una cuenta. Inicia sesión.' });
    }
    console.error('Error registrando cuenta:', error.message);
    return res.status(500).json({ error: 'No se pudo crear la cuenta.' });
  }
});

app.post('/api/auth/login', sameOrigin, authLimiter, (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (!validEmail(email) || !password) return res.status(400).json({ error: 'Revisa el correo y la contraseña.' });
  const user = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
  }
  setSession(res, user);
  const fresh = getPublicUser(user.id);
  return res.json({ user: { email: fresh.email, credits: fresh.credits, isAdmin: fresh.is_admin === 1 } });
});

app.post('/api/auth/logout', sameOrigin, (req, res) => {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/'
  });
  return res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = getPublicUser(req.user.id);
  return res.json({ user: { email: user.email, credits: user.credits, isAdmin: user.is_admin === 1 } });
});

app.post('/api/admin/credits/add', sameOrigin, requireAuth, requireAdmin, (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const amount = Number(req.body?.amount);
  const note = String(req.body?.note || 'Carga manual de créditos').trim().slice(0, 160);
  if (!validEmail(email)) return res.status(400).json({ error: 'Escribe el correo de la cuenta destinataria.' });
  if (!Number.isSafeInteger(amount) || amount < 1 || amount > 100000) {
    return res.status(400).json({ error: 'La cantidad debe ser un entero entre 1 y 100000.' });
  }
  const target = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!target) return res.status(404).json({ error: 'No existe una cuenta con ese correo.' });
  const tx = db.transaction(() => {
    db.prepare('UPDATE users SET credits = credits + ? WHERE id = ?').run(amount, target.id);
    db.prepare(`INSERT INTO credit_ledger (user_id, amount, action, note, actor_email)
                VALUES (?, ?, 'admin_add', ?, ?)`)
      .run(target.id, amount, note || 'Carga manual de créditos', req.user.email);
  });
  tx();
  const updated = getPublicUser(target.id);
  return res.json({ ok: true, email: updated.email, credits: updated.credits });
});

app.get('/api/admin/credits/recent', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT u.email, l.amount, l.action, l.note, l.actor_email, l.created_at
    FROM credit_ledger l JOIN users u ON u.id = l.user_id
    ORDER BY l.id DESC LIMIT 25
  `).all();
  return res.json({ rows });
});

app.post('/api/consult/ip', sameOrigin, apiLimiter, requireAuth, async (req, res) => {
  const ip = String(req.body?.ip || '').trim();
  if (!net.isIP(ip)) return res.status(400).json({ error: 'Escribe una dirección IPv4 o IPv6 válida.' });
  const cost = 10;
  const current = getPublicUser(req.user.id);
  if (current.credits < cost) return res.status(402).json({ error: `Necesitas ${cost} créditos para esta herramienta.`, credits: current.credits });
  try {
    const response = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { signal: AbortSignal.timeout(8000) });
    if (!response.ok) throw new Error('El proveedor de geolocalización no respondió correctamente.');
    const payload = await response.json();
    if (payload.success === false) return res.status(422).json({ error: payload.message || 'No se pudo resolver esa IP.' });
    const charged = chargeCredits(req.user.id, cost, 'ip_lookup', `Consulta IP ${ip}`);
    if (!charged) return res.status(402).json({ error: 'No tienes créditos suficientes.', credits: getPublicUser(req.user.id).credits });
    const user = getPublicUser(req.user.id);
    return res.json({
      data: {
        ip,
        country: payload.country || 'No disponible',
        region: payload.region || 'No disponible',
        city: payload.city || 'No disponible',
        postal: payload.postal || 'No disponible',
        latitude: payload.latitude ?? null,
        longitude: payload.longitude ?? null,
        isp: payload.connection?.isp || 'No disponible',
        org: payload.connection?.org || 'No disponible'
      },
      credits: user.credits
    });
  } catch (error) {
    console.error('Error en consulta IP:', error.message);
    return res.status(502).json({ error: 'No se pudo completar la consulta de IP. No se descontaron créditos.' });
  }
});

app.post('/api/consult/dns', sameOrigin, apiLimiter, requireAuth, async (req, res) => {
  const domain = String(req.body?.domain || '').trim().toLowerCase().replace(/\.$/, '');
  const validDomain = domain.length <= 253 && /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain);
  if (!validDomain) return res.status(400).json({ error: 'Escribe un dominio válido, por ejemplo ejemplo.com.' });
  const cost = 2;
  const current = getPublicUser(req.user.id);
  if (current.credits < cost) return res.status(402).json({ error: `Necesitas ${cost} créditos para esta herramienta.`, credits: current.credits });
  try {
    const records = await dns.lookup(domain, { all: true, verbatim: true });
    if (!records.length) return res.status(404).json({ error: 'El dominio no devolvió direcciones DNS.' });
    const charged = chargeCredits(req.user.id, cost, 'dns_lookup', `Resolución DNS ${domain}`);
    if (!charged) return res.status(402).json({ error: 'No tienes créditos suficientes.', credits: getPublicUser(req.user.id).credits });
    const user = getPublicUser(req.user.id);
    return res.json({ domain, records, credits: user.credits });
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return res.status(404).json({ error: 'No se encontraron registros de dirección para ese dominio.' });
    }
    console.error('Error en consulta DNS:', error.message);
    return res.status(502).json({ error: 'No se pudo completar la consulta DNS. No se descontaron créditos.' });
  }
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('/', (req, res) => res.redirect('/login.html'));
app.get('/consultas', (req, res) => res.redirect('/consultas.html'));
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use((err, req, res, next) => {
  console.error('Error no controlado:', err.message);
  if (res.headersSent) return next(err);
  return res.status(500).json({ error: 'Ocurrió un error interno.' });
});

app.listen(PORT, () => {
  console.log(`SPECTER DATA activo en el puerto ${PORT}`);
  if (process.env.CODART_TOKEN) console.log('Se detectó CODART_TOKEN en el entorno del servidor (no se envía al navegador).');
});
