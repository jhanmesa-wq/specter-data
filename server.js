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
const SESSION_SECRET = String(process.env.SESSION_SECRET || '').trim();
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_INITIAL_PASSWORD = String(process.env.ADMIN_INITIAL_PASSWORD || '');
const TELEGRAM_BOT_TOKEN = String(
  process.env.TELEGRAM_BOT_TOKEN ||
  process.env.TELEGRAM_TOKEN ||
  process.env.BOT_TOKEN ||
  ''
).trim();
const TELEGRAM_ADMIN_CHAT_ID = String(
  process.env.TELEGRAM_ADMIN_CHAT_ID ||
  process.env.TELEGRAM_ADMIN_ID ||
  ''
).trim();
const TELEGRAM_ADMIN_USER_ID = String(process.env.TELEGRAM_ADMIN_USER_ID || '').trim();

// Se aceptan alias para no perder configuraciones ya creadas en Render.
const rawTelegramSetting = String(
  process.env.TELEGRAM_USERNAME ||
  process.env.TELEGRAM_USER ||
  process.env.TELEGRAM_PURCHASE_URL ||
  process.env.TELEGRAM_LINK ||
  process.env.BOT_USERNAME ||
  ''
).trim();

function normalizeTelegramUsername(value) {
  if (!value) return '';
  let candidate = value.trim();

  try {
    if (/^https?:\/\//i.test(candidate)) {
      const parsed = new URL(candidate);
      if (!['t.me', 'www.t.me', 'telegram.me', 'www.telegram.me'].includes(parsed.hostname.toLowerCase())) {
        return '';
      }
      candidate = parsed.pathname.split('/').filter(Boolean)[0] || '';
    }
  } catch {
    return '';
  }

  candidate = candidate.replace(/^@/, '').replace(/^(?:https?:\/\/)?(?:www\.)?(?:t\.me|telegram\.me)\//i, '');
  candidate = candidate.split(/[/?#]/)[0].trim();

  return /^[A-Za-z0-9_]{5,32}$/.test(candidate) ? candidate : '';
}

const TELEGRAM_USERNAME = normalizeTelegramUsername(rawTelegramSetting);
const CREDIT_PRICE_TEXT = String(
  process.env.CREDIT_PRICE_TEXT ||
  process.env.CREDIT_PRICE ||
  process.env.CREDITOS_PRECIOS ||
  process.env.PRECIOS_CREDITOS ||
  'Consulta los paquetes y precios disponibles por Telegram.'
).trim();

const MUSIC_URL = String(
  process.env.MUSIC_URL ||
  process.env.BACKGROUND_MUSIC_URL ||
  process.env.MUSIC_LINK ||
  process.env.AUDIO_URL ||
  ''
).trim();

const COOKIE_NAME = 'specter_session';
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('Falta SESSION_SECRET o tiene menos de 32 caracteres. Configúrala en Render > Environment.');
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

  CREATE INDEX IF NOT EXISTS idx_ledger_user
  ON credit_ledger(user_id, id DESC);

  CREATE TABLE IF NOT EXISTS telegram_processed_updates (
    update_id INTEGER PRIMARY KEY,
    processed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

// Activación de administrador por correo configurado en Render.
// Si la cuenta ya existe, se le activa el permiso sin obligar a cambiar su contraseña.
// ADMIN_INITIAL_PASSWORD solo se usa para crear una cuenta administradora que aún no existe.
if (ADMIN_EMAIL) {
  const existing = db.prepare(
    'SELECT id, is_admin FROM users WHERE email = ?'
  ).get(ADMIN_EMAIL);

  if (!existing && ADMIN_INITIAL_PASSWORD) {
    const hash = bcrypt.hashSync(ADMIN_INITIAL_PASSWORD, 12);

    db.prepare(`
      INSERT INTO users (email, password_hash, credits, is_admin)
      VALUES (?, ?, 0, 1)
    `).run(ADMIN_EMAIL, hash);

    console.log(`Cuenta administradora inicial creada: ${ADMIN_EMAIL}`);
  } else if (existing && existing.is_admin !== 1) {
    if (ADMIN_INITIAL_PASSWORD) {
      const hash = bcrypt.hashSync(ADMIN_INITIAL_PASSWORD, 12);
      db.prepare(`
        UPDATE users
        SET password_hash = ?, is_admin = 1
        WHERE id = ?
      `).run(hash, existing.id);
    } else {
      db.prepare(`
        UPDATE users
        SET is_admin = 1
        WHERE id = ?
      `).run(existing.id);
    }

    console.log(`Permisos de administrador activados para: ${ADMIN_EMAIL}`);
  } else if (!existing) {
    console.warn(
      `ADMIN_EMAIL está configurado (${ADMIN_EMAIL}), pero la cuenta aún no existe. Registra esa cuenta o configura ADMIN_INITIAL_PASSWORD para crearla.`
    );
  } else {
    console.log(`Administrador detectado: ${ADMIN_EMAIL}`);
  }
} else {
  console.warn('ADMIN_EMAIL no está configurado. El panel de administración permanecerá desactivado.');
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
      imgSrc: ["'self'", 'data:', 'https:'],
      mediaSrc: ["'self'", 'https:'],
      connectSrc: ["'self'", 'https:'],
      upgradeInsecureRequests:
        process.env.NODE_ENV === 'production' ? [] : null
    }
  }
}));

app.use(express.json({ limit: '24kb' }));

function sameOrigin(req, res, next) {
  const origin = req.get('origin');

  if (!origin) return next();

  try {
    if (new URL(origin).host !== req.get('host')) {
      return res.status(403).json({
        error: 'Origen no permitido.'
      });
    }
  } catch {
    return res.status(403).json({
      error: 'Origen no válido.'
    });
  }

  return next();
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: 'Demasiados intentos. Espera unos minutos y vuelve a intentarlo.'
  }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 35,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

function setSession(res, user) {
  const token = jwt.sign(
    {
      sub: user.id,
      email: user.email
    },
    SESSION_SECRET,
    {
      expiresIn: '7d'
    }
  );

  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: COOKIE_MAX_AGE
  });
}

function readCookie(req, name) {
  const raw = req.headers.cookie || '';

  for (const part of raw.split(';')) {
    const index = part.indexOf('=');

    if (index < 0) continue;

    if (part.slice(0, index).trim() === name) {
      return decodeURIComponent(
        part.slice(index + 1).trim()
      );
    }
  }

  return '';
}

function requireAuth(req, res, next) {
  const token = req.cookies?.[COOKIE_NAME] || readCookie(req, COOKIE_NAME);

  if (!token) {
    return res.status(401).json({
      error: 'Inicia sesión para continuar.'
    });
  }

  try {
    const payload = jwt.verify(token, SESSION_SECRET);

    const user = db.prepare(`
      SELECT id, email, credits, is_admin
      FROM users
      WHERE id = ?
    `).get(payload.sub);

    if (!user) {
      return res.status(401).json({
        error: 'La sesión ya no es válida.'
      });
    }

    req.user = user;
    return next();

  } catch {
    return res.status(401).json({
      error: 'La sesión expiró. Vuelve a ingresar.'
    });
  }
}

function isConfiguredAdmin(user) {
  return Boolean(
    ADMIN_EMAIL &&
    user &&
    user.is_admin === 1 &&
    String(user.email || '').trim().toLowerCase() === ADMIN_EMAIL
  );
}

function requireAdmin(req, res, next) {
  if (!isConfiguredAdmin(req.user)) {
    return res.status(403).json({
      error: 'Esta función es exclusiva de la cuenta ADMIN_EMAIL configurada en Render.'
    });
  }

  return next();
}

function validEmail(value) {
  return typeof value === 'string' &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function getPublicUser(id) {
  return db.prepare(`
    SELECT id, email, credits, is_admin
    FROM users
    WHERE id = ?
  `).get(id);
}

function chargeCredits(userId, amount, action, note) {
  const tx = db.transaction(() => {
    const user = db.prepare(`
      SELECT credits
      FROM users
      WHERE id = ?
    `).get(userId);

    if (!user || user.credits < amount) {
      return false;
    }

    db.prepare(`
      UPDATE users
      SET credits = credits - ?
      WHERE id = ?
    `).run(amount, userId);

    db.prepare(`
      INSERT INTO credit_ledger (user_id, amount, action, note)
      VALUES (?, ?, ?, ?)
    `).run(userId, -amount, action, note);

    return true;
  });

  return tx();
}

// Configuración pública para login.html y consultas.html.
// Nunca se envían al navegador tokens ni credenciales privadas.
app.get('/api/config', (req, res) => {
  res.set('Cache-Control', 'no-store');

  let musicUrl = '';
  try {
    const parsed = new URL(MUSIC_URL);
    if (parsed.protocol === 'https:') musicUrl = parsed.href;
  } catch {
    musicUrl = '';
  }

  const telegramPurchaseUrl = TELEGRAM_USERNAME
    ? `https://t.me/${encodeURIComponent(TELEGRAM_USERNAME)}`
    : '';

  res.json({
    telegramUsername: TELEGRAM_USERNAME,
    telegramPurchaseUrl,
    telegramConfigured: Boolean(telegramPurchaseUrl),
    creditPriceText: CREDIT_PRICE_TEXT,
    musicUrl,
    musicConfigured: Boolean(musicUrl)
  });
});

// Registro.
app.post('/api/auth/register', sameOrigin, authLimiter, (req, res) => {
  res.set('Cache-Control', 'no-store');
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');

  if (!validEmail(email)) {
    return res.status(400).json({
      error: 'Escribe un correo electrónico válido.'
    });
  }

  if (password.length < 8 || password.length > 72) {
    return res.status(400).json({
      error: 'La contraseña debe tener entre 8 y 72 caracteres.'
    });
  }

  if (ADMIN_EMAIL && email === ADMIN_EMAIL) {
    return res.status(403).json({
      error: 'Esta cuenta está reservada para administración. Inicia sesión con la clave configurada en Render.'
    });
  }

  try {
    const hash = bcrypt.hashSync(password, 12);

    const result = db.prepare(`
      INSERT INTO users (email, password_hash, credits)
      VALUES (?, ?, 0)
    `).run(email, hash);

    const user = getPublicUser(result.lastInsertRowid);

    setSession(res, user);

    return res.status(201).json({
      user: {
        email: user.email,
        credits: user.credits,
        isAdmin: false
      }
    });

  } catch (error) {
    if (String(error.code || '').includes('SQLITE_CONSTRAINT')) {
      return res.status(409).json({
        error: 'Ese correo ya tiene una cuenta. Inicia sesión.'
      });
    }

    console.error('Error registrando cuenta:', error.message);

    return res.status(500).json({
      error: 'No se pudo crear la cuenta.'
    });
  }
});

// Inicio de sesión.
app.post('/api/auth/login', sameOrigin, authLimiter, (req, res) => {
  res.set('Cache-Control', 'no-store');
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');

  if (!validEmail(email) || !password) {
    return res.status(400).json({
      error: 'Revisa el correo y la contraseña.'
    });
  }

  const user = db.prepare(`
    SELECT id, email, password_hash
    FROM users
    WHERE email = ?
  `).get(email);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({
      error: 'Correo o contraseña incorrectos.'
    });
  }

  setSession(res, user);

  const fresh = getPublicUser(user.id);

  return res.json({
    user: {
      email: fresh.email,
      credits: fresh.credits,
      isAdmin: isConfiguredAdmin(fresh)
    }
  });
});

// Cerrar sesión.
app.post('/api/auth/logout', sameOrigin, (req, res) => {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/'
  });

  return res.json({ ok: true });
});
// Obtener perfil.
app.get('/api/me', requireAuth, (req, res) => {
  res.set('Cache-Control', 'no-store');
  const user = getPublicUser(req.user.id);

  return res.json({
    user: {
      email: user.email,
      credits: user.credits,
      isAdmin: isConfiguredAdmin(user)
    }
  });
});

// Función única para acreditar cuentas y dejar trazabilidad en el libro contable.
function addCreditsToAccount(email, amount, note, actorEmail, action = 'admin_add') {
  const normalizedEmail = String(email || '').trim().toLowerCase();

  if (!validEmail(normalizedEmail)) {
    return { ok: false, status: 400, error: 'Escribe un correo electrónico válido.' };
  }

  if (!Number.isSafeInteger(amount) || amount < 1 || amount > 100000) {
    return { ok: false, status: 400, error: 'La cantidad debe ser un entero entre 1 y 100000.' };
  }

  const target = db.prepare(`
    SELECT id, email
    FROM users
    WHERE email = ?
  `).get(normalizedEmail);

  if (!target) {
    return { ok: false, status: 404, error: 'No existe una cuenta con ese correo.' };
  }

  const tx = db.transaction(() => {
    db.prepare(`
      UPDATE users
      SET credits = credits + ?
      WHERE id = ?
    `).run(amount, target.id);

    db.prepare(`
      INSERT INTO credit_ledger
        (user_id, amount, action, note, actor_email)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      target.id,
      amount,
      action,
      String(note || 'Carga de créditos').trim().slice(0, 160),
      String(actorEmail || 'administrador').slice(0, 254)
    );
  });

  tx();

  const updated = getPublicUser(target.id);
  return {
    ok: true,
    email: updated.email,
    credits: updated.credits,
    amount
  };
}

// Agregar créditos desde el panel web: solo administrador.
app.post(
  '/api/admin/credits/add',
  sameOrigin,
  requireAuth,
  requireAdmin,
  (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const amount = Number(req.body?.amount);
    const note = String(req.body?.note || 'Carga manual de créditos')
      .trim()
      .slice(0, 160);

    const result = addCreditsToAccount(
      email,
      amount,
      note,
      req.user.email,
      'admin_add'
    );

    if (!result.ok) {
      return res.status(result.status).json({ error: result.error });
    }

    return res.json({
      ok: true,
      email: result.email,
      amount: result.amount,
      credits: result.credits
    });
  }
);

// Historial reciente de créditos: solo administrador.
app.get(
  '/api/admin/credits/recent',
  requireAuth,
  requireAdmin,
  (req, res) => {
    const rows = db.prepare(`
      SELECT
        u.email,
        l.amount,
        l.action,
        l.note,
        l.actor_email,
        l.created_at
      FROM credit_ledger l
      JOIN users u ON u.id = l.user_id
      ORDER BY l.id DESC
      LIMIT 25
    `).all();

    return res.json({ rows });
  }
);

// Consulta de IP.
app.post(
  '/api/consult/ip',
  sameOrigin,
  apiLimiter,
  requireAuth,
  async (req, res) => {
    const ip = String(req.body?.ip || '').trim();

    if (!net.isIP(ip)) {
      return res.status(400).json({
        error: 'Escribe una dirección IPv4 o IPv6 válida.'
      });
    }

    const cost = 10;
    const current = getPublicUser(req.user.id);

    if (current.credits < cost) {
      return res.status(402).json({
        error: `Necesitas ${cost} créditos para esta herramienta.`,
        credits: current.credits
      });
    }

    try {
      const response = await fetch(
        `https://ipwho.is/${encodeURIComponent(ip)}`,
        {
          signal: AbortSignal.timeout(8000)
        }
      );

      if (!response.ok) {
        throw new Error(
          'El proveedor de geolocalización no respondió correctamente.'
        );
      }

      const payload = await response.json();

      if (payload.success === false) {
        return res.status(422).json({
          error: payload.message || 'No se pudo resolver esa IP.'
        });
      }

      const charged = chargeCredits(
        req.user.id,
        cost,
        'ip_lookup',
        `Consulta IP ${ip}`
      );

      if (!charged) {
        return res.status(402).json({
          error: 'No tienes créditos suficientes.',
          credits: getPublicUser(req.user.id).credits
        });
      }

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

      return res.status(502).json({
        error: 'No se pudo completar la consulta de IP. No se descontaron créditos.'
      });
    }
  }
);

// Consulta DNS.
app.post(
  '/api/consult/dns',
  sameOrigin,
  apiLimiter,
  requireAuth,
  async (req, res) => {
    const domain = String(req.body?.domain || '')
      .trim()
      .toLowerCase()
      .replace(/\.$/, '');

    const validDomain =
      domain.length <= 253 &&
      /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain);

    if (!validDomain) {
      return res.status(400).json({
        error: 'Escribe un dominio válido, por ejemplo ejemplo.com.'
      });
    }

    const cost = 2;
    const current = getPublicUser(req.user.id);

    if (current.credits < cost) {
      return res.status(402).json({
        error: `Necesitas ${cost} créditos para esta herramienta.`,
        credits: current.credits
      });
    }

    try {
      const records = await dns.lookup(domain, {
        all: true,
        verbatim: true
      });

      if (!records.length) {
        return res.status(404).json({
          error: 'El dominio no devolvió direcciones DNS.'
        });
      }

      const charged = chargeCredits(
        req.user.id,
        cost,
        'dns_lookup',
        `Resolución DNS ${domain}`
      );

      if (!charged) {
        return res.status(402).json({
          error: 'No tienes créditos suficientes.',
          credits: getPublicUser(req.user.id).credits
        });
      }

      const user = getPublicUser(req.user.id);

      return res.json({
        domain,
        records,
        credits: user.credits
      });

    } catch (error) {
      if (
        error.code === 'ENOTFOUND' ||
        error.code === 'ENODATA'
      ) {
        return res.status(404).json({
          error: 'No se encontraron registros de dirección para ese dominio.'
        });
      }

      console.error('Error en consulta DNS:', error.message);

      return res.status(502).json({
        error: 'No se pudo completar la consulta DNS. No se descontaron créditos.'
      });
    }
  }
);


// ============================================================
// BOT DE TELEGRAM: /addcreditos correo cantidad
// Configurar TELEGRAM_BOT_TOKEN y TELEGRAM_ADMIN_CHAT_ID en Render.
// El update_id se registra en SQLite junto con el abono para evitar duplicados.
function processTelegramUpdate(update) {
  const message = update?.message;
  const text = String(message?.text || '').trim();
  const chatId = String(message?.chat?.id ?? '');
  const senderId = String(message?.from?.id ?? '');
  const updateId = Number(update?.update_id);

  if (!Number.isSafeInteger(updateId) || !message || !text) {
    return { reply: '' };
  }

  const command = text.split(/\s+/, 1)[0].split('@')[0].toLowerCase();
  const args = text.split(/\s+/).slice(1);

  const tx = db.transaction(() => {
    const alreadyProcessed = db.prepare(
      'SELECT update_id FROM telegram_processed_updates WHERE update_id = ?'
    ).get(updateId);

    if (alreadyProcessed) return { reply: '' };

    let reply = '';

    if (command === '/id') {
      reply = `Chat ID: ${chatId}\nUsuario ID: ${senderId}\nConfigura TELEGRAM_ADMIN_CHAT_ID en Render con el Chat ID indicado.`;
    } else if (command === '/start' || command === '/help') {
      reply = 'SPECTER DATA — Administración de créditos\n\nComando:\n/addcreditos correo cantidad\n\nEjemplo:\n/addcreditos usuario@gmail.com 100\n\nUsa /id para consultar el ID de este chat.';
    } else if (command === '/addcreditos') {
      const isPrivateChat = String(message.chat?.type || '') === 'private';
      const authorized =
        Boolean(TELEGRAM_ADMIN_CHAT_ID) &&
        chatId === TELEGRAM_ADMIN_CHAT_ID &&
        (
          TELEGRAM_ADMIN_USER_ID
            ? senderId === TELEGRAM_ADMIN_USER_ID
            : isPrivateChat && senderId === chatId
        );

      if (!authorized) {
        reply = '⛔ No autorizado. Este chat o usuario no está habilitado para administrar créditos.';
      } else if (args.length !== 2) {
        reply = 'Formato incorrecto.\nUso: /addcreditos correo cantidad\nEjemplo: /addcreditos usuario@gmail.com 100';
      } else {
        const email = String(args[0] || '').trim().toLowerCase();
        const amount = Number(args[1]);

        if (!validEmail(email)) {
          reply = '❌ El correo indicado no es válido.';
        } else if (!Number.isSafeInteger(amount) || amount < 1 || amount > 100000) {
          reply = '❌ La cantidad debe ser un entero entre 1 y 100000.';
        } else {
          const target = db.prepare(
            'SELECT id, email FROM users WHERE email = ?'
          ).get(email);

          if (!target) {
            reply = `❌ No existe una cuenta registrada con el correo ${email}.`;
          } else {
            db.prepare(`
              UPDATE users
              SET credits = credits + ?
              WHERE id = ?
            `).run(amount, target.id);

            db.prepare(`
              INSERT INTO credit_ledger
                (user_id, amount, action, note, actor_email)
              VALUES (?, ?, 'telegram_add', ?, ?)
            `).run(
              target.id,
              amount,
              'Carga de créditos mediante Telegram',
              `telegram:${senderId}`
            );

            const updated = getPublicUser(target.id);
            reply = `✅ Créditos agregados correctamente.\n\nCuenta: ${updated.email}\nCréditos añadidos: ${amount}\nSaldo actual: ${updated.credits} CR`;
          }
        }
      }
    }

    db.prepare(`
      INSERT OR IGNORE INTO telegram_processed_updates (update_id)
      VALUES (?)
    `).run(updateId);

    return { reply };
  });

  return tx();
}

async function telegramApi(method, payload) {
  const response = await fetch(
    `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${method}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(35000)
    }
  );

  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok) {
    throw new Error(data.description || `Telegram API respondió HTTP ${response.status}`);
  }
  return data.result;
}

async function startTelegramCreditBot() {
  if (!TELEGRAM_BOT_TOKEN) {
    console.log('Bot de créditos Telegram desactivado: falta TELEGRAM_BOT_TOKEN.');
    return;
  }

  let offset = Number(
    db.prepare('SELECT COALESCE(MAX(update_id), 0) + 1 AS next_id FROM telegram_processed_updates').get().next_id
  );

  console.log('Bot de créditos Telegram iniciado. Esperando comandos autorizados...');

  while (true) {
    try {
      const updates = await telegramApi('getUpdates', {
        offset,
        timeout: 25,
        allowed_updates: ['message']
      });

      for (const update of updates || []) {
        offset = Number(update.update_id) + 1;

        try {
          const result = processTelegramUpdate(update);
          if (result.reply && update.message?.chat?.id != null) {
            await telegramApi('sendMessage', {
              chat_id: update.message.chat.id,
              text: result.reply
            });
          }
        } catch (error) {
          console.error('Error procesando comando de Telegram:', error.message);
        }
      }
    } catch (error) {
      console.error('Conexión del bot Telegram:', error.message);
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
}

// Archivos públicos.
app.use(
  express.static(
    path.join(__dirname, 'public'),
    { extensions: ['html'] }
  )
);

app.get('/', (req, res) => {
  res.redirect('/login.html');
});

app.get('/consultas', (req, res) => {
  res.redirect('/consultas.html');
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Manejo de errores.
app.use((err, req, res, next) => {
  console.error('Error no controlado:', err.message);

  if (res.headersSent) {
    return next(err);
  }

  return res.status(500).json({
    error: 'Ocurrió un error interno.'
  });
});

// Iniciar servidor.
app.listen(PORT, () => {
  console.log(`SPECTER DATA activo en el puerto ${PORT}`);

  if (process.env.CODART_TOKEN) {
    console.log(
      'Se detectó CODART_TOKEN en el entorno del servidor (no se envía al navegador).'
    );
  }

  startTelegramCreditBot().catch(error => {
    console.error('No se pudo iniciar el bot de créditos Telegram:', error.message);
  });
});
