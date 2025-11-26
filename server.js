const express = require('express');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const VEND_FILE = path.join(DATA_DIR, 'vends.json');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');

let vends = [];
let authStore = {
  apiKey: '',
  users: [],
  pending: [],
  tokens: [],
};

const defaultVends = [];

const hashPassword = (password, salt = crypto.randomBytes(16).toString('hex')) => {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { salt, hash };
};

const verifyPassword = (password, user) => {
  if (!user || !user.salt || !user.hash) return false;
  const { hash } = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.hash, 'hex'));
};

const emptyAuth = () => ({
  apiKey: generateApiKey(),
  users: [],
  pending: [],
  tokens: [],
});

const randomFromRange = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

function generateApiKey() {
  const length = randomFromRange(10, 15);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = '';
  for (let i = 0; i < length; i += 1) key += chars.charAt(Math.floor(Math.random() * chars.length));
  return key;
}

const ensureFiles = async () => {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(VEND_FILE);
  } catch {
    await fs.writeFile(VEND_FILE, JSON.stringify(defaultVends, null, 2));
  }
  try {
    await fs.access(AUTH_FILE);
  } catch {
    await fs.writeFile(AUTH_FILE, JSON.stringify(emptyAuth(), null, 2));
  }
};

const loadVends = async () => {
  const raw = await fs.readFile(VEND_FILE, 'utf8');
  vends = JSON.parse(raw || '[]');
};

const saveVends = async () => {
  await fs.writeFile(VEND_FILE, JSON.stringify(vends, null, 2));
};

const loadAuth = async () => {
  const raw = await fs.readFile(AUTH_FILE, 'utf8');
  authStore = JSON.parse(raw || JSON.stringify(emptyAuth()));
  if (!authStore.apiKey) authStore.apiKey = generateApiKey();
  if (!authStore.tokens) authStore.tokens = [];

  // Migrate any plaintext passwords to hashed.
  let migrated = false;
  authStore.users = authStore.users.map((u) => {
    if (u.hash && u.salt) return u;
    const creds = hashPassword(u.password || '');
    migrated = true;
    return { username: u.username, role: u.role, ...creds };
  });
  authStore.pending = authStore.pending.map((u) => {
    if (u.hash && u.salt) return u;
    const creds = hashPassword(u.password || '');
    migrated = true;
    return { username: u.username, ...creds };
  });
  // Clean expired tokens.
  const now = Date.now();
  const initialTokens = authStore.tokens.length;
  authStore.tokens = authStore.tokens.filter((t) => !t.expiresAt || t.expiresAt > now);
  if (authStore.tokens.length !== initialTokens) migrated = true;
  if (migrated) await saveAuth();
};

const saveAuth = async () => {
  await fs.writeFile(AUTH_FILE, JSON.stringify(authStore, null, 2));
};

const cookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.COOKIE_SECURE === 'true',
  maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
};

const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');
const createSession = async (user) => {
  const token = generateApiKey() + Date.now();
  const tokenHash = hashToken(token);
  const expiresAt = Date.now() + cookieOptions.maxAge;
  authStore.tokens.push({ tokenHash, username: user.username, role: user.role, expiresAt });
  await saveAuth();
  return { token, expiresAt };
};
const findSession = (token) => {
  if (!token) return null;
  const tokenHash = hashToken(token);
  const now = Date.now();
  const record = authStore.tokens.find((t) => t.tokenHash === tokenHash && (!t.expiresAt || t.expiresAt > now));
  return record || null;
};
const clearSession = async (token) => {
  if (!token) return;
  const tokenHash = hashToken(token);
  const before = authStore.tokens.length;
  authStore.tokens = authStore.tokens.filter((t) => t.tokenHash !== tokenHash);
  if (authStore.tokens.length !== before) await saveAuth();
};

const parseCookies = (req) => {
  const header = req.headers.cookie;
  if (!header) return {};
  return header.split(';').reduce((acc, part) => {
    const [k, v] = part.trim().split('=');
    acc[k] = decodeURIComponent(v || '');
    return acc;
  }, {});
};

const requireApiKey = (req, res, next) => {
  const key = req.header('x-api-key');
  if (!key || key !== authStore.apiKey) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  next();
};

const requireAuth = (req, res, next) => {
  const cookies = parseCookies(req);
  const token = cookies.auth_token;
  const session = findSession(token);
  if (!session) return res.status(401).json({ error: 'Unauthorized' });
  req.user = { username: session.username, role: session.role };
  next();
};

const requireOwner = (req, res, next) => {
  if (!req.user || req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Owner access required' });
  }
  next();
};

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', requireApiKey);
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

const parseCoord = (v) => {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};

const isValidVend = (body) => {
  const required = ['worldName', 'itemName', 'id', 'perEach', 'price', 'lastUpdate'];
  if (!required.every((key) => key in body)) return false;
  if ('x' in body && body.x !== null && body.x !== '' && !Number.isFinite(Number(body.x))) return false;
  if ('y' in body && body.y !== null && body.y !== '' && !Number.isFinite(Number(body.y))) return false;
  return true;
};

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = authStore.users.find((u) => u.username === username);
  if (!user || !verifyPassword(password, user)) return res.status(401).json({ error: 'Invalid credentials' });

  const session = await createSession(user);
  res.cookie('auth_token', session.token, cookieOptions);
  return res.json({ username: user.username, role: user.role, expiresAt: session.expiresAt });
});

app.post('/auth/logout', async (req, res) => {
  const cookies = parseCookies(req);
  const token = cookies.auth_token;
  if (token) await clearSession(token);
  res.cookie('auth_token', '', { ...cookieOptions, maxAge: 0 });
  res.json({ ok: true });
});

app.post('/auth/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const existsUser = authStore.users.some((u) => u.username === username);
  const existsPending = authStore.pending.some((u) => u.username === username);
  if (existsUser || existsPending) return res.status(409).json({ error: 'Username already exists or pending' });
  const creds = hashPassword(password);
  authStore.pending.push({ username, ...creds });
  await saveAuth();
  res.status(201).json({ message: 'Registration submitted, waiting for owner approval' });
});

app.get('/auth/me', requireAuth, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

app.get('/owner/pending', requireAuth, requireOwner, (req, res) => {
  res.json(authStore.pending.map((p) => ({ username: p.username })));
});

app.post('/owner/pending/:username/approve', requireAuth, requireOwner, async (req, res) => {
  const { username } = req.params;
  const pendingIndex = authStore.pending.findIndex((p) => p.username === username);
  if (pendingIndex === -1) return res.status(404).json({ error: 'Pending user not found' });
  const entry = authStore.pending.splice(pendingIndex, 1)[0];
  authStore.users.push({ username: entry.username, hash: entry.hash, salt: entry.salt, role: 'user' });
  await saveAuth();
  res.json({ username: entry.username, role: 'user' });
});

app.get('/owner/api-key', requireAuth, (req, res) => {
  res.json({ apiKey: authStore.apiKey });
});

app.post('/owner/api-key/rotate', requireAuth, requireOwner, async (req, res) => {
  authStore.apiKey = generateApiKey();
  await saveAuth();
  res.json({ apiKey: authStore.apiKey });
});

app.get('/api/vends', (req, res) => {
  res.json(vends);
});

app.post('/api/vends', async (req, res) => {
  const data = req.body;
  if (!isValidVend(data)) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const price = Math.trunc(Number(data.price));
  if (!Number.isFinite(price) || price < 0) {
    return res.status(400).json({ error: 'Price must be a non-negative integer' });
  }

  const exists = vends.some((entry) => entry.id === data.id);
  if (exists) {
    return res.status(409).json({ error: 'id already exists' });
  }

  const newEntry = {
    worldName: String(data.worldName).trim(),
    itemName: String(data.itemName).trim(),
    id: String(data.id).trim(),
    perEach: Boolean(data.perEach),
    price,
    lastUpdate: data.lastUpdate,
    x: parseCoord(data.x),
    y: parseCoord(data.y),
  };

  vends.push(newEntry);
  await saveVends();
  res.status(201).json(newEntry);
});

app.put('/api/vends/:id', async (req, res) => {
  const { id } = req.params;
  const index = vends.findIndex((entry) => entry.id === id);
  if (index === -1) {
    return res.status(404).json({ error: 'Not found' });
  }
  const data = { ...vends[index], ...req.body, id };
  if (!isValidVend(data)) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const price = Math.trunc(Number(data.price));
  if (!Number.isFinite(price) || price < 0) {
    return res.status(400).json({ error: 'Price must be a non-negative integer' });
  }
  vends[index] = {
    worldName: String(data.worldName).trim(),
    itemName: String(data.itemName).trim(),
    id,
    perEach: Boolean(data.perEach),
    price,
    lastUpdate: data.lastUpdate,
    x: parseCoord(data.x),
    y: parseCoord(data.y),
  };
  await saveVends();
  res.json(vends[index]);
});

app.delete('/api/vends/:id', async (req, res) => {
  const { id } = req.params;
  const index = vends.findIndex((entry) => entry.id === id);
  if (index === -1) {
    return res.status(404).json({ error: 'Not found' });
  }
  const removed = vends.splice(index, 1)[0];
  await saveVends();
  res.json(removed);
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

(async () => {
  try {
    await ensureFiles();
    await Promise.all([loadVends(), loadAuth()]);
    // Bind to localhost by default for local testing. To expose on all interfaces,
    // set the PORT env var and/or change the host to '0.0.0.0'.
    app.listen(PORT, '127.0.0.1', () => {
      console.log(`Lucky Proxy Vend Finder running at http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
})();
