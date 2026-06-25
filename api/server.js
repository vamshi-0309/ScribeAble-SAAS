const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const initSqlJs = require('sql.js');

// ── CONFIG ────────────────────────────────────────────────────────────────────
const PORT       = 3000;
const JWT_SECRET = 'scribeconnect_jwt_secret_change_in_production_2024';
const isVercel   = process.env.VERCEL === '1' || process.env.NOW_REGION !== undefined;
const DB_FILE    = isVercel
  ? path.join('/tmp', 'scribeconnect.db')
  : path.join(__dirname, '..', 'scribeconnect.db');
const SALT_ROUNDS = 10;

const MIME = {
  '.html': 'text/html',
  '.css' : 'text/css',
  '.js'  : 'application/javascript',
  '.json': 'application/json',
  '.png' : 'image/png',
  '.jpg' : 'image/jpeg',
  '.svg' : 'image/svg+xml',
  '.ico' : 'image/x-icon'
};

// ── DATABASE (sql.js – pure WASM SQLite) ──────────────────────────────────────
let db;

async function initDB() {
  const SQL = await initSqlJs();

  if (isVercel) {
    const bundledDbPath = path.join(__dirname, '..', 'scribeconnect.db');
    if (!fs.existsSync(DB_FILE) && fs.existsSync(bundledDbPath)) {
      try {
        fs.copyFileSync(bundledDbPath, DB_FILE);
        console.log('📋 Copied bundled database to /tmp:', DB_FILE);
      } catch (copyErr) {
        console.error('Failed to copy database to /tmp:', copyErr);
      }
    }
  }

  if (fs.existsSync(DB_FILE)) {
    const data = fs.readFileSync(DB_FILE);
    db = new SQL.Database(data);
    console.log('📂 Loaded existing database from', DB_FILE);
  } else {
    db = new SQL.Database();
    console.log('🆕 Created new database at', DB_FILE);
  }

  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      name         TEXT    NOT NULL,
      email        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT   NOT NULL,
      created_at   TEXT    DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL,
      token      TEXT    NOT NULL UNIQUE,
      created_at TEXT    DEFAULT (datetime('now')),
      expires_at TEXT    NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  saveDB();
  console.log('✅ Database ready');
}

function saveDB() {
  try {
    const data = db.export();
    fs.writeFileSync(DB_FILE, Buffer.from(data));
  } catch (err) {
    console.error('Failed to write database file:', err.message);
  }
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
function dbGet(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row;
    }
    stmt.free();
    return null;
  } catch (e) {
    return null;
  }
}

// ── HELPERS continued ─────────────────────────────────────────────────────────
function dbRun(sql, params = []) {
  try {
    db.run(sql, params);
    saveDB();
    return true;
  } catch (e) {
    console.error('DB error:', e.message);
    return false;
  }
}

function jsonResponse(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    'Content-Type' : 'application/json',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(payload);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch (e) { resolve({}); }
    });
    req.on('error', reject);
  });
}

function getBearerToken(req) {
  const auth = req.headers['authorization'] || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

function expireOldSessions() {
  dbRun(`DELETE FROM sessions WHERE expires_at < datetime('now')`);
}

// ── ROUTE HANDLERS ────────────────────────────────────────────────────────────

// POST /api/signup
async function handleSignup(req, res) {
  const { name, email, password } = await parseBody(req);

  if (!name || !email || !password)
    return jsonResponse(res, 400, { error: 'Name, email and password are required.' });

  if (!email.includes('@'))
    return jsonResponse(res, 400, { error: 'Please enter a valid email address.' });

  if (password.length < 8)
    return jsonResponse(res, 400, { error: 'Password must be at least 8 characters.' });

  const existing = dbGet('SELECT id FROM users WHERE email = ?', [email]);
  if (existing)
    return jsonResponse(res, 409, { error: 'An account with this email already exists.' });

  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  const ok   = dbRun('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', [name.trim(), email.trim(), hash]);

  if (!ok)
    return jsonResponse(res, 500, { error: 'Failed to create account. Please try again.' });

  const user    = dbGet('SELECT id, name, email FROM users WHERE email = ?', [email]);
  const token   = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);

  dbRun('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, token, expires]);

  console.log(`✅ New user: ${user.email}`);
  return jsonResponse(res, 201, { token, user: { id: user.id, name: user.name, email: user.email } });
}

// POST /api/login
async function handleLogin(req, res) {
  const { email, password } = await parseBody(req);

  if (!email || !password)
    return jsonResponse(res, 400, { error: 'Email and password are required.' });

  const user = dbGet('SELECT id, name, email, password_hash FROM users WHERE email = ?', [email.trim()]);
  if (!user)
    return jsonResponse(res, 401, { error: 'No account found with this email.' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match)
    return jsonResponse(res, 401, { error: 'Incorrect password. Please try again.' });

  expireOldSessions();

  const token   = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);

  dbRun('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, token, expires]);

  console.log(`🔑 Login: ${user.email}`);
  return jsonResponse(res, 200, { token, user: { id: user.id, name: user.name, email: user.email } });
}

// GET /api/me  (validate token)
function handleMe(req, res) {
  const token = getBearerToken(req);
  if (!token) return jsonResponse(res, 401, { error: 'No token provided.' });

  const payload = verifyToken(token);
  if (!payload)  return jsonResponse(res, 401, { error: 'Invalid or expired token.' });

  // Check token exists in sessions table (not logged out)
  const session = dbGet('SELECT id FROM sessions WHERE token = ? AND expires_at > datetime(\'now\')', [token]);
  if (!session)  return jsonResponse(res, 401, { error: 'Session expired. Please log in again.' });

  const user = dbGet('SELECT id, name, email FROM users WHERE id = ?', [payload.userId]);
  if (!user)     return jsonResponse(res, 401, { error: 'User not found.' });

  return jsonResponse(res, 200, { user: { id: user.id, name: user.name, email: user.email } });
}

// POST /api/logout
function handleLogout(req, res) {
  const token = getBearerToken(req);
  if (token) {
    dbRun('DELETE FROM sessions WHERE token = ?', [token]);
    console.log('👋 User logged out');
  }
  return jsonResponse(res, 200, { message: 'Logged out successfully.' });
}

// POST /api/assistant
async function handleAssistant(req, res) {
  const { transcript } = await parseBody(req);
  if (!transcript) {
    return jsonResponse(res, 400, { error: 'Transcript is required.' });
  }

  const lower = transcript.toLowerCase().trim();
  let reply = "";
  let action = null;
  let actionArg = null;

  if (lower.includes('help') || lower.includes('what can you do') || lower.includes('commands') || lower.includes('guide')) {
    reply = "Sure! I can help you find a scribe, switch to dark mode, or tell you how ScribeConnect works. What do you need?";
    action = "help";
  } else if (lower.includes('hello') || lower.includes('hi') || lower.includes('hey') || lower.includes('good morning') || lower.includes('good afternoon')) {
    reply = "Hello there! I am your ScribeConnect assistant. I am here to help you navigate the platform, find exam scribes, or volunteer. What can I do for you today?";
  } else if (lower.includes('find scribe') || lower.includes('need scribe') || lower.includes('request scribe') || lower.includes('get scribe') || lower.includes('book scribe') || lower.includes('look for scribe')) {
    reply = "I would be happy to help you find a scribe. I am opening the request form now. Please tell me the subject, exam date, and location so I can match you with available volunteers.";
    action = "openModal";
    actionArg = "seeker";
  } else if (lower.includes('volunteer') || lower.includes('register') || lower.includes('become scribe') || lower.includes('want to volunteer') || lower.includes('be a scribe')) {
    reply = "That is wonderful! Volunteers are the heart of ScribeConnect. I am launching the volunteer registration form. You can select your subjects and availability to get started.";
    action = "openModal";
    actionArg = "volunteer";
  } else if (lower.includes('how it works') || lower.includes('how does it work') || lower.includes('explain') || lower.includes('steps')) {
    reply = "ScribeConnect is very easy to use. First, you choose your role and sign up. Then, candidates submit exam details and we match them with nearby verified scribes in under five minutes. Finally, you connect securely. Is there any specific step you'd like me to explain?";
    action = "scrollTo";
    actionArg = "#how";
  } else if (lower.includes('dark mode') || lower.includes('dark theme') || lower.includes('go dark') || lower.includes('switch to dark')) {
    reply = "Switching to dark theme for a more comfortable reading experience.";
    action = "theme";
    actionArg = "dark";
  } else if (lower.includes('light mode') || lower.includes('light theme') || lower.includes('switch to light')) {
    reply = "Switching to light theme.";
    action = "theme";
    actionArg = "light";
  } else if (lower.includes('stop reading') || lower.includes('be quiet') || lower.includes('silence')) {
    reply = "Stopping reading.";
    action = "stopReading";
  } else if (lower.includes('sign out') || lower.includes('logout') || lower.includes('exit')) {
    reply = "Logging you out from ScribeConnect. Have a great day!";
    action = "logout";
  } else if (lower.includes('filter maths') || lower.includes('maths scribes')) {
    reply = "Filtering to show available scribes with expertise in Mathematics.";
    action = "filter";
    actionArg = "maths";
  } else if (lower.includes('filter science') || lower.includes('science scribes')) {
    reply = "Filtering to show available scribes with expertise in Science.";
    action = "filter";
    actionArg = "science";
  } else if (lower.includes('isl scribes') || lower.includes('sign language')) {
    reply = "Filtering to show scribes with Indian Sign Language skills.";
    action = "filter";
    actionArg = "isl";
  } else if (lower.includes('free scribes') || lower.includes('free volunteers') || lower.includes('show free')) {
    reply = "Filtering to show free volunteers only.";
    action = "filter";
    actionArg = "volunteer";
  } else if (lower.includes('all scribes') || lower.includes('show all') || lower.includes('clear filter')) {
    reply = "Clearing filters to show all verified scribes.";
    action = "filter";
    actionArg = "all";
  } else if (lower.includes('close') || lower.includes('cancel') || lower.includes('dismiss')) {
    reply = "Closing all open dialogues.";
    action = "closeModal";
  } else if (lower.includes('cost') || lower.includes('price') || lower.includes('how much') || lower.includes('free')) {
    reply = "ScribeConnect offers both free volunteers who assist as social service, and professional paid scribes whose rates typically range from one hundred to one thousand rupees per hour. You can search and filter for free volunteers in the budget options.";
  } else if (lower.includes('how many scribes') || lower.includes('scribes available') || lower.includes('cities')) {
    reply = "We have over twelve hundred verified scribes across forty-two cities in India. The average response time is just under five minutes.";
  } else if (lower.includes('privacy') || lower.includes('safe') || lower.includes('security')) {
    reply = "Privacy and safety are our top priorities. All profiles undergo database verification. Student profiles and venues are kept confidential and are only shared with matching scribes once mutual agreement is achieved.";
  } else {
    reply = `I heard you say: "${transcript}". As your virtual AI assistant, I can help you find exam scribes, register as a volunteer, navigate the site, or adjust accessibility settings like font sizes and high contrast. Please let me know what you would like to do.`;
  }

  return jsonResponse(res, 200, { response: reply, action, actionArg });
}

// ── STATIC FILE HANDLER ───────────────────────────────────────────────────────
function serveStatic(req, res) {
  let urlPath = req.url.split('?')[0];
  let filePath = urlPath === '/' ? 'index.html' : urlPath.replace(/^\//, '');
  filePath = path.resolve(__dirname, '..', filePath);

  if (!filePath.startsWith(path.resolve(__dirname, '..'))) {
    res.writeHead(403); res.end('Forbidden'); return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404); res.end('404 Not Found'); return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);
  });
}

// ── SERVERLESS HANDLER ────────────────────────────────────────────────────────
let dbInitialized = false;
let dbPromise = null;
async function ensureDB() {
  if (dbInitialized) return;
  if (!dbPromise) {
    dbPromise = initDB();
  }
  await dbPromise;
  dbInitialized = true;
}

const handler = async (req, res) => {
  await ensureDB();

  const { method, url } = req;
  const route = url.split('?')[0];

  console.log(`${method} ${route}`);

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin' : '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization'
    });
    return res.end();
  }

  // API routes
  if (method === 'POST' && route === '/api/signup')  return handleSignup(req, res);
  if (method === 'POST' && route === '/api/login')   return handleLogin(req, res);
  if (method === 'GET'  && route === '/api/me')      return handleMe(req, res);
  if (method === 'POST' && route === '/api/logout')  return handleLogout(req, res);
  if (method === 'POST' && route === '/api/assistant') return handleAssistant(req, res);

  // Static files
  serveStatic(req, res);
};

// ── BOOT (only when run directly) ─────────────────────────────────────────────
if (require.main === module) {
  initDB().then(() => {
    const server = http.createServer(handler);
    server.listen(PORT, () => {
      console.log(`\n🚀 ScribeConnect server running at http://localhost:${PORT}`);
      console.log('   Auth endpoints: /api/signup  /api/login  /api/me  /api/logout\n');
    });
  }).catch(err => {
    console.error('❌ Failed to initialise database:', err);
    process.exit(1);
  });
}

// Export for Vercel Serverless
module.exports = handler;
