const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

// ── LOAD .env (local dev only) ────────────────────────────────────────────────
const envPath = path.join(__dirname, '..', '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx > 0) {
      const key = trimmed.slice(0, eqIdx).trim();
      const val = trimmed.slice(eqIdx + 1).trim();
      if (!process.env[key]) process.env[key] = val;
    }
  });
}

// ── CONFIG ────────────────────────────────────────────────────────────────────
const PORT        = process.env.PORT || 3000;
const JWT_SECRET  = process.env.JWT_SECRET || 'scribeconnect_jwt_secret_change_in_production_2024';
const SUPABASE_URL  = process.env.SUPABASE_URL;
const SUPABASE_KEY  = process.env.SUPABASE_ANON_KEY;
const SALT_ROUNDS = 10;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ Missing SUPABASE_URL or SUPABASE_ANON_KEY environment variables!');
  if (process.env.VERCEL) process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

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

// ── HELPERS ───────────────────────────────────────────────────────────────────
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

function expiresAt30Days() {
  return new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
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

  // Check existing user
  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .ilike('email', email.trim())
    .maybeSingle();

  if (existing)
    return jsonResponse(res, 409, { error: 'An account with this email already exists.' });

  const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

  const { data: user, error: insertErr } = await supabase
    .from('users')
    .insert({ name: name.trim(), email: email.trim().toLowerCase(), password_hash })
    .select('id, name, email')
    .single();

  if (insertErr || !user)
    return jsonResponse(res, 500, { error: 'Failed to create account. Please try again.' });

  const token   = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  const expires = expiresAt30Days();

  await supabase.from('sessions').insert({ user_id: user.id, token, expires_at: expires });

  console.log(`✅ New user: ${user.email}`);
  return jsonResponse(res, 201, { token, user: { id: user.id, name: user.name, email: user.email } });
}

// POST /api/login
async function handleLogin(req, res) {
  const { email, password } = await parseBody(req);

  if (!email || !password)
    return jsonResponse(res, 400, { error: 'Email and password are required.' });

  const { data: user } = await supabase
    .from('users')
    .select('id, name, email, password_hash')
    .ilike('email', email.trim())
    .maybeSingle();

  if (!user)
    return jsonResponse(res, 401, { error: 'No account found with this email.' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match)
    return jsonResponse(res, 401, { error: 'Incorrect password. Please try again.' });

  // Clear expired sessions
  await supabase.from('sessions').delete().lt('expires_at', new Date().toISOString());

  const token   = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  const expires = expiresAt30Days();

  await supabase.from('sessions').insert({ user_id: user.id, token, expires_at: expires });

  console.log(`🔑 Login: ${user.email}`);
  return jsonResponse(res, 200, { token, user: { id: user.id, name: user.name, email: user.email } });
}

// GET /api/me
async function handleMe(req, res) {
  const token = getBearerToken(req);
  if (!token) return jsonResponse(res, 401, { error: 'No token provided.' });

  const payload = verifyToken(token);
  if (!payload)  return jsonResponse(res, 401, { error: 'Invalid or expired token.' });

  const { data: session } = await supabase
    .from('sessions')
    .select('id')
    .eq('token', token)
    .gt('expires_at', new Date().toISOString())
    .maybeSingle();

  if (!session)  return jsonResponse(res, 401, { error: 'Session expired. Please log in again.' });

  const { data: user } = await supabase
    .from('users')
    .select('id, name, email')
    .eq('id', payload.userId)
    .maybeSingle();

  if (!user) return jsonResponse(res, 401, { error: 'User not found.' });

  return jsonResponse(res, 200, { user: { id: user.id, name: user.name, email: user.email } });
}

// POST /api/logout
async function handleLogout(req, res) {
  const token = getBearerToken(req);
  if (token) {
    await supabase.from('sessions').delete().eq('token', token);
    console.log('👋 User logged out');
  }
  return jsonResponse(res, 200, { message: 'Logged out successfully.' });
}

// POST /api/assistant
async function handleAssistant(req, res) {
  const { transcript } = await parseBody(req);
  if (!transcript)
    return jsonResponse(res, 400, { error: 'Transcript is required.' });

  const lower = transcript.toLowerCase().trim();
  let reply = '';
  let action = null;
  let actionArg = null;

  if (lower.includes('help') || lower.includes('what can you do') || lower.includes('commands') || lower.includes('guide')) {
    reply = "Sure! I can help you find a scribe, switch to dark mode, or tell you how ScribeConnect works. What do you need?";
    action = "help";
  } else if (lower.includes('hello') || lower.includes('hi') || lower.includes('hey') || lower.includes('good morning') || lower.includes('good afternoon')) {
    reply = "Hello there! I am your ScribeConnect assistant. I am here to help you navigate the platform, find exam scribes, or volunteer. What can I do for you today?";
  } else if (lower.includes('find scribe') || lower.includes('need scribe') || lower.includes('request scribe') || lower.includes('get scribe') || lower.includes('book scribe')) {
    reply = "I would be happy to help you find a scribe. I am opening the request form now.";
    action = "openModal"; actionArg = "seeker";
  } else if (lower.includes('volunteer') || lower.includes('register') || lower.includes('become scribe') || lower.includes('want to volunteer')) {
    reply = "That is wonderful! Volunteers are the heart of ScribeConnect. I am launching the volunteer registration form.";
    action = "openModal"; actionArg = "volunteer";
  } else if (lower.includes('how it works') || lower.includes('how does it work') || lower.includes('explain') || lower.includes('steps')) {
    reply = "ScribeConnect is very easy to use. First, choose your role and sign up. Then, submit exam details and we match you with nearby scribes in under five minutes.";
    action = "scrollTo"; actionArg = "#how";
  } else if (lower.includes('dark mode') || lower.includes('dark theme') || lower.includes('go dark') || lower.includes('switch to dark')) {
    reply = "Switching to dark theme for a more comfortable reading experience.";
    action = "theme"; actionArg = "dark";
  } else if (lower.includes('light mode') || lower.includes('light theme') || lower.includes('switch to light')) {
    reply = "Switching to light theme.";
    action = "theme"; actionArg = "light";
  } else if (lower.includes('stop reading') || lower.includes('be quiet') || lower.includes('silence')) {
    reply = "Stopping reading."; action = "stopReading";
  } else if (lower.includes('sign out') || lower.includes('logout') || lower.includes('exit')) {
    reply = "Logging you out from ScribeConnect. Have a great day!"; action = "logout";
  } else if (lower.includes('filter maths') || lower.includes('maths scribes')) {
    reply = "Filtering to show scribes with Maths expertise."; action = "filter"; actionArg = "maths";
  } else if (lower.includes('filter science') || lower.includes('science scribes')) {
    reply = "Filtering to show scribes with Science expertise."; action = "filter"; actionArg = "science";
  } else if (lower.includes('isl scribes') || lower.includes('sign language')) {
    reply = "Filtering to show scribes with Indian Sign Language skills."; action = "filter"; actionArg = "isl";
  } else if (lower.includes('free scribes') || lower.includes('free volunteers') || lower.includes('show free')) {
    reply = "Filtering to show free volunteers only."; action = "filter"; actionArg = "volunteer";
  } else if (lower.includes('all scribes') || lower.includes('show all') || lower.includes('clear filter')) {
    reply = "Clearing filters to show all verified scribes."; action = "filter"; actionArg = "all";
  } else if (lower.includes('close') || lower.includes('cancel') || lower.includes('dismiss')) {
    reply = "Closing all open dialogues."; action = "closeModal";
  } else if (lower.includes('cost') || lower.includes('price') || lower.includes('how much')) {
    reply = "ScribeConnect offers both free volunteers and professional scribes (₹100–₹1000/hr). Filter by 'free' to see volunteers.";
  } else if (lower.includes('privacy') || lower.includes('safe') || lower.includes('security')) {
    reply = "Privacy and safety are our top priorities. All profiles are verified and contact is shared only after mutual consent.";
  } else {
    reply = `I heard: "${transcript}". I can help you find scribes, register as a volunteer, navigate the site, or adjust accessibility settings.`;
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
const handler = async (req, res) => {
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

  try {
    if (method === 'POST' && route === '/api/signup')    return await handleSignup(req, res);
    if (method === 'POST' && route === '/api/login')     return await handleLogin(req, res);
    if (method === 'GET'  && route === '/api/me')        return await handleMe(req, res);
    if (method === 'POST' && route === '/api/logout')    return await handleLogout(req, res);
    if (method === 'POST' && route === '/api/assistant') return await handleAssistant(req, res);
  } catch (err) {
    console.error('Handler error:', err);
    return jsonResponse(res, 500, { error: 'Internal server error.' });
  }

  // Static files
  serveStatic(req, res);
};

// ── LOCAL DEV BOOT ────────────────────────────────────────────────────────────
if (require.main === module) {
  const server = http.createServer(handler);
  server.listen(PORT, () => {
    console.log(`\n🚀 ScribeConnect running at http://localhost:${PORT}`);
    console.log('   Auth: /api/signup  /api/login  /api/me  /api/logout\n');
  });
}

module.exports = handler;
