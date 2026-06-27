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
  try {
    const { name, full_name, email, password, mobile, role } = await parseBody(req);
    const finalName = (full_name || name || '').trim();
    const finalEmail = (email || '').trim().toLowerCase();
    const finalMobile = (mobile || '').trim();
    const finalRole = (role || 'seeker').trim();

    if (!finalName || !finalEmail || !password || !finalMobile) {
      return jsonResponse(res, 400, { error: 'All fields (full_name, email, password, mobile) are required.' });
    }

    if (!finalEmail.includes('@')) {
      return jsonResponse(res, 400, { error: 'Please enter a valid email address.' });
    }

    if (password.length < 8) {
      return jsonResponse(res, 400, { error: 'Password must be at least 8 characters long.' });
    }

    // Check existing user
    let { data: existingUser, error: checkErr } = await supabase
      .from('users')
      .select('id, email')
      .ilike('email', finalEmail)
      .maybeSingle();

    if (checkErr) {
      console.error('Database check error during signup:', checkErr);
      return jsonResponse(res, 500, { error: `Database error: ${checkErr.message}` });
    }

    if (existingUser) {
      return jsonResponse(res, 400, { error: 'An account with this email address already exists.' });
    }

    // Hash the password
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    // Insert user
    const { data: newUser, error: insertErr } = await supabase
      .from('users')
      .insert({
        full_name: finalName,
        email: finalEmail,
        password: passwordHash,
        mobile: finalMobile,
        role: finalRole
      })
      .select('id, full_name, email')
      .single();

    if (insertErr || !newUser) {
      console.error('Database insert error during signup:', insertErr);
      return jsonResponse(res, 500, { error: `Failed to create account: ${insertErr ? insertErr.message : 'Database error'}` });
    }

    const token   = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '30d' });
    const expires = expiresAt30Days();

    const { error: sessionErr } = await supabase.from('sessions').insert({ user_id: newUser.id, token, expires_at: expires });

    if (sessionErr) {
      console.error('Database session insert error during signup:', sessionErr);
      return jsonResponse(res, 500, { error: `Account verified, but failed to start session: ${sessionErr.message}` });
    }

    console.log(`✅ New user: ${newUser.email}`);
    return jsonResponse(res, 201, { token, user: { id: newUser.id, name: newUser.full_name, email: newUser.email } });
  } catch (err) {
    console.error('Catch block error in handleSignup:', err);
    return jsonResponse(res, 500, { error: `Internal server error: ${err.message || err}` });
  }
}

// POST /api/login
async function handleLogin(req, res) {
  try {
    const { email, password } = await parseBody(req);
    const finalEmail = (email || '').trim().toLowerCase();

    if (!finalEmail || !password)
      return jsonResponse(res, 400, { error: 'Email and password are required.' });

    // Check existing user - must select password field too!
    let { data: user, error: fetchErr } = await supabase
      .from('users')
      .select('id, full_name, email, password')
      .ilike('email', finalEmail)
      .maybeSingle();

    if (fetchErr) {
      console.error('Login database fetch error:', fetchErr);
      return jsonResponse(res, 500, { error: `Database error: ${fetchErr.message}` });
    }

    if (!user) {
      return jsonResponse(res, 401, { error: 'Invalid email or password.' });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return jsonResponse(res, 401, { error: 'Invalid email or password.' });
    }

    // Clear expired sessions
    await supabase.from('sessions').delete().lt('expires_at', new Date().toISOString());

    const token   = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    const expires = expiresAt30Days();

    const { error: sessionErr } = await supabase.from('sessions').insert({ user_id: user.id, token, expires_at: expires });

    if (sessionErr) {
      console.error('Database session insert error during login:', sessionErr);
      return jsonResponse(res, 500, { error: `Session establishment failed: ${sessionErr.message}` });
    }

    console.log(`🔑 Login: ${user.email}`);
    return jsonResponse(res, 200, { token, user: { id: user.id, name: user.full_name, email: user.email } });
  } catch (err) {
    console.error('Catch block error in handleLogin:', err);
    return jsonResponse(res, 500, { error: `Internal server error: ${err.message || err}` });
  }
}

// GET /api/me
async function handleMe(req, res) {
  try {
    const token = getBearerToken(req);
    if (!token) return jsonResponse(res, 401, { error: 'No token provided.' });

    const payload = verifyToken(token);
    if (!payload)  return jsonResponse(res, 401, { error: 'Invalid or expired token.' });

    const { data: session, error: sessionErr } = await supabase
      .from('sessions')
      .select('id')
      .eq('token', token)
      .gt('expires_at', new Date().toISOString())
      .maybeSingle();

    if (sessionErr) {
      console.error('Session verify error:', sessionErr);
      return jsonResponse(res, 500, { error: `Session verification error: ${sessionErr.message}` });
    }

    if (!session)  return jsonResponse(res, 401, { error: 'Session expired. Please log in again.' });

    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('id, full_name, email')
      .eq('id', payload.userId)
      .maybeSingle();

    if (userErr) {
      console.error('User fetch error in verify:', userErr);
      return jsonResponse(res, 500, { error: `User profile fetch error: ${userErr.message}` });
    }

    if (!user) return jsonResponse(res, 401, { error: 'User not found.' });

    return jsonResponse(res, 200, { user: { id: user.id, name: user.full_name, email: user.email } });
  } catch (err) {
    console.error('Catch block error in handleMe:', err);
    return jsonResponse(res, 500, { error: `Internal server error: ${err.message || err}` });
  }
}

// POST /api/logout
async function handleLogout(req, res) {
  try {
    const token = getBearerToken(req);
    if (token) {
      await supabase.from('sessions').delete().eq('token', token);
      console.log('👋 User logged out');
    }
    return jsonResponse(res, 200, { message: 'Logged out successfully.' });
  } catch (err) {
    console.error('Logout error:', err);
    return jsonResponse(res, 500, { error: `Internal server error during logout: ${err.message || err}` });
  }
}

// GET /api/config
async function handleConfig(req, res) {
  return jsonResponse(res, 200, {
    supabaseUrl: process.env.SUPABASE_URL,
    supabaseKey: process.env.SUPABASE_ANON_KEY
  });
}

// POST /api/social-login
async function handleSocialLogin(req, res) {
  try {
    const { email, full_name, role } = await parseBody(req);
    const finalEmail = (email || '').trim().toLowerCase();
    const finalName = (full_name || 'Google User').trim();
    const finalRole = (role || 'seeker').trim();

    if (!finalEmail) {
      return jsonResponse(res, 400, { error: 'Email is required.' });
    }

    // Check if user exists
    let { data: user, error: fetchErr } = await supabase
      .from('users')
      .select('id, full_name, email')
      .ilike('email', finalEmail)
      .maybeSingle();

    if (fetchErr) {
      console.error('Social login fetch error:', fetchErr);
      return jsonResponse(res, 500, { error: `Database query failed: ${fetchErr.message}` });
    }

    if (!user) {
      // Create user if they don't exist
      const generatedPassword = await bcrypt.hash(Math.random().toString(36).substring(2, 15), SALT_ROUNDS);
      const { data: newUser, error: insertErr } = await supabase
        .from('users')
        .insert({
          full_name: finalName,
          email: finalEmail,
          password: generatedPassword,
          role: finalRole,
          mobile: ''
        })
        .select('id, full_name, email')
        .single();

      if (insertErr || !newUser) {
        console.error('Social login insert error:', insertErr);
        return jsonResponse(res, 500, { error: `Failed to create user account: ${insertErr ? insertErr.message : 'Database error'}` });
      }
      user = newUser;
    }

    const token   = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    const expires = expiresAt30Days();
    const { error: sessionErr } = await supabase.from('sessions').insert({ user_id: user.id, token, expires_at: expires });

    if (sessionErr) {
      console.error('Social login session insert error:', sessionErr);
      return jsonResponse(res, 500, { error: `Social login succeeded, but session establishment failed: ${sessionErr.message}` });
    }

    return jsonResponse(res, 200, { token, user: { id: user.id, name: user.full_name, email: user.email } });
  } catch (err) {
    console.error('Social login catch block error:', err);
    return jsonResponse(res, 500, { error: `Internal server error during social login: ${err.message || err}` });
  }
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
    if (method === 'POST' && route === '/api/signup')       return await handleSignup(req, res);
    if (method === 'POST' && route === '/api/login')        return await handleLogin(req, res);
    if (method === 'GET'  && route === '/api/me')           return await handleMe(req, res);
    if (method === 'POST' && route === '/api/logout')       return await handleLogout(req, res);
    if (method === 'GET'  && route === '/api/config')       return await handleConfig(req, res);
    if (method === 'POST' && route === '/api/social-login') return await handleSocialLogin(req, res);
    if (method === 'POST' && route === '/api/assistant')    return await handleAssistant(req, res);
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
