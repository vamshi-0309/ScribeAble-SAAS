const express = require('express');
const fs      = require('fs');
const path    = require('path');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
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
const JWT_SECRET   = process.env.JWT_SECRET || 'scribeconnect_jwt_secret_2024';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;
const SALT_ROUNDS  = 10;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ SUPABASE_URL or SUPABASE_ANON_KEY is not set.');
}

const supabase = createClient(SUPABASE_URL || '', SUPABASE_KEY || '');

// ── EXPRESS APP ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── HELPERS ───────────────────────────────────────────────────────────────────
function getBearerToken(req) {
  const auth = req.headers['authorization'] || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch (e) { return null; }
}

function expiresAt30Days() {
  return new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
}

// ── POST /api/signup ──────────────────────────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  try {
    const { name, full_name, email, password, mobile, role } = req.body || {};
    const finalName = (full_name || name || '').trim();
    const finalEmail = (email || '').trim().toLowerCase();
    const finalMobile = (mobile || '').trim();
    const finalRole = (role || 'seeker').trim();

    if (!finalName)
      return res.status(400).json({ error: 'Full name is required.' });
    if (!finalEmail)
      return res.status(400).json({ error: 'Email address is required.' });
    if (!finalEmail.includes('@'))
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    if (!password)
      return res.status(400).json({ error: 'Password is required.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    // Check existing user
    const { data: existing, error: checkErr } = await supabase
      .from('users').select('id').ilike('email', finalEmail).maybeSingle();

    if (checkErr) {
      console.error('Database check error during signup:', checkErr);
      return res.status(500).json({ error: `Database error during verification: ${checkErr.message}` });
    }

    if (existing)
      return res.status(409).json({ error: 'An account with this email already exists.' });

    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

    const { data: user, error: insertErr } = await supabase
      .from('users')
      .insert({
        full_name: finalName,
        email: finalEmail,
        password: password_hash,
        mobile: finalMobile,
        role: finalRole
      })
      .select('id, full_name, email')
      .single();

    if (insertErr || !user) {
      console.error('Database insert error during signup:', insertErr);
      return res.status(500).json({ error: `Failed to create account: ${insertErr ? insertErr.message : 'Database returned no data.'}` });
    }

    const token   = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    const expires = expiresAt30Days();
    const { error: sessionErr } = await supabase.from('sessions').insert({ user_id: user.id, token, expires_at: expires });

    if (sessionErr) {
      console.error('Database session insert error during signup:', sessionErr);
      return res.status(500).json({ error: `Account created, but failed to start session: ${sessionErr.message}` });
    }

    console.log(`✅ New user: ${user.email}`);
    return res.status(201).json({ token, user: { id: user.id, name: user.full_name, email: user.email } });
  } catch (err) {
    console.error('Catch block error in signup route:', err);
    return res.status(500).json({ error: `Internal server error: ${err.message || err}` });
  }
});

// ── POST /api/login ───────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required.' });

    const { data: user, error: fetchErr } = await supabase
      .from('users').select('id, full_name, email, password')
      .ilike('email', email.trim()).maybeSingle();

    if (fetchErr) {
      console.error('Login database fetch error:', fetchErr);
      return res.status(500).json({ error: `Database error during login: ${fetchErr.message}` });
    }

    if (!user)
      return res.status(401).json({ error: 'No account found with this email.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ error: 'Incorrect password. Please try again.' });

    await supabase.from('sessions').delete().lt('expires_at', new Date().toISOString());

    const token   = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    const expires = expiresAt30Days();
    const { error: sessionErr } = await supabase.from('sessions').insert({ user_id: user.id, token, expires_at: expires });

    if (sessionErr) {
      console.error('Database session insert error during login:', sessionErr);
      return res.status(500).json({ error: `Login succeeded, but session establishment failed: ${sessionErr.message}` });
    }

    console.log(`🔑 Login: ${user.email}`);
    return res.status(200).json({ token, user: { id: user.id, name: user.full_name, email: user.email } });
  } catch (err) {
    console.error('Catch block error in login route:', err);
    return res.status(500).json({ error: `Internal server error: ${err.message || err}` });
  }
});

// ── GET /api/me ───────────────────────────────────────────────────────────────
app.get('/api/me', async (req, res) => {
  try {
    const token = getBearerToken(req);
    if (!token) return res.status(401).json({ error: 'No token provided.' });

    const payload = verifyToken(token);
    if (!payload)  return res.status(401).json({ error: 'Invalid or expired token.' });

    const { data: session, error: sessionErr } = await supabase
      .from('sessions').select('id').eq('token', token)
      .gt('expires_at', new Date().toISOString()).maybeSingle();

    if (sessionErr) {
      console.error('Session verify error:', sessionErr);
      return res.status(500).json({ error: `Session verification error: ${sessionErr.message}` });
    }

    if (!session) return res.status(401).json({ error: 'Session expired. Please log in again.' });

    const { data: user, error: userErr } = await supabase
      .from('users').select('id, full_name, email').eq('id', payload.userId).maybeSingle();

    if (userErr) {
      console.error('User fetch error in verify:', userErr);
      return res.status(500).json({ error: `User profile fetch error: ${userErr.message}` });
    }

    if (!user) return res.status(401).json({ error: 'User not found.' });

    return res.status(200).json({ user: { id: user.id, name: user.full_name, email: user.email } });
  } catch (err) {
    console.error('Catch block error in me route:', err);
    return res.status(500).json({ error: `Internal server error: ${err.message || err}` });
  }
});

// ── POST /api/logout ──────────────────────────────────────────────────────────
app.post('/api/logout', async (req, res) => {
  try {
    const token = getBearerToken(req);
    if (token) {
      await supabase.from('sessions').delete().eq('token', token);
      console.log('👋 User logged out');
    }
    return res.status(200).json({ message: 'Logged out successfully.' });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(500).json({ error: `Internal server error during logout: ${err.message || err}` });
  }
});

// ── POST /api/assistant ───────────────────────────────────────────────────────
app.post('/api/assistant', async (req, res) => {
  const { transcript } = req.body || {};
  if (!transcript) return res.status(400).json({ error: 'Transcript is required.' });

  const lower = transcript.toLowerCase().trim();
  let reply = '', action = null, actionArg = null;

  if (lower.includes('help') || lower.includes('what can you do')) {
    reply = "I can help you find a scribe, switch themes, or explain how ScribeConnect works."; action = "help";
  } else if (lower.includes('hello') || lower.includes('hi') || lower.includes('hey')) {
    reply = "Hello! I'm your ScribeConnect assistant. How can I help you today?";
  } else if (lower.includes('find scribe') || lower.includes('need scribe') || lower.includes('book scribe')) {
    reply = "Opening the scribe request form for you."; action = "openModal"; actionArg = "seeker";
  } else if (lower.includes('volunteer') || lower.includes('become scribe') || lower.includes('register')) {
    reply = "Launching the volunteer registration form."; action = "openModal"; actionArg = "volunteer";
  } else if (lower.includes('how it works') || lower.includes('how does it work')) {
    reply = "ScribeConnect matches you with verified scribes in under 5 minutes."; action = "scrollTo"; actionArg = "#how";
  } else if (lower.includes('dark mode') || lower.includes('dark theme')) {
    reply = "Switching to dark theme."; action = "theme"; actionArg = "dark";
  } else if (lower.includes('light mode') || lower.includes('light theme')) {
    reply = "Switching to light theme."; action = "theme"; actionArg = "light";
  } else if (lower.includes('sign out') || lower.includes('logout')) {
    reply = "Logging you out. Have a great day!"; action = "logout";
  } else if (lower.includes('stop reading') || lower.includes('be quiet') || lower.includes('silence')) {
    reply = "Stopping."; action = "stopReading";
  } else if (lower.includes('close') || lower.includes('cancel') || lower.includes('dismiss')) {
    reply = "Closing dialogues."; action = "closeModal";
  } else if (lower.includes('all scribes') || lower.includes('show all') || lower.includes('clear filter')) {
    reply = "Showing all scribes."; action = "filter"; actionArg = "all";
  } else if (lower.includes('free scribes') || lower.includes('free volunteers')) {
    reply = "Filtering to free volunteers."; action = "filter"; actionArg = "volunteer";
  } else if (lower.includes('maths') || lower.includes('math')) {
    reply = "Filtering to maths scribes."; action = "filter"; actionArg = "maths";
  } else if (lower.includes('science')) {
    reply = "Filtering to science scribes."; action = "filter"; actionArg = "science";
  } else if (lower.includes('isl') || lower.includes('sign language')) {
    reply = "Filtering to ISL scribes."; action = "filter"; actionArg = "isl";
  } else if (lower.includes('cost') || lower.includes('price') || lower.includes('how much')) {
    reply = "ScribeConnect has free volunteers and paid scribes (₹100–₹1000/hr). Filter by 'free' to see volunteers.";
  } else if (lower.includes('privacy') || lower.includes('safe') || lower.includes('security')) {
    reply = "All profiles are verified. Contact is shared only after mutual consent.";
  } else {
    reply = `I heard: "${transcript}". I can help you find scribes, register as a volunteer, or navigate the site.`;
  }

  return res.status(200).json({ response: reply, action, actionArg });
});

// ── GET /api/config ──────────────────────────────────────────────────────────
app.get('/api/config', (req, res) => {
  return res.json({
    supabaseUrl: process.env.SUPABASE_URL,
    supabaseKey: process.env.SUPABASE_ANON_KEY
  });
});

// ── POST /api/social-login ───────────────────────────────────────────────────
app.post('/api/social-login', async (req, res) => {
  try {
    const { email, full_name, role } = req.body || {};
    const finalEmail = (email || '').trim().toLowerCase();
    const finalName = (full_name || 'Google User').trim();
    const finalRole = (role || 'seeker').trim();

    if (!finalEmail) {
      return res.status(400).json({ error: 'Email is required.' });
    }

    // Check if user exists
    let { data: user, error: fetchErr } = await supabase
      .from('users')
      .select('id, full_name, email')
      .ilike('email', finalEmail)
      .maybeSingle();

    if (fetchErr) {
      console.error('Social login fetch error:', fetchErr);
      return res.status(500).json({ error: `Database query failed: ${fetchErr.message}` });
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
        return res.status(500).json({ error: `Failed to create user account: ${insertErr ? insertErr.message : 'Database error'}` });
      }
      user = newUser;
    }

    const token   = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    const expires = expiresAt30Days();
    const { error: sessionErr } = await supabase.from('sessions').insert({ user_id: user.id, token, expires_at: expires });

    if (sessionErr) {
      console.error('Social login session insert error:', sessionErr);
      return res.status(500).json({ error: `Social login succeeded, but session establishment failed: ${sessionErr.message}` });
    }

    return res.status(200).json({ token, user: { id: user.id, name: user.full_name, email: user.email } });
  } catch (err) {
    console.error('Social login catch block error:', err);
    return res.status(500).json({ error: `Internal server error during social login: ${err.message || err}` });
  }
});

// ── STATIC FILE SERVING ───────────────────────────────────────────────────────
app.get('/style.css', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'style.css'));
});

app.get('/script.js', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'script.js'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// ── EXPORT (NO app.listen — Vercel handles that) ──────────────────────────────
module.exports = app;
