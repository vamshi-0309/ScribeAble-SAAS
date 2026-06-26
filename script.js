

// ── AUTH STATE ────────────────────────
const API = '';  // same origin

function getToken()        { return localStorage.getItem('sc_token'); }
function setToken(t)       { localStorage.setItem('sc_token', t); }
function clearToken()      { localStorage.removeItem('sc_token'); }

let supabaseClient = null;

async function initSupabase() {
  try {
    const res = await fetch('/api/config');
    if (res.ok) {
      const config = await res.json();
      if (config.supabaseUrl && config.supabaseKey) {
        supabaseClient = supabase.createClient(config.supabaseUrl, config.supabaseKey);
        
        // Listen for redirect back from OAuth
        supabaseClient.auth.onAuthStateChange(async (event, session) => {
          if (session && (event === 'SIGNED_IN' || event === 'USER_UPDATED')) {
            const user = session.user;
            try {
              const resLogin = await fetch('/api/social-login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  email: user.email,
                  full_name: user.user_metadata.full_name || user.user_metadata.name || 'Google User',
                  role: currentRole
                })
              });
              if (resLogin.ok) {
                const data = await resLogin.json();
                setToken(data.token);
                launchApp(data.user.name);
                
                // Clear the hash fragment from address bar
                window.history.replaceState({}, document.title, window.location.pathname);
                
                // Sign out of Supabase client session so it doesn't auto-login on reload
                await supabaseClient.auth.signOut();
              } else {
                const errData = await resLogin.json();
                showError(errData.error || 'Failed to link Google account.');
              }
            } catch (e) {
              showError('Server connection error during Google login.');
            }
          }
        });
      }
    }
  } catch (e) {
    console.error('Supabase initialization failed:', e);
  }
}

// ── BOOT: restore session on page load ───
window.addEventListener('DOMContentLoaded', async () => {
  await initSupabase();
  // ── Restore text size from localStorage ──
  const savedSize = localStorage.getItem('sc_textsize') || 'normal';
  applyTextSize(savedSize, false); // false = no TTS on restore

  // Keyboard a11y for role-cards
  document.querySelectorAll('.role-card').forEach(card => {
    card.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); card.click(); }
    });
  });

  // Load voices async (Chrome)
  if ('speechSynthesis' in window) {
    window.speechSynthesis.onvoiceschanged = () => window.speechSynthesis.getVoices();
  }

  // Toast click-to-close
  const toast = document.getElementById('voice-toast');
  if (toast) toast.addEventListener('click', closeToast);

  // Scroll reveal animation using IntersectionObserver
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        revealObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.05 });

  document.querySelectorAll('section, .step-card, .scribe-card, .a11y-card, .stats, .vol-grid').forEach(el => {
    el.classList.add('fade-in-section');
    revealObserver.observe(el);
  });

  // Try to restore session
  const token = getToken();
  if (token) {
    const lp = document.getElementById('login-page');
    if (lp) lp.style.display = 'none';
    try {
      const res = await fetch('/api/me', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      if (res.ok) {
        const { user } = await res.json();
        launchApp(user.name, false); // silent restore – no TTS on reload
        return;
      }
    } catch (e) {}
    // Token invalid – clear it
    clearToken();
  }
  // Show login page
  showLoginPage();
});

function showLoginPage() {
  document.getElementById('login-page').style.display = 'flex';
  document.getElementById('app').style.display = 'none';
}

// ── THEME ─────────────────────────────
let isDark = true;

function toggleTheme() {
  isDark = !isDark;
  const t = isDark ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', t);
  const icon  = isDark ? '🌙' : '☀️';
  const label = isDark ? 'Switch to light mode' : 'Switch to dark mode';
  const ab = document.getElementById('theme-btn-app');
  const lb = document.getElementById('theme-btn-login');
  if (ab) { ab.textContent = icon; ab.setAttribute('aria-label', label); }
  if (lb) { lb.textContent = icon; lb.setAttribute('aria-label', label); }
  speak('Switched to ' + (isDark ? 'dark' : 'light') + ' mode');
}

// ── ROLE / AUTH TAB SWITCHING ─────────
let currentRole = 'seeker';
let currentAuth = 'login';

function switchRole(role) {
  currentRole = role;
  document.getElementById('tab-seeker').classList.toggle('active', role === 'seeker');
  document.getElementById('tab-volunteer').classList.toggle('active', role === 'volunteer');
  speak('You selected: ' + (role === 'seeker' ? 'Person seeking a scribe' : 'Scribe or volunteer'));
}

// ── HELPERS ───────────────────────────
function switchAuth(mode) {
  currentAuth = mode;
  document.getElementById('atab-login').classList.toggle('active', mode === 'login');
  document.getElementById('atab-signup').classList.toggle('active', mode === 'signup');
  document.getElementById('panel-login').classList.toggle('active', mode === 'login');
  document.getElementById('panel-signup').classList.toggle('active', mode === 'signup');
  document.getElementById('auth-switch-text').innerHTML = mode === 'login'
    ? "Don't have an account? <a onclick=\"switchAuth('signup')\" tabindex=\"0\">Create one free</a>"
    : "Already have an account? <a onclick=\"switchAuth('login')\" tabindex=\"0\">Sign in</a>";
  document.getElementById('error-banner').classList.remove('show');
}

function showError(msg) {
  const b = document.getElementById('error-banner');
  if (b) {
    b.textContent = msg;
    b.classList.add('show');
  }
  speak(msg);
}

async function doLogin() {
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-pw').value;
  if (!email || !password) {
    showError('Please enter your email and password.');
    return;
  }
  if (!email.includes('@')) {
    showError('Please enter a valid email address.');
    return;
  }

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    if (res.ok) {
      setToken(data.token);
      launchApp(data.user.name);
    } else {
      showError(data.error || 'Login failed.');
    }
  } catch (err) {
    showError('Unable to connect to server. Please check if the server is running.');
  }
}

async function doSignup() {
  const name = document.getElementById('su-name').value.trim();
  const email = document.getElementById('su-email').value.trim();
  const phone = document.getElementById('su-phone').value.trim();
  const password = document.getElementById('su-pw').value;
  
  if (!name || !email || !password) {
    showError('Please fill in all required fields.');
    return;
  }
  if (!email.includes('@')) {
    showError('Please enter a valid email address.');
    return;
  }
  if (password.length < 8) {
    showError('Password must be at least 8 characters.');
    return;
  }

  try {
    const res = await fetch('/api/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        full_name: name,
        email: email,
        mobile: phone,
        password: password,
        role: currentRole
      })
    });
    const data = await res.json();
    if (res.ok) {
      setToken(data.token);
      launchApp(data.user.name);
    } else {
      showError(data.error || 'Signup failed.');
    }
  } catch (err) {
    showError('Unable to connect to server. Please check if the server is running.');
  }
}

function launchApp(username, announceTTS = true) {
  document.getElementById('login-page').style.display = 'none';
  const app = document.getElementById('app');
  app.style.display = 'block';
  const initials = username.substring(0, 2).toUpperCase();
  document.getElementById('nav-avatar').textContent = initials;
  document.getElementById('nav-username').textContent = username;
  if (announceTTS) {
    speak('Welcome, ' + username + '! You are now signed in to ScribeAble.');
  }
}

async function doLogout() {
  const token = getToken();
  if (token) {
    try {
      await fetch('/api/logout', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token }
      });
    } catch (e) {}
  }
  clearToken();
  document.getElementById('app').style.display = 'none';
  document.getElementById('login-page').style.display = 'flex';
  document.getElementById('login-email').value = '';
  document.getElementById('login-pw').value = '';
  const errBanner = document.getElementById('error-banner');
  if (errBanner) errBanner.classList.remove('show');
  speak('You have been signed out. See you next time.');
}

function togglePw(id, btn) {
  const inp = document.getElementById(id);
  const show = inp.type === 'password';
  inp.type = show ? 'text' : 'password';
  btn.textContent = show ? '🙈' : '👁';
  btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
}

function forgotPw(e) {
  e.preventDefault();
  const email = document.getElementById('login-email').value.trim();
  if (email) speak('A password reset link would be sent to ' + email);
  else speak('Please enter your email address first, then click Forgot Password.');
  alert(email ? 'Password reset link sent to ' + email : 'Please enter your email first.');
}

function socialLogin(type) {
  if (type === 'Google') {
    loginWithGoogle();
  } else {
    speak('Signing in with ' + type + '. Please wait.');
    setTimeout(() => {
      // Demo: show error since OAuth not wired to backend yet
      showError('Social login coming soon. Please use email & password.');
    }, 600);
  }
}

async function loginWithGoogle() {
  if (!supabaseClient) {
    showError('Database connection initializing. Please try again in a moment.');
    return;
  }
  speak('Redirecting to Google Sign-In...');
  const { data, error } = await supabaseClient.auth.signInWithOAuth({
    provider: 'google',
    options: {
      redirectTo: window.location.origin
    }
  });
  if (error) {
    showError(error.message);
  }
}

function voiceLogin() {
  speak('Please say your name to sign in with voice.');
  showToast('Say your name...');
  listenOnce(function (t) {
    closeToast();
    if (t) launchApp(t, true);
  });
}

// ── ACCESSIBILITY ─────────────────────

// Core apply function (used on load + button click)
function applyTextSize(size, announce) {
  // Set data-textsize on <html> so CSS selectors work
  document.documentElement.setAttribute('data-textsize', size);

  // Sync button active states
  ['sz-normal', 'sz-lg', 'sz-xl'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    const matches = (id === 'sz-' + size);
    el.classList.toggle('active', matches);
    el.setAttribute('aria-pressed', String(matches));
  });

  // Save to localStorage so it persists across reloads
  localStorage.setItem('sc_textsize', size);

  if (announce) {
    const label = size === 'normal' ? 'normal' : size === 'lg' ? 'large' : 'extra large';
    speak('Text size set to ' + label);
  }
}

function setTextSize(size) {
  applyTextSize(size, true); // true = announce via TTS
}

function toggleContrast() {
  document.body.classList.toggle('high-contrast');
  const on  = document.body.classList.contains('high-contrast');
  const btn = document.getElementById('btn-contrast');
  if (btn) { btn.classList.toggle('active', on); btn.setAttribute('aria-pressed', String(on)); }
  speak('High contrast ' + (on ? 'on' : 'off'));
}

let activeUtterance = null; // Global to prevent garbage collection in Chrome

// ── TTS ───────────────────────────────
function speak(text, callback) {
  if (!('speechSynthesis' in window)) {
    if (callback) callback();
    return;
  }
  window.speechSynthesis.cancel();
  
  activeUtterance = new SpeechSynthesisUtterance(text);
  activeUtterance.rate  = 0.95; 
  activeUtterance.pitch = 1; 
  activeUtterance.lang = 'en-US';
  
  const voices = window.speechSynthesis.getVoices();
  // Find a natural female voice: Google UK English Female, Microsoft Zira, Samantha, Hazel, etc.
  const preferredFemale = voices.find(v => {
    const name = v.name.toLowerCase();
    const lang = v.lang.toLowerCase();
    return lang.startsWith('en') && (
      name.includes('female') || 
      name.includes('zira') || 
      name.includes('samantha') || 
      name.includes('hazel') || 
      name.includes('google uk english female') || 
      name.includes('natural')
    );
  });
  const fallbackFemale = voices.find(v => v.name.toLowerCase().includes('female'))
                     || voices.find(v => v.lang.startsWith('en'));
  if (preferredFemale) {
    activeUtterance.voice = preferredFemale;
  } else if (fallbackFemale) {
    activeUtterance.voice = fallbackFemale;
  }

  activeUtterance.onstart = () => {
    if (voiceConversationActive) {
      updateVoiceBtnUI('Speaking…');
      updateMicUI(true, 'Speaking…');
      showToast('🔊 Speaking…', 'Speaking…');
    } else {
      updateMicUI(false);
    }
  };

  const handleEnd = () => {
    activeUtterance = null;
    if (voiceConversationActive) {
      // 300ms delay on restart to avoid overlaps as requested
      setTimeout(callback || listenLoop, 300);
    } else {
      updateVoiceBtnUI(false);
      updateMicUI(false);
      closeToast();
    }
  };

  activeUtterance.onend = handleEnd;
  activeUtterance.onerror = handleEnd;

  window.speechSynthesis.speak(activeUtterance);
}

function readPage() {
  const el = document.getElementById('main');
  if (!el) return;
  speak(el.innerText.substring(0, 2000));
  const p = document.getElementById('mic-pulse');
  if (p) p.classList.add('listening');
  const l = document.getElementById('mic-label');
  if (l) l.textContent = 'Reading...';
}

function stopReading() {
  if (window.speechSynthesis) window.speechSynthesis.cancel();
  const p = document.getElementById('mic-pulse');
  if (p) p.classList.remove('listening');
  const l = document.getElementById('mic-label');
  if (l) l.textContent = 'Mic off';
}

// ── VOICE ASSISTANT ───────────────────
// Continuous Conversation Assistant:
// One click starts the session -> listens, thinks, responds, then automatically listens again.
let recognition = null;
let voiceConversationActive = false;

async function processVoiceCommand(transcript) {
  closeToast();
  updateMicUI(false);
  updateVoiceBtnUI('Thinking…');
  showToast('🧠 Thinking…', 'Thinking…');

  try {
    const res = await fetch('/api/assistant', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ transcript })
    });
    if (res.ok) {
      const data = await res.json();
      
      // Perform action if returned
      if (data.action) {
        if (data.action === "openModal") {
          openModal(data.actionArg);
        } else if (data.action === "scrollTo") {
          scrollToSection(data.actionArg);
        } else if (data.action === "theme") {
          if (data.actionArg === "dark" && !isDark) toggleTheme();
          else if (data.actionArg === "light" && isDark) toggleTheme();
        } else if (data.action === "textSize") {
          setTextSize(data.actionArg);
        } else if (data.action === "contrast") {
          toggleContrast();
        } else if (data.action === "readPage") {
          readPage();
        } else if (data.action === "stopReading") {
          stopReading();
        } else if (data.action === "logout") {
          doLogout();
        } else if (data.action === "filter") {
          filterByVoice(data.actionArg);
        } else if (data.action === "closeModal") {
          closeAllModals();
        }
      }

      speak(data.response, listenLoop);
    } else {
      speak("I encountered an error processing your query. Please try again.", listenLoop);
    }
  } catch (err) {
    speak("Sorry, I had trouble connecting. Please check your internet connection.", listenLoop);
  }
}

// Push-to-talk: one click starts the continuous loop
function startVoiceFlow() {
  if (voiceConversationActive) {
    stopVoiceAssistant();
    return;
  }

  if (!('webkitSpeechRecognition' in window || 'SpeechRecognition' in window)) {
    speak('Voice recognition requires Google Chrome browser.');
    return;
  }

  voiceConversationActive = true;
  speak('Voice assistant active. How can I help you today?', listenLoop);
}

function listenLoop() {
  if (!voiceConversationActive) return;

  // Fully stop recognition before restarting
  if (recognition) {
    try {
      recognition.onend = null;
      recognition.onerror = null;
      recognition.onresult = null;
      recognition.stop();
    } catch (e) {}
  }

  // Small delay before starting again to ensure clean mic state
  setTimeout(() => {
    if (!voiceConversationActive) return;

    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    recognition = new SR();
    recognition.lang = 'en-IN';
    recognition.continuous = false; // single session for accurate end-of-speech detection
    recognition.interimResults = false;
    recognition.maxAlternatives = 1;

    updateMicUI(true, 'Listening…');
    updateVoiceBtnUI('Listening…');
    showToast('🎙️ Listening… speak now', 'Listening…');

    recognition.onresult = e => {
      if (!voiceConversationActive) return;
      const transcript = e.results[0][0].transcript;
      updateMicUI(false);
      updateVoiceBtnUI('Thinking…');
      showToast('🧠 Thinking…', 'Thinking…');
      
      setTimeout(() => {
        if (voiceConversationActive) {
          processVoiceCommand(transcript);
        }
      }, 350);
    };

    recognition.onerror = err => {
      if (!voiceConversationActive) return;
      updateMicUI(false);
      if (err.error === 'no-speech') {
        // Silence detected -> silently restart listening immediately
        listenLoop();
      } else if (err.error === 'not-allowed') {
        speak('Microphone access denied. Please allow microphone permission in your browser.', stopVoiceAssistant);
      } else {
        // Silently retry in 300ms
        setTimeout(() => {
          if (voiceConversationActive) listenLoop();
        }, 300);
      }
    };

    recognition.onend = () => {
      // Natural end of recognition without result/error -> restart loop
      setTimeout(() => {
        if (voiceConversationActive && !window.speechSynthesis.speaking) {
          const btn = document.getElementById('voice-main-btn');
          if (btn && !btn.classList.contains('thinking') && !btn.classList.contains('speaking')) {
            listenLoop();
          }
        }
      }, 300);
    };

    try {
      recognition.start();
    } catch (e) {
      setTimeout(() => {
        if (voiceConversationActive) listenLoop();
      }, 400);
    }
  }, 100);
}

function stopVoiceAssistant() {
  voiceConversationActive = false;
  if (window.speechSynthesis) window.speechSynthesis.cancel();
  if (recognition) {
    try {
      recognition.onend = null;
      recognition.onerror = null;
      recognition.onresult = null;
      recognition.stop();
    } catch (e) {}
  }
  updateMicUI(false);
  updateVoiceBtnUI(false);
  closeToast();
  speak('Voice assistant stopped.');
}

function voiceFill(target) {
  const msgs = {
    support : "Say your support needs. E.g.: I need writing help and questions read aloud.",
    exam    : "Say your exam details. E.g.: Physics exam on 20th September at 9am, 3 hours.",
    location: "Say your location. E.g.: Banjara Hills, Hyderabad, pincode 500034."
  };
  speak(msgs[target]);
  const ids = { support: 'voice-step1', exam: 'voice-step2', location: 'voice-step3' };
  const btn = document.getElementById(ids[target]);
  if (btn) { btn.classList.add('listening'); btn.textContent = '🔴 Listening...'; }
  showToast(msgs[target]);
  listenOnce(function (t) {
    if (btn) { btn.classList.remove('listening'); btn.textContent = '🎙️ Fill by Voice'; }
    closeToast();
    if (target === 'location') {
      document.getElementById('exam-location').value = t;
      const pin = t.match(/\b\d{6}\b/);
      if (pin) document.getElementById('exam-pincode').value = pin[0];
    }
    if (target === 'exam') {
      const subjects = ['maths','physics','chemistry','biology','english','hindi','telugu'];
      const sel = document.getElementById('exam-subject');
      subjects.forEach(s => {
        if (t.toLowerCase().includes(s)) {
          for (let i = 0; i < sel.options.length; i++) {
            if (sel.options[i].text.toLowerCase().includes(s)) { sel.selectedIndex = i; break; }
          }
        }
      });
    }
    speak('Got it. Please check and tap Next.');
  });
}

function updateMicUI(active, state) {
  const p = document.getElementById('mic-pulse');
  const l = document.getElementById('mic-label');
  if (!p || !l) return;
  p.classList.remove('listening', 'thinking', 'speaking');
  if (active) {
    if (state === 'Listening…') {
      p.classList.add('listening');
      l.textContent = 'Listening…';
    } else if (state === 'Thinking…') {
      p.classList.add('thinking');
      l.textContent = 'Thinking…';
    } else if (state === 'Speaking…') {
      p.classList.add('speaking');
      l.textContent = 'Speaking…';
    } else {
      p.classList.add('listening');
      l.textContent = 'Listening…';
    }
  } else {
    l.textContent = 'Mic off';
  }
}

function updateVoiceBtnUI(state) {
  const btn = document.getElementById('voice-main-btn');
  if (!btn) return;
  if (state === 'Listening…') {
    btn.className = 'voice-big-btn listening';
    btn.textContent = '🔴 Listening… (tap to stop)';
  } else if (state === 'Thinking…') {
    btn.className = 'voice-big-btn thinking';
    btn.textContent = '🧠 Thinking… (tap to stop)';
  } else if (state === 'Speaking…') {
    btn.className = 'voice-big-btn speaking';
    btn.textContent = '🔊 Speaking… (tap to stop)';
  } else {
    btn.className = 'voice-big-btn';
    btn.textContent = '🎙️ Use Voice Assistant';
  }
}

// ── SINGLE-SHOT LISTENER (for voiceFill + voiceLogin) ────
// Separate from push-to-talk; used for inline form filling only.
function listenOnce(cb) {
  if (!('webkitSpeechRecognition' in window || 'SpeechRecognition' in window)) {
    speak('Voice recognition requires Google Chrome.');
    closeToast(); return;
  }
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  const r  = new SR();
  r.lang = 'en-IN';
  r.continuous = false;
  r.interimResults = false;
  r.onresult = e => { cb(e.results[0][0].transcript); };
  r.onerror  = ()  => { updateMicUI(false); speak('Could not hear you. Try again.'); closeToast(); };
  r.onend    = ()  => { updateMicUI(false); };
  updateMicUI(true);
  try { r.start(); } catch(e) {}
}

function voiceHelp() {
  speak('Available commands: Find scribe, Volunteer, How it works, Filter maths, Filter science, ISL, Free volunteers, Dark mode, Light mode, Large text, High contrast, Read page, Stop, Sign out, Help.');
  showToast('Say a command or "help" for options');
}

function filterByVoice(tag) {
  const chips = document.querySelectorAll('.filter-chip');
  chips.forEach(c => { c.classList.remove('active'); c.setAttribute('aria-pressed','false'); });
  const target = Array.from(chips).find(c => {
    const oc = c.getAttribute('onclick') || '';
    return tag === 'all' ? oc.includes("'all'") : oc.includes("'" + tag + "'");
  });
  if (target) { target.classList.add('active'); target.setAttribute('aria-pressed','true'); }
  document.querySelectorAll('.scribe-card').forEach(card => {
    card.style.display = (tag === 'all' || card.dataset.tags.includes(tag)) ? '' : 'none';
  });
  speak(tag === 'all' ? 'Showing all scribes.' : 'Filtered by ' + tag + '.');
}

function closeAllModals() {
  ['modal-seeker','modal-volunteer','modal-confirm'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.remove('open');
  });
  document.body.style.overflow = '';
  speak('Closed.');
}

// ── TOAST ─────────────────────────────
function showToast(msg, state) {
  const t = document.getElementById('voice-toast');
  if (!t) return;
  document.getElementById('toast-msg').textContent = msg;
  t.classList.add('show');
  t.classList.remove('listening', 'thinking', 'speaking');
  if (state === 'Listening…') t.classList.add('listening');
  else if (state === 'Thinking…') t.classList.add('thinking');
  else if (state === 'Speaking…') t.classList.add('speaking');
}
function closeToast() {
  const t = document.getElementById('voice-toast');
  if (t) t.classList.remove('show', 'listening', 'thinking', 'speaking');
}

// ── GPS ───────────────────────────────
function getGPS() {
  if (!navigator.geolocation) { speak('GPS not available.'); return; }
  speak('Detecting your location...');
  navigator.geolocation.getCurrentPosition(
    pos => {
      document.getElementById('exam-location').value = 'Detected via GPS';
      speak('Location detected. Nearby scribes will be shown.');
    },
    () => { speak('Could not detect location. Please type your area.'); }
  );
}

// ── PRICE ─────────────────────────────
function updatePrice(val) { document.getElementById('price-display').textContent = 'Up to ₹' + val + ' / hour'; }
function toggleFreeOnly(cb) {
  const s = document.getElementById('budget-section');
  s.style.opacity      = cb.checked ? '.3' : '1';
  s.style.pointerEvents = cb.checked ? 'none' : 'auto';
}

// ── MODALS ────────────────────────────
function openModal(type) {
  const el = document.getElementById('modal-' + type);
  if (!el) return;
  el.classList.add('open');
  document.body.style.overflow = 'hidden';
  if (type === 'seeker')    speak('Find your scribe. Step 1: Tell us what kind of support you need.');
  if (type === 'volunteer') speak('Register as a scribe. Step 1: Choose your type.');
}
function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('open');
  document.body.style.overflow = '';
}
function closeModalOnBg(e, id) { if (e.target === document.getElementById(id)) closeModal(id); }

// ── SEEKER STEPS ──────────────────────
let seekerCurrent = 1;

function seekerStep(n) {
  if (n === 5) fillReview();
  const cur  = document.getElementById('seeker-step-' + seekerCurrent);
  const next = document.getElementById('seeker-step-' + n);
  if (cur)  cur.classList.remove('active');
  if (next) next.classList.add('active');
  ['sdot-1','sdot-2','sdot-3','sdot-4','sdot-5'].forEach((id, i) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('done','active');
    if (i + 1 < n) el.classList.add('done');
    else if (i + 1 === n) el.classList.add('active');
  });
  seekerCurrent = n;
  const labels = ['','Tell us what support you need','Exam details','Your location and language','Set your budget','Review and submit'];
  if (labels[n]) speak(labels[n]);
}

function fillReview() {
  const needs = [];
  ['need-write','need-read','need-isl','need-motor','need-visual','need-cognitive'].forEach(id => {
    const el = document.getElementById(id);
    if (el && el.checked) { const sp = el.parentElement.querySelector('span'); if (sp) needs.push(sp.textContent.replace(/^\S+\s/,'')); }
  });
  document.getElementById('rev-support').textContent  = needs.length ? needs.join(', ') : 'Not specified';
  document.getElementById('rev-subject').textContent  = document.getElementById('exam-subject').value || 'Not specified';
  const d = document.getElementById('exam-date').value;
  const t = document.getElementById('exam-time').value;
  document.getElementById('rev-datetime').textContent = (d && t) ? d + ' at ' + t : d || t || 'Not specified';
  document.getElementById('rev-location').textContent = (document.getElementById('exam-location').value || 'Not specified') + ', ' + document.getElementById('exam-city').value;
  document.getElementById('rev-lang').textContent     = document.getElementById('pref-lang').value;
  document.getElementById('rev-budget').textContent   = document.getElementById('free-only').checked ? 'Free volunteers only' : 'Up to ₹' + document.getElementById('budget-slider').value + '/hr';
}

function submitRequest() {
  speak('Your request has been submitted. 4 nearby scribes have been notified.');
  seekerStep(6);
}

// ── VOLUNTEER STEPS ───────────────────
let volCurrent = 1;

function volStep(n) {
  const cur  = document.getElementById('vol-step-' + volCurrent);
  const next = document.getElementById('vol-step-' + n);
  if (cur)  cur.classList.remove('active');
  if (next) next.classList.add('active');
  ['vdot-1','vdot-2','vdot-3'].forEach((id, i) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('done','active');
    if (i + 1 < n) el.classList.add('done');
    else if (i + 1 === n) el.classList.add('active');
  });
  volCurrent = n;
  if (n === 3) speak('Registration complete! Thank you for joining ScribeConnect.');
}

function selectVolType(el, type) {
  document.querySelectorAll('.role-card').forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
  speak(type === 'free' ? 'Free Volunteer selected.' : 'Paid Scribe selected.');
}

// ── FILTER SCRIBES ────────────────────
function filterScribes(tag, btn) {
  document.querySelectorAll('.filter-chip').forEach(c => {
    c.classList.remove('active'); c.setAttribute('aria-pressed','false');
  });
  if (btn) { btn.classList.add('active'); btn.setAttribute('aria-pressed','true'); }
  document.querySelectorAll('.scribe-card').forEach(card => {
    card.style.display = (tag === 'all' || card.dataset.tags.includes(tag)) ? '' : 'none';
  });
  speak(tag === 'all' ? 'Showing all scribes.' : 'Filtered by ' + tag + '.');
}

// ── REQUEST CONFIRM ───────────────────
function openRequestConfirm(name, price, area) {
  document.getElementById('confirm-body').innerHTML = `
    <div class="success-screen" style="padding:20px 0">
      <div class="success-icon" style="font-size:46px">🤝</div>
      <div class="success-title" style="font-size:19px">Request ${name}?</div>
      <p class="success-sub" style="font-size:13px">Your contact details will only be shared after ${name} accepts.</p>
      <div class="confirmation-card" style="margin:14px 0">
        <div class="conf-row"><span class="conf-label">Scribe</span><span class="conf-value">${name}</span></div>
        <div class="conf-row"><span class="conf-label">Location</span><span class="conf-value">${area}</span></div>
        <div class="conf-row"><span class="conf-label">Rate</span><span class="conf-value" style="color:var(--teal)">${price}</span></div>
        <div class="conf-row"><span class="conf-label">Privacy</span><span class="conf-value">Shared only on acceptance</span></div>
      </div>
      <button class="btn-submit" onclick="confirmRequest('${name}')">Send Request →</button>
      <button class="btn-back" style="margin-top:10px;width:100%;text-align:center;padding:9px" onclick="closeModal('modal-confirm')">Cancel</button>
    </div>`;
  openModal('confirm');
  speak('Confirm request to ' + name + '. Rate is ' + price + '.');
}

function confirmRequest(name) {
  document.getElementById('confirm-body').innerHTML = `
    <div class="success-screen" style="padding:20px 0">
      <div class="success-icon" style="font-size:52px">✅</div>
      <div class="success-title">Request Sent!</div>
      <p class="success-sub">${name} has been notified. Contact details shared once they accept.</p>
      <button class="btn-primary" style="width:100%;justify-content:center;margin-top:14px" onclick="closeModal('modal-confirm')">Done ✓</button>
    </div>`;
  speak('Your request has been sent to ' + name + '.');
}

// ── SCROLL ────────────────────────────
function scrollToSection(id) {
  const el = document.querySelector(id);
  if (el) el.scrollIntoView({ behavior: 'smooth' });
}
