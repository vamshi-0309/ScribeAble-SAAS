// Local development only — Vercel does NOT use this file
// Vercel serves static files from root and runs api/server.js for /api/*
if (require.main === module) {
  require('./api/server.js');
}
