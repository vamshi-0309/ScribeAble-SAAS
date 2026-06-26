// Delegates to api/server.js for local dev (npm start)
// Also exports the handler so Vercel can use this file if it picks it up
const handler = require('./api/server.js');
module.exports = handler;
