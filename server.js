// Stub pointing to the correct api/server.js location for local running
const path = require('path');
const handler = require('./api/server.js');

if (require.main === module) {
  // If run directly (e.g. node server.js or npm start), start the server
  const http = require('http');
  const PORT = 3000;
  
  // Note: the handler will initialize its DB inside api/server.js
  const server = http.createServer(handler);
  server.listen(PORT, () => {
    console.log(`\n🚀 ScribeConnect server running at http://localhost:${PORT}`);
  });
} else {
  module.exports = handler;
}
