// Local development only — not used by Vercel
const app  = require('./api/index.js');
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 ScribeConnect running at http://localhost:${PORT}`);
  console.log('   API: /api/signup  /api/login  /api/me  /api/logout\n');
});
