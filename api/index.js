// BUG HUNT — Vercel serverless entry point.
// Vercel only builds files under /api/ as functions, so this thin wrapper
// re-exports the Express app defined in ../server.js (local `npm start`
// still runs server.js directly — nothing changes locally).
module.exports = require('../server.js');
