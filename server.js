/* BUG HUNT server — Express + file JSON store (Postgres schema in schema.sql)
 * Core rule: 2 members -> 1 team -> 1 login -> 1 shared score.
 * Security: team APIs never leak solution_code / test case I/O / leaderboard / other teams.
 * Code execution: real sandboxed-ish execution for Python & JavaScript (timeout, output
 * caps, no network in child env). C/C++/Java use a clearly-labelled DEMO mock evaluator
 * unless MOCK_NON_PYTHON=false and toolchains exist. Never runs on "main server" blindly:
 * child processes with timeouts + vm contexts with timeouts.
 */
require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { spawn } = require('child_process');
const vm = require('vm');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me-32-chars-min';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '12h';
const EXEC_TIMEOUT_MS = parseInt(process.env.EXEC_TIMEOUT_MS || '5000', 10);
const MOCK_NON_PYTHON = (process.env.MOCK_NON_PYTHON || 'true') === 'true';

// Vercel serverless filesystem is read-only except /tmp.
// Locally use ./data/db.json, on Vercel use /tmp/bughunt-db.json (ephemeral)
// + in-memory fallback so UI never crashes with EROFS.
const IS_VERCEL = !!process.env.VERCEL;

// Resolve the writable data directory robustly. Depending on how the serverless
// bundle is assembled, files may sit relative to __dirname, process.cwd(), or a
// parent folder — so try each candidate and fall back to a freshly-created ./data.
function resolveDir(candidatePaths, fallback) {
  for (const p of candidatePaths) {
    try { if (fs.statSync(p).isDirectory()) return p; } catch {}
  }
  try { fs.mkdirSync(fallback, { recursive: true }); return fallback; } catch {}
  return fallback;
}
const DATA_DIR = IS_VERCEL ? require('os').tmpdir() : resolveDir(
  [path.join(__dirname, 'data'), path.join(process.cwd(), 'data'), path.join(__dirname, '..', 'data')],
  path.join(__dirname, 'data')
);
const DB_FILE = path.join(DATA_DIR, IS_VERCEL ? 'bughunt-db.json' : 'db.json');
try {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
} catch (e) { console.warn('DATA_DIR init skipped:', e.message); }

// Resolve the static frontend folder the same way. This is the classic "localhost
// works, Vercel 404s" trap: inside the serverless function the static assets may
// live under __dirname/public, process.cwd()/public or one directory up, so we
// must not hard-code a single base.
const PUBLIC_DIR = resolveDir(
  [path.join(__dirname, 'public'), path.join(process.cwd(), 'public'), path.join(__dirname, '..', 'public')],
  path.join(__dirname, 'public')
);

const uid = (p = 'id') => p + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
const nowISO = () => new Date().toISOString();
const norm = (s) => String(s == null ? '' : s).trim();
const normOut = (s) => String(s == null ? '' : s).replace(/\r\n/g, '\n').split('\n').map((l) => l.trimEnd()).join('\n').trim();

function defaultDB() {
  return {
    users: [], teams: [], members: [], questions: [],
    testcases: [], submissions: [], attempts: [],
    settings: {
      event_name: 'BUG HUNT',
      description: 'A competitive debugging challenge where two-member teams test their coding skills by finding and fixing bugs.',
      registration_start: null, registration_end: null,
      event_start: null, event_end: null,
      max_team_size: 2, allow_multiple_submissions: true,
      allow_profile_edit: false, status: 'live',
    },
  };
}
function loadDB() {
  try {
    if (!fs.existsSync(DB_FILE)) { const d = defaultDB(); try { fs.writeFileSync(DB_FILE, JSON.stringify(d, null, 2)); } catch {} return d; }
    const d = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    return Object.assign(defaultDB(), d);
  } catch { return defaultDB(); }
}
let db = loadDB();
function save() {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
  catch (e) { console.warn('DB save skipped (ephemeral FS):', e.message); }
}

// ---------- storage (file JSON <-> PostgreSQL) ----------
// File mode (default, no DATABASE_URL): local JSON store — localhost/event laptop.
// PG mode (DATABASE_URL set, e.g. Neon on Vercel): EVERY read/write goes to the
// shared Postgres database, so all serverless instances see the SAME data and
// teams/questions NEVER vanish on refresh, cold start or redeploy.
// Row shapes are identical in both modes; ids stay opaque strings.
const USE_PG = !!process.env.DATABASE_URL;
const { randomUUID } = require('crypto');
const newId = (p = 'id') => (USE_PG ? randomUUID() : uid(p));
let pgPool = null;
function getPool() {
  if (pgPool) return pgPool;
  const url = process.env.DATABASE_URL;
  if (url.startsWith('pgmem://')) {
    // TEST ONLY: in-memory Postgres emulator (npm i --no-save pg-mem). Never used in prod.
    const { newDb } = require('pg-mem');
    const { Pool } = newDb().adapters.createPg();
    pgPool = new Pool();
  } else {
    const { Pool } = require('pg');
    pgPool = new Pool({ connectionString: url, ssl: { rejectUnauthorized: false }, max: 3, idleTimeoutMillis: 15000 });
  }
  return pgPool;
}
// Portable DDL (no extensions): TEXT ids/timestamps keep row shapes identical to file mode.
const PG_DDL = [
  `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT '')`,
  `CREATE TABLE IF NOT EXISTS teams (id TEXT PRIMARY KEY, team_name TEXT NOT NULL, login_email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, college TEXT NOT NULL DEFAULT '', department TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL DEFAULT '')`,
  `CREATE TABLE IF NOT EXISTS team_members (id TEXT PRIMARY KEY, team_id TEXT NOT NULL, member_number INT NOT NULL, full_name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL, college TEXT NOT NULL, department TEXT NOT NULL, year TEXT NOT NULL, UNIQUE(team_id, member_number))`,
  `CREATE TABLE IF NOT EXISTS questions (id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, language TEXT NOT NULL, difficulty TEXT NOT NULL, points INT NOT NULL, buggy_code TEXT NOT NULL, solution_code TEXT NOT NULL, time_limit INT NOT NULL DEFAULT 20, status TEXT NOT NULL DEFAULT 'draft', created_at TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '')`,
  `CREATE TABLE IF NOT EXISTS test_cases (id TEXT PRIMARY KEY, question_id TEXT NOT NULL, input_data TEXT NOT NULL DEFAULT '', expected_output TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '')`,
  `CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, team_id TEXT NOT NULL, question_id TEXT NOT NULL, started_at TEXT NOT NULL DEFAULT '', UNIQUE(team_id, question_id))`,
  `CREATE TABLE IF NOT EXISTS submissions (id TEXT PRIMARY KEY, team_id TEXT NOT NULL, question_id TEXT NOT NULL, submitted_code TEXT NOT NULL, passed_tests INT NOT NULL DEFAULT 0, total_tests INT NOT NULL DEFAULT 0, score INT NOT NULL DEFAULT 0, execution_time INT NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'Failed', submitted_at TEXT NOT NULL DEFAULT '')`,
  `CREATE TABLE IF NOT EXISTS event_settings (id INT PRIMARY KEY, event_name TEXT NOT NULL DEFAULT 'BUG HUNT', description TEXT NOT NULL DEFAULT '', registration_start TEXT, registration_end TEXT, event_start TEXT, event_end TEXT, max_team_size INT NOT NULL DEFAULT 2, allow_multiple_submissions BOOLEAN NOT NULL DEFAULT true, allow_profile_edit BOOLEAN NOT NULL DEFAULT false, status TEXT NOT NULL DEFAULT 'live')`,
];
async function pgInit() {
  const pool = getPool();
  let lastErr = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await pool.query(PG_DDL.join(';\n')); // single round-trip: faster cold starts (10s serverless limit)
      const s = await pool.query('SELECT * FROM event_settings WHERE id = 1');
      if (!s.rows.length) {
        await pool.query(`INSERT INTO event_settings (id, event_name, description, max_team_size, allow_multiple_submissions, allow_profile_edit, status) VALUES (1,'BUG HUNT','A competitive debugging challenge where two-member teams test their coding skills by finding and fixing bugs.',2,true,false,'live')`);
      }
      return;
    } catch (e) { lastErr = e; await new Promise((r) => setTimeout(r, 1000)); }
  }
  throw new Error('Postgres init failed (DATABASE_URL unreachable?): ' + (lastErr && lastErr.message));
}
// Row mappers: timestamptz may come back as Date (real pg) or string (file/pg-mem) — normalize to ISO strings.
const S = (v) => (v === null || v === undefined ? null : (v instanceof Date ? v.toISOString() : String(v)));
const N = (v, d = 0) => { const n = Number(v); return Number.isFinite(n) ? n : d; };
const B = (v) => !!v;
const mapSettings = (r) => r ? ({ event_name: r.event_name, description: r.description, registration_start: S(r.registration_start), registration_end: S(r.registration_end), event_start: S(r.event_start), event_end: S(r.event_end), max_team_size: N(r.max_team_size, 2), allow_multiple_submissions: B(r.allow_multiple_submissions), allow_profile_edit: B(r.allow_profile_edit), status: r.status }) : null;
const mapTeam = (r) => r && ({ id: String(r.id), team_name: r.team_name, login_email: r.login_email, password_hash: r.password_hash, college: r.college || '', department: r.department || '', status: r.status, created_at: S(r.created_at) });
const mapMember = (r) => r && ({ id: String(r.id), team_id: String(r.team_id), member_number: N(r.member_number), full_name: r.full_name, email: r.email, phone: r.phone, college: r.college, department: r.department, year: r.year });
const mapQuestion = (r) => r && ({ id: String(r.id), title: r.title, description: r.description, language: r.language, difficulty: r.difficulty, points: N(r.points), buggy_code: r.buggy_code, solution_code: r.solution_code, time_limit: N(r.time_limit, 20), status: r.status, created_at: S(r.created_at), updated_at: S(r.updated_at) });
const mapTestCase = (r) => r && ({ id: String(r.id), question_id: String(r.question_id), input_data: r.input_data ?? '', expected_output: r.expected_output ?? '', created_at: S(r.created_at) });
const mapAttempt = (r) => r && ({ id: String(r.id), team_id: String(r.team_id), question_id: String(r.question_id), started_at: S(r.started_at) });
const mapSubmission = (r) => r && ({ id: String(r.id), team_id: String(r.team_id), question_id: String(r.question_id), submitted_code: r.submitted_code, passed_tests: N(r.passed_tests), total_tests: N(r.total_tests), score: N(r.score), execution_time: N(r.execution_time), status: r.status, submitted_at: S(r.submitted_at) });

const fileStore = {
  settings: async () => db.settings,
  updateSettings: async (patch) => { Object.assign(db.settings, patch); save(); return db.settings; },
  findAdmin: async (email) => db.users.find((u) => u.email === email && u.role === 'ADMIN') || null,
  createAdmin: async (row) => { db.users.push(row); save(); return row; },
  teamById: async (id) => db.teams.find((t) => t.id === id) || null,
  teamByLogin: async (em) => db.teams.find((x) => x.login_email === em) || null,
  teamNameTaken: async (nameLower, excludeId) => !!db.teams.find((t) => t.team_name.toLowerCase() === nameLower && t.id !== excludeId),
  allTeams: async () => [...db.teams],
  createTeam: async (row) => { db.teams.push(row); save(); return row; },
  setTeamStatus: async (id, status) => { const t = db.teams.find((x) => x.id === id); if (t) { t.status = status; save(); } return t || null; },
  setTeamName: async (id, name) => { const t = db.teams.find((x) => x.id === id); if (t) { t.team_name = name; save(); } return t || null; },
  membersByTeam: async (tid) => db.members.filter((m) => m.team_id === tid).sort((a, b) => a.member_number - b.member_number),
  allMemberPhones: async () => db.members.map((m) => m.phone),
  createMembers: async (rows) => { db.members.push(...rows); save(); return rows; },
  questionById: async (id) => db.questions.find((x) => x.id === id) || null,
  allQuestions: async () => [...db.questions],
  createQuestion: async (row) => { db.questions.push(row); save(); return row; },
  updateQuestion: async (id, fields) => { const q = db.questions.find((x) => x.id === id); if (q) { Object.assign(q, fields); save(); } return q || null; },
  deleteQuestion: async (id) => { db.questions = db.questions.filter((x) => x.id !== id); db.testcases = db.testcases.filter((t) => t.question_id !== id); save(); },
  testCasesByQuestion: async (qid) => db.testcases.filter((t) => t.question_id === qid),
  addTestCase: async (row) => { db.testcases.push(row); save(); return row; },
  deleteTestCasesByQuestion: async (qid) => { db.testcases = db.testcases.filter((t) => t.question_id !== qid); save(); },
  attemptByTeamQuestion: async (tid, qid) => db.attempts.find((a) => a.team_id === tid && a.question_id === qid) || null,
  createAttempt: async (row) => { db.attempts.push(row); save(); return row; },
  submissionsByTeam: async (tid) => db.submissions.filter((s) => s.team_id === tid).sort((a, b) => b.submitted_at.localeCompare(a.submitted_at)),
  allSubmissions: async () => [...db.submissions].sort((a, b) => b.submitted_at.localeCompare(a.submitted_at)),
  acceptedSubmission: async (tid, qid) => db.submissions.find((s) => s.team_id === tid && s.question_id === qid && s.status === 'Accepted') || null,
  createSubmission: async (row) => { db.submissions.push(row); save(); return row; },
};
const pgStore = {
  settings: async () => mapSettings((await getPool().query('SELECT * FROM event_settings WHERE id = 1')).rows[0]),
  updateSettings: async (patch) => {
    const keys = Object.keys(patch);
    if (!keys.length) return pgStore.settings();
    const set = keys.map((k, i) => `${k} = $${i + 1}`).join(', ');
    await getPool().query(`UPDATE event_settings SET ${set} WHERE id = 1`, keys.map((k) => patch[k]));
    return pgStore.settings();
  },
  findAdmin: async (email) => { const r = await getPool().query(`SELECT * FROM users WHERE LOWER(email) = LOWER($1) AND role = 'ADMIN'`, [email]); const u = r.rows[0]; return u ? ({ id: String(u.id), email: u.email, password_hash: u.password_hash, role: u.role, created_at: S(u.created_at) }) : null; },
  createAdmin: async (row) => { await getPool().query(`INSERT INTO users (id, email, password_hash, role, created_at) VALUES ($1,$2,$3,$4,$5)`, [row.id, row.email, row.password_hash, row.role, row.created_at]); return row; },
  teamById: async (id) => { const r = await getPool().query('SELECT * FROM teams WHERE id = $1', [id]); return mapTeam(r.rows[0]) || null; },
  teamByLogin: async (em) => { const r = await getPool().query('SELECT * FROM teams WHERE LOWER(login_email) = LOWER($1)', [em]); return mapTeam(r.rows[0]) || null; },
  teamNameTaken: async (nameLower, excludeId) => { const r = await getPool().query('SELECT id FROM teams WHERE LOWER(team_name) = LOWER($1) AND id <> $2', [nameLower, excludeId || '']); return r.rows.length > 0; },
  allTeams: async () => (await getPool().query('SELECT * FROM teams ORDER BY created_at ASC')).rows.map(mapTeam),
  createTeam: async (row) => { await getPool().query(`INSERT INTO teams (id, team_name, login_email, password_hash, college, department, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, [row.id, row.team_name, row.login_email, row.password_hash, row.college, row.department, row.status, row.created_at]); return row; },
  setTeamStatus: async (id, status) => { await getPool().query('UPDATE teams SET status = $1 WHERE id = $2', [status, id]); return pgStore.teamById(id); },
  setTeamName: async (id, name) => { await getPool().query('UPDATE teams SET team_name = $1 WHERE id = $2', [name, id]); return pgStore.teamById(id); },
  membersByTeam: async (tid) => (await getPool().query('SELECT * FROM team_members WHERE team_id = $1 ORDER BY member_number ASC', [tid])).rows.map(mapMember),
  allMemberPhones: async () => (await getPool().query('SELECT phone FROM team_members')).rows.map((r) => r.phone),
  createMembers: async (rows) => { for (const m of rows) await getPool().query(`INSERT INTO team_members (id, team_id, member_number, full_name, email, phone, college, department, year) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [m.id, m.team_id, m.member_number, m.full_name, m.email, m.phone, m.college, m.department, m.year]); return rows; },
  questionById: async (id) => { const r = await getPool().query('SELECT * FROM questions WHERE id = $1', [id]); return mapQuestion(r.rows[0]) || null; },
  allQuestions: async () => (await getPool().query('SELECT * FROM questions ORDER BY created_at ASC')).rows.map(mapQuestion),
  createQuestion: async (row) => { await getPool().query(`INSERT INTO questions (id, title, description, language, difficulty, points, buggy_code, solution_code, time_limit, status, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, [row.id, row.title, row.description, row.language, row.difficulty, row.points, row.buggy_code, row.solution_code, row.time_limit, row.status, row.created_at, row.updated_at]); return row; },
  updateQuestion: async (id, fields) => {
    const keys = Object.keys(fields);
    if (keys.length) { const set = keys.map((k, i) => `${k} = $${i + 1}`).join(', '); await getPool().query(`UPDATE questions SET ${set} WHERE id = $${keys.length + 1}`, [...keys.map((k) => fields[k]), id]); }
    return pgStore.questionById(id);
  },
  deleteQuestion: async (id) => { await getPool().query('DELETE FROM test_cases WHERE question_id = $1', [id]); await getPool().query('DELETE FROM questions WHERE id = $1', [id]); },
  testCasesByQuestion: async (qid) => (await getPool().query('SELECT * FROM test_cases WHERE question_id = $1 ORDER BY created_at ASC', [qid])).rows.map(mapTestCase),
  addTestCase: async (row) => { await getPool().query(`INSERT INTO test_cases (id, question_id, input_data, expected_output, created_at) VALUES ($1,$2,$3,$4,$5)`, [row.id, row.question_id, row.input_data, row.expected_output, row.created_at]); return row; },
  deleteTestCasesByQuestion: async (qid) => { await getPool().query('DELETE FROM test_cases WHERE question_id = $1', [qid]); },
  attemptByTeamQuestion: async (tid, qid) => { const r = await getPool().query('SELECT * FROM attempts WHERE team_id = $1 AND question_id = $2', [tid, qid]); return mapAttempt(r.rows[0]) || null; },
  createAttempt: async (row) => { await getPool().query(`INSERT INTO attempts (id, team_id, question_id, started_at) VALUES ($1,$2,$3,$4)`, [row.id, row.team_id, row.question_id, row.started_at]); return row; },
  submissionsByTeam: async (tid) => (await getPool().query('SELECT * FROM submissions WHERE team_id = $1 ORDER BY submitted_at DESC', [tid])).rows.map(mapSubmission),
  allSubmissions: async () => (await getPool().query('SELECT * FROM submissions ORDER BY submitted_at DESC')).rows.map(mapSubmission),
  acceptedSubmission: async (tid, qid) => { const r = await getPool().query(`SELECT * FROM submissions WHERE team_id = $1 AND question_id = $2 AND status = 'Accepted' LIMIT 1`, [tid, qid]); return mapSubmission(r.rows[0]) || null; },
  createSubmission: async (row) => { await getPool().query(`INSERT INTO submissions (id, team_id, question_id, submitted_code, passed_tests, total_tests, score, execution_time, status, submitted_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [row.id, row.team_id, row.question_id, row.submitted_code, row.passed_tests, row.total_tests, row.score, row.execution_time, row.status, row.submitted_at]); return row; },
};
const store = USE_PG ? pgStore : fileStore;

// ---------- seed ----------
async function seed() {
  const adminEmail = norm(process.env.DEMO_ADMIN_EMAIL || 'admin@bughunt.com').toLowerCase();
  const adminPass = process.env.DEMO_ADMIN_PASSWORD || 'admin123';
  if (USE_PG) {
    await pgInit();
    console.log('BUG HUNT storage: PostgreSQL (shared — survives refresh/cold-start/redeploy)');
    if (!(await store.findAdmin(adminEmail))) {
      await store.createAdmin({ id: randomUUID(), email: adminEmail, password_hash: await bcrypt.hash(adminPass, 10), role: 'ADMIN', created_at: nowISO() });
    }
    return;
  }
  console.log('BUG HUNT storage: local JSON file');
  let changed = false;
  if (!db.users.find((u) => u.email === adminEmail)) {
    db.users.push({ id: uid('u'), email: adminEmail, password_hash: await bcrypt.hash(adminPass, 10), role: 'ADMIN', created_at: nowISO() });
    changed = true;
  }
  // NOTE: no demo questions are seeded - admin creates every question from the console.
  // NOTE: no demo teams are seeded — every team must register with an @sasurie.com login.
  if (changed) save();
}

// ---------- auth ----------
function signToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN }); }
function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!tok) return res.status(401).json({ error: 'Authentication required' });
  try { req.user = jwt.verify(tok, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid or expired token' }); }
}
const requireAdmin = (req, res, next) => (req.user && req.user.role === 'ADMIN' ? next() : res.status(403).json({ error: '403 – Access Denied' }));
const requireTeam = (req, res, next) => (req.user && req.user.role === 'PARTICIPANT' ? next() : res.status(403).json({ error: '403 – Access Denied' }));

// ---------- executor ----------
function parseArgs(input) {
  const raw = norm(input);
  if (!raw) return [];
  // try JSON-ish lines first, else whitespace split with number coercion
  const parts = raw.split(/\s+/);
  return parts.map((p) => {
    if (/^-?\d+$/.test(p)) return parseInt(p, 10);
    if (/^-?\d*\.\d+$/.test(p)) return parseFloat(p);
    if ((p.startsWith('"') && p.endsWith('"')) || (p.startsWith("'") && p.endsWith("'"))) return p.slice(1, -1);
    const n = Number(p);
    return Number.isNaN(n) ? p : n;
  });
}
function jsDriver(userCode, args) {
  const argLit = JSON.stringify(args);
  return `${userCode}\n;__args__=${argLit};__out__=null;
try{
  if (typeof calculate==='function') __out__=calculate(...__args__);
  else if (typeof solve==='function') __out__=solve(...__args__);
  else if (typeof factorial==='function') __out__=factorial(...__args__);
  else if (typeof is_palindrome==='function') __out__=is_palindrome(...__args__);
  else if (typeof fizzbuzz==='function') __out__=fizzbuzz(...__args__);
  else if (typeof main==='function') __out__=main(...__args__);
  else __out__='__NO_ENTRY__';
  if(__out__===true)__out__='True'; else if(__out__===false)__out__='False';
  if(__out__!==null&&typeof __out__==='object')__out__=JSON.stringify(__out__);
  if(__out__!==null&&__out__!==undefined) console.log(String(__out__));
}catch(e){ console.error('ERROR:'+e.message); }`;
}
function runJS(userCode, input) {
  return new Promise((resolve) => {
    let logs = [];
    const sandbox = { console: { log: (...a) => logs.push(a.join(' ')), error: (...a) => logs.push(a.join(' ')) }, __args__: parseArgs(input) };
    sandbox.global = sandbox;
    const ctx = vm.createContext(sandbox, { name: 'bughunt' });
    try {
      vm.runInContext(jsDriver(userCode, sandbox.__args__), ctx, { timeout: Math.min(EXEC_TIMEOUT_MS, 5000), displayErrors: false });
      resolve({ output: normOut(logs.join('\n')), error: null });
    } catch (e) { resolve({ output: normOut(logs.join('\n')), error: String(e && e.message || e) }); }
  });
}
function pyDriver(userCode, args) {
  // Driver: exec user code, then call first matching function with coerced args
  const lines = [
    'import sys, json',
    '__user_src__ = ' + JSON.stringify(userCode),
    'exec(__user_src__, globals())',
    '__raw__ = ' + JSON.stringify(args) + '',
    'def __coerce__(v):',
    '  return v',
    '__out__ = "__NO_ENTRY__"',
    'try:',
    '  if "calculate" in globals() and callable(globals()["calculate"]): __out__ = globals()["calculate"](*__raw__)',
    '  elif "factorial" in globals() and callable(globals()["factorial"]): __out__ = globals()["factorial"](*__raw__)',
    '  elif "is_palindrome" in globals() and callable(globals()["is_palindrome"]):',
    '    a = " ".join([str(x) for x in __raw__]) if len(__raw__)>1 else (__raw__[0] if __raw__ else "")',
    '    __out__ = globals()["is_palindrome"](a)',
    '  elif "fizzbuzz" in globals() and callable(globals()["fizzbuzz"]): __out__ = globals()["fizzbuzz"](*__raw__)',
    '  elif "solve" in globals() and callable(globals()["solve"]): __out__ = globals()["solve"](*__raw__)',
    '  elif "main" in globals() and callable(globals()["main"]): __out__ = globals()["main"](*__raw__)',
    '  else:',
    '    import io',
    '    __out__ = "__NO_ENTRY__"',
    '  print(str(__out__))',
    'except Exception as e:',
    '  print("ERROR:" + str(e))',
  ];
  return lines.join('\n');
}
function runPython(userCode, input) {
  return new Promise((resolve) => {
    const args = parseArgs(input);
    // If user code uses input(), feed raw stdin instead of function harness
    const usesStdin = /(^|\W)input\s*\(/.test(userCode);
    const driver = usesStdin ? userCode : pyDriver(userCode, args);
    const py = spawn('python', ['-c', driver], { timeout: EXEC_TIMEOUT_MS, killSignal: 'SIGKILL', env: { ...process.env, PYTHONNOUSERSITE: '1', PYTHONDONTWRITEBYTECODE: '1' } });
    let out = '', err = '';
    const kill = setTimeout(() => { try { py.kill('SIGKILL'); } catch {} }, EXEC_TIMEOUT_MS + 500);
    if (usesStdin && input) { py.stdin.write(String(input)); }
    try { py.stdin.end(); } catch {}
    py.stdout.on('data', (d) => { out += d.toString(); if (out.length > 20000) { out = out.slice(0, 20000); try { py.kill('SIGKILL'); } catch {} } });
    py.stderr.on('data', (d) => { err += d.toString(); });
    py.on('error', (e) => { clearTimeout(kill); resolve({ output: '', error: 'Python unavailable: ' + e.message }); });
    py.on('close', (code) => {
      clearTimeout(kill);
      const cleaned = normOut(out);
      if (!cleaned && err) return resolve({ output: '', error: normOut(err).slice(0, 500) });
      resolve({ output: cleaned, error: null });
    });
  });
}
function mockEvaluate(question, code, testcases) {
  // DEMO mock for C/C++/Java (or fallback): compare normalized submission vs solution.
  const a = code.replace(/\s+/g, ' ').trim();
  const b = (question.solution_code || '').replace(/\s+/g, ' ').trim();
  if (a === b) return testcases.map(() => ({ pass: true, mock: true }));
  // heuristic: does the submission still contain the known buggy snippet?
  const buggySig = (question.buggy_code || '').replace(/\s+/g, ' ').trim().slice(0, 120);
  const stillBuggy = buggySig && a.includes(buggySig.slice(0, 60));
  // partial credit heuristic: share of solution tokens present
  const solTokens = new Set(b.split(/[^A-Za-z0-9_]+/).filter(Boolean));
  const subTokens = new Set(a.split(/[^A-Za-z0-9_]+/).filter(Boolean));
  let hit = 0; solTokens.forEach((t) => { if (subTokens.has(t)) hit++; });
  const ratio = solTokens.size ? hit / solTokens.size : 0;
  const passCount = stillBuggy ? 0 : Math.round(ratio * testcases.length);
  return testcases.map((_, i) => ({ pass: i < passCount, mock: true }));
}
async function evaluate(question, code) {
  const tcs = await store.testCasesByQuestion(question.id);
  const lang = question.language;
  const t0 = Date.now();
  const results = [];
  if ((lang === 'C' || lang === 'C++' || lang === 'Java') && MOCK_NON_PYTHON) {
    const m = mockEvaluate(question, code, tcs);
    let passed = 0;
    tcs.forEach((tc, i) => { const p = m[i].pass; if (p) passed++; results.push({ pass: p, mock: true }); });
    return { results, passed, total: tcs.length, execMs: Date.now() - t0, mock: true };
  }
  for (const tc of tcs) {
    let r;
    if (lang === 'Python') r = await runPython(code, tc.input_data);
    else r = await runJS(code, tc.input_data); // JavaScript + fallback
    if (r.error && /python unavailable/i.test(String(r.error))) {
      // No Python runtime (e.g. Vercel serverless) -> DEMO mock fallback,
      // clearly labelled mock:true so Run/Submit UI still works for demos.
      const m = mockEvaluate(question, code, tcs);
      let passed = 0;
      tcs.forEach((tc2, i) => { const p = m[i].pass; if (p) passed++; results.push({ pass: p, mock: true }); });
      return { results, passed, total: tcs.length, execMs: Date.now() - t0, mock: true };
    }
    const pass = !r.error && normOut(r.output) === normOut(tc.expected_output);
    results.push({ pass, mock: false });
  }
  const passed = results.filter((r) => r.pass).length;
  return { results, passed, total: tcs.length, execMs: Date.now() - t0, mock: false };
}
function calcScore(points, passed, total) {
  if (!total) return 0;
  if (passed >= total) return points;
  if (passed <= 0) return 0;
  return Math.round((points * passed) / total); // proportional partial credit
}
function verdict(passed, total) { return total > 0 && passed >= total ? 'Accepted' : passed > 0 ? 'Partial' : 'Failed'; }

// sanitizers — NEVER leak solution / test I/O to teams
const publicQuestion = async (q) => ({ id: q.id, title: q.title, description: q.description, language: q.language, difficulty: q.difficulty, points: q.points, time_limit: q.time_limit, status: q.status, test_count: (await store.testCasesByQuestion(q.id)).length, created_at: q.created_at });
const teamOf = async (id) => store.teamById(id);
const membersOf = async (tid) => store.membersByTeam(tid);
async function bestScores(teamId) {
  const map = {};
  for (const s of await store.submissionsByTeam(teamId)) {
    if (!map[s.question_id] || s.score > map[s.question_id].score) map[s.question_id] = s;
  }
  return map;
}
async function teamStats(teamId) {
  const subs = await store.submissionsByTeam(teamId);
  const best = await bestScores(teamId);
  const solved = Object.values(best).filter((s) => s.status === 'Accepted').length;
  const attempted = new Set(subs.map((s) => s.question_id)).size;
  const totalScore = Object.values(best).reduce((a, s) => a + s.score, 0);
  return { attempted, solved, totalScore, submissions: subs.length };
}

// ---------- app ----------
const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// ----- public -----
app.get('/api/public/settings', async (req, res) => res.json({ settings: await store.settings() }));
app.get('/api/public/stats', async (req, res) => {
  const qs = await store.allQuestions();
  const ts = await store.allTeams();
  const pub = qs.filter((q) => q.status === 'published').length;
  res.json({ teams: ts.filter((t) => t.status === 'active').length, questions: pub, languages: ['C', 'C++', 'Java', 'Python', 'JavaScript'] });
});

// ----- auth -----
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e || ''));
// Participant restriction: team login accounts must belong to the college domain,
// and each mobile number may be used by only one member across all teams.
const TEAM_EMAIL_DOMAIN = String(process.env.TEAM_EMAIL_DOMAIN || 'sasurie.com').toLowerCase();
const teamEmailOk = (e) => new RegExp(`^[^\\s@]+@${TEAM_EMAIL_DOMAIN.replace(/\./g, '\\.')}$`, 'i').test(String(e || '').trim());
const normPhone = (p) => String(p || '').replace(/\D/g, ''); // digits only, for uniqueness checks
app.post('/api/auth/register', async (req, res) => {
  try {
    const b = req.body || {};
    if ((await store.settings()).status === 'completed') return res.status(400).json({ error: 'Event has completed. Registration closed.' });
    const team_name = norm(b.team_name), login_email = norm(b.login_email).toLowerCase();
    const password = String(b.password || ''), confirm = String(b.confirm_password || b.confirmPassword || '');
    const m1 = b.member1 || {}, m2 = b.member2 || {};
    if (!team_name) return res.status(400).json({ error: 'Team name is required' });
    if (!teamEmailOk(login_email)) return res.status(400).json({ error: `Team login email must be an @${TEAM_EMAIL_DOMAIN} address` });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (password !== confirm) return res.status(400).json({ error: 'Passwords do not match' });
    for (const [i, m] of [[1, m1], [2, m2]]) {
      for (const f of ['full_name', 'email', 'phone', 'college', 'department', 'year'])
        if (!norm(m[f])) return res.status(400).json({ error: `Member ${i}: ${f.replace('_', ' ')} is required` });
      if (!emailOk(m.email)) return res.status(400).json({ error: `Member ${i}: valid email required` });
      if (!/^[+\d][\d\s-]{6,15}$/.test(norm(m.phone))) return res.status(400).json({ error: `Member ${i}: valid phone required` });
    }
    if (norm(m1.email).toLowerCase() === norm(m2.email).toLowerCase()) return res.status(400).json({ error: 'Members must have different emails' });
    // One mobile number may register only once across the whole event
    const p1 = normPhone(m1.phone), p2 = normPhone(m2.phone);
    if (p1 === p2) return res.status(400).json({ error: 'Member 1 and Member 2 cannot share the same mobile number' });
    const usedPhones = new Set((await store.allMemberPhones()).map((p) => normPhone(p)));
    if (usedPhones.has(p1)) return res.status(400).json({ error: 'Member 1 mobile number is already registered with another team' });
    if (usedPhones.has(p2)) return res.status(400).json({ error: 'Member 2 mobile number is already registered with another team' });
    if (await store.teamByLogin(login_email)) return res.status(400).json({ error: 'Team login email already registered' });
    if (await store.teamNameTaken(team_name.toLowerCase())) return res.status(400).json({ error: 'Team name already taken' });
    const tid = newId('team');
    await store.createTeam({ id: tid, team_name, login_email, password_hash: await bcrypt.hash(password, 10), college: norm(m1.college), department: norm(m1.department), status: 'active', created_at: nowISO() });
    await store.createMembers([
      { id: newId('m'), team_id: tid, member_number: 1, full_name: norm(m1.full_name), email: norm(m1.email).toLowerCase(), phone: norm(m1.phone), college: norm(m1.college), department: norm(m1.department), year: norm(m1.year) },
      { id: newId('m'), team_id: tid, member_number: 2, full_name: norm(m2.full_name), email: norm(m2.email).toLowerCase(), phone: norm(m2.phone), college: norm(m2.college), department: norm(m2.department), year: norm(m2.year) },
    ]);
    return res.json({ ok: true, message: 'Team registered. Login with your team account.' });
  } catch (e) { return res.status(500).json({ error: 'Registration failed' }); }
});
app.post('/api/auth/team-login', async (req, res) => {
  const { login_email, email, password } = req.body || {};
  const em = norm(login_email || email).toLowerCase();
  if (!teamEmailOk(em)) return res.status(401).json({ error: `Only @${TEAM_EMAIL_DOMAIN} team accounts can login here` });
  const t = await store.teamByLogin(em);
  if (!t || !(await bcrypt.compare(String(password || ''), t.password_hash))) return res.status(401).json({ error: 'Invalid team credentials' });
  if (t.status !== 'active') return res.status(403).json({ error: 'Team account is disabled. Contact admin.' });
  return res.json({ token: signToken({ role: 'PARTICIPANT', team_id: t.id }), team: { id: t.id, team_name: t.team_name } });
});
app.post('/api/auth/admin-login', async (req, res) => {
  const { email, password } = req.body || {};
  const u = await store.findAdmin(norm(email).toLowerCase());
  if (!u || !(await bcrypt.compare(String(password || ''), u.password_hash))) return res.status(401).json({ error: 'Invalid admin credentials' });
  return res.json({ token: signToken({ role: 'ADMIN', admin_id: u.id, email: u.email }) });
});
app.get('/api/auth/me', requireAuth, async (req, res) => {
  if (req.user.role === 'ADMIN') return res.json({ role: 'ADMIN', email: req.user.email });
  const t = await teamOf(req.user.team_id);
  if (!t) return res.status(401).json({ error: 'Team not found' });
  res.json({ role: 'PARTICIPANT', team: { id: t.id, team_name: t.team_name, login_email: t.login_email, status: t.status }, members: await membersOf(t.id) });
});

// ----- team APIs -----
app.get('/api/team/dashboard', requireAuth, requireTeam, async (req, res) => {
  const t = await teamOf(req.user.team_id);
  if (!t || t.status !== 'active') return res.status(403).json({ error: 'Team disabled' });
  const qs = await store.allQuestions();
  const byId = Object.fromEntries(qs.map((q) => [q.id, q]));
  const pub = qs.filter((q) => q.status === 'published');
  const st = await teamStats(t.id);
  const recent = (await store.submissionsByTeam(t.id)).slice(0, 6)
    .map((s) => ({ ...s, question_title: (byId[s.question_id] || {}).title || '—', submitted_code: undefined }));
  res.json({ team: { team_name: t.team_name }, members: await membersOf(t.id), cards: { available: pub.length, attempted: st.attempted, solved: st.solved, score: st.totalScore }, recent });
});
app.get('/api/team/challenges', requireAuth, requireTeam, async (req, res) => {
  const best = await bestScores(req.user.team_id);
  const qs = (await store.allQuestions()).filter((q) => q.status === 'published');
  res.json({
    questions: await Promise.all(qs.map(async (q) => ({ ...(await publicQuestion(q)), best_score: best[q.id] ? best[q.id].score : 0, best_status: best[q.id] ? best[q.id].status : null }))),
  });
});
app.get('/api/team/questions/:id', requireAuth, requireTeam, async (req, res) => {
  const q = await store.questionById(req.params.id);
  if (!q || q.status !== 'published') return res.status(404).json({ error: 'Challenge not found' });
  const pq = await publicQuestion(q);
  pq.buggy_code = q.buggy_code;
  const att = await store.attemptByTeamQuestion(req.user.team_id, q.id);
  pq.attempt_started_at = att ? att.started_at : null;
  res.json({ question: pq });
});
app.post('/api/team/questions/:id/start', requireAuth, requireTeam, async (req, res) => {
  const q = await store.questionById(req.params.id);
  if (!q || q.status !== 'published') return res.status(404).json({ error: 'Challenge not found' });
  let att = await store.attemptByTeamQuestion(req.user.team_id, q.id);
  if (!att) { att = await store.createAttempt({ id: newId('att'), team_id: req.user.team_id, question_id: q.id, started_at: nowISO() }); }
  res.json({ started_at: att.started_at, time_limit: q.time_limit });
});
async function attemptExpired(teamId, q) {
  const att = await store.attemptByTeamQuestion(teamId, q.id);
  if (!att) return false;
  const elapsedMin = (Date.now() - new Date(att.started_at).getTime()) / 60000;
  return elapsedMin > (q.time_limit || 20) + 0.15; // ~9s grace
}
app.post('/api/team/questions/:id/run', requireAuth, requireTeam, async (req, res) => {
  const q = await store.questionById(req.params.id);
  if (!q || q.status !== 'published') return res.status(404).json({ error: 'Challenge not found' });
  if (await attemptExpired(req.user.team_id, q)) return res.status(400).json({ error: "TIME'S UP — timer expired. Your code was auto-saved.", expired: true });
  const code = String(req.body.code || '');
  if (!code.trim()) return res.status(400).json({ error: 'No code to run' });
  if (code.length > 60000) return res.status(400).json({ error: 'Code too large' });
  try {
    const r = await evaluate(q, code);
    // Only pass/fail booleans — never inputs/outputs
    res.json({ passed: r.passed, total: r.total, results: r.results.map((x) => ({ pass: x.pass })), mock: !!r.mock, exec_ms: r.execMs, message: r.passed === r.total ? 'All test cases passed' : 'Some test cases failed.' });
  } catch (e) { res.status(500).json({ error: 'Execution failed. Try again.' }); }
});
app.post('/api/team/questions/:id/submit', requireAuth, requireTeam, async (req, res) => {
  const q = await store.questionById(req.params.id);
  if (!q || q.status !== 'published') return res.status(404).json({ error: 'Challenge not found' });
  if (await attemptExpired(req.user.team_id, q)) return res.status(400).json({ error: "TIME'S UP — submission blocked, timer expired.", expired: true });
  const code = String(req.body.code || '');
  if (!code.trim()) return res.status(400).json({ error: 'No code to submit' });
  if (code.length > 60000) return res.status(400).json({ error: 'Code too large' });
  if (!(await store.settings()).allow_multiple_submissions) {
    const prev = await store.acceptedSubmission(req.user.team_id, q.id);
    if (prev) return res.status(400).json({ error: 'Already solved. Multiple submissions disabled.' });
  }
  try {
    const r = await evaluate(q, code);
    const score = calcScore(q.points, r.passed, r.total); // backend-calculated only
    const sub = { id: newId('s'), team_id: req.user.team_id, question_id: q.id, submitted_code: code, passed_tests: r.passed, total_tests: r.total, score, execution_time: r.execMs || 0, status: verdict(r.passed, r.total), submitted_at: nowISO() };
    await store.createSubmission(sub);
    res.json({ ok: true, passed: r.passed, total: r.total, score, max: q.points, status: sub.status, submitted_at: sub.submitted_at, question: q.title, mock: !!r.mock });
  } catch (e) { res.status(500).json({ error: 'Submission evaluation failed' }); }
});
app.get('/api/team/submissions', requireAuth, requireTeam, async (req, res) => {
  const qs = await store.allQuestions();
  const byId = Object.fromEntries(qs.map((q) => [q.id, q]));
  const list = (await store.submissionsByTeam(req.user.team_id))
    .map((s) => ({ id: s.id, question_id: s.question_id, question_title: (byId[s.question_id] || {}).title || '—', passed_tests: s.passed_tests, total_tests: s.total_tests, score: s.score, max: (byId[s.question_id] || {}).points || 0, status: s.status, submitted_at: s.submitted_at, execution_time: s.execution_time }));
  res.json({ submissions: list });
});
app.get('/api/team/profile', requireAuth, requireTeam, async (req, res) => {
  const t = await teamOf(req.user.team_id);
  res.json({ team: { team_name: t.team_name, login_email: t.login_email, college: t.college, department: t.department, status: t.status, created_at: t.created_at }, members: await membersOf(t.id), editable: !!(await store.settings()).allow_profile_edit });
});
app.put('/api/team/profile', requireAuth, requireTeam, async (req, res) => {
  if (!(await store.settings()).allow_profile_edit) return res.status(403).json({ error: 'Profile editing is disabled by admin' });
  const t = await teamOf(req.user.team_id);
  const { team_name } = req.body || {};
  if (team_name && norm(team_name) && norm(team_name) !== t.team_name) {
    if (await store.teamNameTaken(norm(team_name).toLowerCase(), t.id)) return res.status(400).json({ error: 'Team name taken' });
    await store.setTeamName(t.id, norm(team_name));
  }
  res.json({ ok: true });
});

// ----- admin APIs -----
app.get('/api/admin/stats', requireAuth, requireAdmin, async (req, res) => {
  const qs = await store.allQuestions();
  const ts = await store.allTeams();
  const subs = await store.allSubmissions();
  const byTeam = Object.fromEntries(ts.map((t) => [t.id, t]));
  const byQ = Object.fromEntries(qs.map((q) => [q.id, q]));
  const totalPoints = qs.reduce((a, q) => a + q.points, 0);
  const avg = ts.length ? Math.round(subs.reduce((a, s) => a + s.score, 0) / Math.max(1, ts.length)) : 0;
  const recent = subs.slice(0, 8).map((s) => ({
    id: s.id, team: (byTeam[s.team_id] || {}).team_name || '—', question: (byQ[s.question_id] || {}).title || '—',
    score: s.score, submitted_at: s.submitted_at, status: s.status,
  }));
  res.json({
    cards: {
      total_teams: ts.length, active_teams: ts.filter((t) => t.status === 'active').length,
      total_questions: qs.length, published: qs.filter((q) => q.status === 'published').length,
      submissions: subs.length, points: totalPoints, avg,
    }, recent,
  });
});
app.get('/api/admin/questions', requireAuth, requireAdmin, async (req, res) => {
  const qs = await store.allQuestions();
  res.json({ questions: await Promise.all(qs.map(async (q) => ({ ...q, test_count: (await store.testCasesByQuestion(q.id)).length }))) });
});
app.post('/api/admin/questions', requireAuth, requireAdmin, async (req, res) => {
  const b = req.body || {};
  if (!norm(b.title)) return res.status(400).json({ error: 'Title required' });
  if (!norm(b.description)) return res.status(400).json({ error: 'Description required' });
  if (!['C', 'C++', 'Java', 'Python', 'JavaScript'].includes(b.language)) return res.status(400).json({ error: 'Invalid language' });
  if (!['Easy', 'Medium', 'Hard'].includes(b.difficulty)) return res.status(400).json({ error: 'Invalid difficulty' });
  if (!(parseInt(b.points, 10) > 0)) return res.status(400).json({ error: 'Points must be > 0' });
  if (!norm(b.buggy_code)) return res.status(400).json({ error: 'Buggy code required' });
  if (!norm(b.solution_code)) return res.status(400).json({ error: 'Correct solution required' });
  const q = { id: newId('q'), title: norm(b.title), description: String(b.description), language: b.language, difficulty: b.difficulty, points: parseInt(b.points, 10), buggy_code: String(b.buggy_code), solution_code: String(b.solution_code), time_limit: Math.max(1, parseInt(b.time_limit, 10) || 20), status: ['draft', 'published', 'disabled'].includes(b.status) ? b.status : 'draft', created_at: nowISO(), updated_at: nowISO() };
  await store.createQuestion(q);
  for (const tc of (Array.isArray(b.test_cases) ? b.test_cases : [])) {
    if (tc && (norm(tc.input_data) || norm(tc.expected_output))) await store.addTestCase({ id: newId('t'), question_id: q.id, input_data: String(tc.input_data ?? ''), expected_output: String(tc.expected_output ?? ''), created_at: nowISO() });
  }
  res.json({ ok: true, question: q });
});
app.get('/api/admin/questions/:id', requireAuth, requireAdmin, async (req, res) => {
  const q = await store.questionById(req.params.id);
  if (!q) return res.status(404).json({ error: 'Not found' });
  res.json({ question: q, test_cases: await store.testCasesByQuestion(q.id) });
});
app.put('/api/admin/questions/:id', requireAuth, requireAdmin, async (req, res) => {
  const q = await store.questionById(req.params.id);
  if (!q) return res.status(404).json({ error: 'Not found' });
  const b = req.body || {};
  const fields = {};
  for (const f of ['title', 'description', 'language', 'difficulty', 'buggy_code', 'solution_code', 'status']) if (b[f] !== undefined) fields[f] = b[f];
  if (b.points !== undefined) { const p = parseInt(b.points, 10); if (!(p > 0)) return res.status(400).json({ error: 'Points must be > 0' }); fields.points = p; }
  if (b.time_limit !== undefined) fields.time_limit = Math.max(1, parseInt(b.time_limit, 10) || q.time_limit);
  fields.updated_at = nowISO();
  const updated = await store.updateQuestion(q.id, fields);
  if (Array.isArray(b.test_cases)) {
    await store.deleteTestCasesByQuestion(q.id);
    for (const tc of b.test_cases) { await store.addTestCase({ id: newId('t'), question_id: q.id, input_data: String(tc.input_data ?? ''), expected_output: String(tc.expected_output ?? ''), created_at: nowISO() }); }
  }
  res.json({ ok: true, question: updated });
});
app.delete('/api/admin/questions/:id', requireAuth, requireAdmin, async (req, res) => {
  await store.deleteQuestion(req.params.id);
  res.json({ ok: true });
});
app.get('/api/admin/teams', requireAuth, requireAdmin, async (req, res) => {
  const ts = await store.allTeams();
  res.json({
    teams: await Promise.all(ts.map(async (t) => {
      const st = await teamStats(t.id), ms = await membersOf(t.id);
      return { id: t.id, team_name: t.team_name, login_email: t.login_email, college: t.college, department: t.department, status: t.status, created_at: t.created_at, member1: ms[0] ? ms[0].full_name : '—', member2: ms[1] ? ms[1].full_name : '—', members: ms, solved: st.solved, score: st.totalScore, submissions: st.submissions };
    })),
  });
});
app.get('/api/admin/teams/:id', requireAuth, requireAdmin, async (req, res) => {
  const t = await teamOf(req.params.id);
  if (!t) return res.status(404).json({ error: 'Not found' });
  res.json({ team: t, members: await membersOf(t.id), submissions: await store.submissionsByTeam(t.id) });
});
app.put('/api/admin/teams/:id/status', requireAuth, requireAdmin, async (req, res) => {
  const t = await store.setTeamStatus(req.params.id, req.body.status === 'disabled' ? 'disabled' : 'active');
  if (!t) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true, status: t.status });
});
app.get('/api/admin/submissions', requireAuth, requireAdmin, async (req, res) => {
  const { team, question, status } = req.query;
  let list = await store.allSubmissions();
  if (team) list = list.filter((s) => s.team_id === team);
  if (question) list = list.filter((s) => s.question_id === question);
  if (status) list = list.filter((s) => s.status === status);
  const ts = await store.allTeams();
  const qs = await store.allQuestions();
  const byTeam = Object.fromEntries(ts.map((t) => [t.id, t]));
  const byQ = Object.fromEntries(qs.map((q) => [q.id, q]));
  res.json({
    submissions: list.map((s) => ({ ...s, team_name: (byTeam[s.team_id] || {}).team_name || '—', question_title: (byQ[s.question_id] || {}).title || '—' })),
  });
});
app.get('/api/admin/leaderboard', requireAuth, requireAdmin, async (req, res) => {
  const sort = req.query.sort || 'score';
  const ts = await store.allTeams();
  const rows = await Promise.all(ts.map(async (t) => {
    const st = await teamStats(t.id), ms = await membersOf(t.id);
    const subs = await store.submissionsByTeam(t.id);
    const last = subs[0] || null;
    return { team_id: t.id, team_name: t.team_name, member1: ms[0] ? ms[0].full_name : '—', member2: ms[1] ? ms[1].full_name : '—', college: ms[0] ? ms[0].college : t.college, solved: st.solved, score: st.totalScore, submissions: st.submissions, last_submit: last ? last.submitted_at : null, status: t.status };
  }));
  rows.sort((a, b) => {
    if (sort === 'solved' && b.solved !== a.solved) return b.solved - a.solved;
    if (sort === 'time' && (a.last_submit || '') !== (b.last_submit || '')) return (a.last_submit || '').localeCompare(b.last_submit || '');
    if (b.score !== a.score) return b.score - a.score;
    if (b.solved !== a.solved) return b.solved - a.solved;
    return (a.last_submit || '').localeCompare(b.last_submit || '');
  });
  res.json({ leaderboard: rows.map((r, i) => ({ rank: i + 1, ...r })) });
});
app.get('/api/admin/settings', requireAuth, requireAdmin, async (req, res) => res.json({ settings: await store.settings() }));
app.put('/api/admin/settings', requireAuth, requireAdmin, async (req, res) => {
  const b = req.body || {};
  const patch = {};
  for (const f of ['event_name', 'description', 'registration_start', 'registration_end', 'event_start', 'event_end', 'status']) if (b[f] !== undefined) patch[f] = b[f];
  if (b.max_team_size !== undefined) patch.max_team_size = 2; // locked: exactly 2
  for (const f of ['allow_multiple_submissions', 'allow_profile_edit']) if (b[f] !== undefined) patch[f] = !!b[f];
  const settings = await store.updateSettings(patch);
  res.json({ ok: true, settings });
});

// ----- static + guards -----
// Friendly 403 page for participants hitting /admin/* without admin token is enforced client-side + API-side.
// NOTE: express.static must come before the fallback so /css/style.css and /js/common.js
// always resolve with correct MIME — otherwise UI/UX breaks on Vercel.
app.use(express.static(PUBLIC_DIR));
app.get('/admin', (req, res) => res.redirect('/admin/login.html'));
app.get('/admin/', (req, res) => res.redirect('/admin/login.html'));
// Serve the main pages without the .html extension too (e.g. /register, /login, /rules)
// so the registration page is reachable whichever way a link/URL refers to it.
const PAGE_ALIASES = ['index', 'login', 'register', 'rules', 'dashboard', 'challenges', 'challenge', 'submissions', 'profile', '403'];
app.get('/:page', (req, res, next) => {
  if (PAGE_ALIASES.includes(req.params.page)) return res.sendFile(path.join(PUBLIC_DIR, req.params.page + '.html'));
  next();
});
app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  // Missing static asset (css/js/img) -> proper 404, not 403 page (prevents broken UI masking)
  if (/\.(css|js|map|png|jpg|jpeg|svg|ico|woff2?|ttf)$/i.test(req.path)) return res.status(404).end();
  const notFoundPage = path.join(PUBLIC_DIR, '403.html');
  if (fs.existsSync(notFoundPage)) return res.status(404).sendFile(notFoundPage);
  return res.status(404).send('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>404 — BUG HUNT</title></head><body style="font-family:system-ui,sans-serif;text-align:center;padding:80px 20px;background:#070b16;color:#e2e8f0"><h1 style="font-size:64px;margin:0">404</h1><h2>Page not found</h2><p style="color:#94a3b8">The page you requested does not exist.</p><a style="color:#38bdf8" href="/">Go Home</a></body></html>');
});

seed()
  .then(() => {
    if (require.main === module) {
      // Local / bare-metal run: `npm start` / `node server.js`
      app.listen(PORT, () => console.log(`BUG HUNT live on http://localhost:${PORT}\nDEMO admin: ${process.env.DEMO_ADMIN_EMAIL || 'admin@bughunt.com'} / ${process.env.DEMO_ADMIN_PASSWORD || 'admin123'}`));
    } else {
      console.log('BUG HUNT app loaded (serverless export – no listen)');
    }
  })
  .catch((e) => { console.error('BUG HUNT seed failed:', e); });

// Vercel / serverless: export the Express app as the request handler.
// (`vercel.json` rewrites all traffic here via the Node runtime.)
module.exports = app;
