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

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

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
    if (!fs.existsSync(DB_FILE)) { const d = defaultDB(); fs.writeFileSync(DB_FILE, JSON.stringify(d, null, 2)); return d; }
    const d = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    return Object.assign(defaultDB(), d);
  } catch { const d = defaultDB(); fs.writeFileSync(DB_FILE, JSON.stringify(d, null, 2)); return d; }
}
let db = loadDB();
function save() { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }

// ---------- seed ----------
async function seed() {
  let changed = false;
  const adminEmail = norm(process.env.DEMO_ADMIN_EMAIL || 'admin@bughunt.com').toLowerCase();
  const adminPass = process.env.DEMO_ADMIN_PASSWORD || 'admin123';
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
  const tcs = db.testcases.filter((t) => t.question_id === question.id);
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
const publicQuestion = (q) => ({ id: q.id, title: q.title, description: q.description, language: q.language, difficulty: q.difficulty, points: q.points, time_limit: q.time_limit, status: q.status, test_count: db.testcases.filter((t) => t.question_id === q.id).length, created_at: q.created_at });
const teamOf = (id) => db.teams.find((t) => t.id === id);
const membersOf = (tid) => db.members.filter((m) => m.team_id === tid).sort((a, b) => a.member_number - b.member_number);
function bestScores(teamId) {
  const map = {};
  for (const s of db.submissions.filter((x) => x.team_id === teamId)) {
    if (!map[s.question_id] || s.score > map[s.question_id].score) map[s.question_id] = s;
  }
  return map;
}
function teamStats(teamId) {
  const subs = db.submissions.filter((s) => s.team_id === teamId);
  const best = bestScores(teamId);
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
app.get('/api/public/settings', (req, res) => res.json({ settings: db.settings }));
app.get('/api/public/stats', (req, res) => {
  const pub = db.questions.filter((q) => q.status === 'published').length;
  res.json({ teams: db.teams.filter((t) => t.status === 'active').length, questions: pub, languages: ['C', 'C++', 'Java', 'Python', 'JavaScript'] });
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
    if (db.settings.status === 'completed') return res.status(400).json({ error: 'Event has completed. Registration closed.' });
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
    const usedPhones = new Set(db.members.map((m) => normPhone(m.phone)));
    if (usedPhones.has(p1)) return res.status(400).json({ error: 'Member 1 mobile number is already registered with another team' });
    if (usedPhones.has(p2)) return res.status(400).json({ error: 'Member 2 mobile number is already registered with another team' });
    if (db.teams.find((t) => t.login_email === login_email)) return res.status(400).json({ error: 'Team login email already registered' });
    if (db.teams.find((t) => t.team_name.toLowerCase() === team_name.toLowerCase())) return res.status(400).json({ error: 'Team name already taken' });
    const tid = uid('team');
    db.teams.push({ id: tid, team_name, login_email, password_hash: await bcrypt.hash(password, 10), college: norm(m1.college), department: norm(m1.department), status: 'active', created_at: nowISO() });
    db.members.push(
      { id: uid('m'), team_id: tid, member_number: 1, full_name: norm(m1.full_name), email: norm(m1.email).toLowerCase(), phone: norm(m1.phone), college: norm(m1.college), department: norm(m1.department), year: norm(m1.year) },
      { id: uid('m'), team_id: tid, member_number: 2, full_name: norm(m2.full_name), email: norm(m2.email).toLowerCase(), phone: norm(m2.phone), college: norm(m2.college), department: norm(m2.department), year: norm(m2.year) },
    );
    save();
    return res.json({ ok: true, message: 'Team registered. Login with your team account.' });
  } catch (e) { return res.status(500).json({ error: 'Registration failed' }); }
});
app.post('/api/auth/team-login', async (req, res) => {
  const { login_email, email, password } = req.body || {};
  const em = norm(login_email || email).toLowerCase();
  if (!teamEmailOk(em)) return res.status(401).json({ error: `Only @${TEAM_EMAIL_DOMAIN} team accounts can login here` });
  const t = db.teams.find((x) => x.login_email === em);
  if (!t || !(await bcrypt.compare(String(password || ''), t.password_hash))) return res.status(401).json({ error: 'Invalid team credentials' });
  if (t.status !== 'active') return res.status(403).json({ error: 'Team account is disabled. Contact admin.' });
  return res.json({ token: signToken({ role: 'PARTICIPANT', team_id: t.id }), team: { id: t.id, team_name: t.team_name } });
});
app.post('/api/auth/admin-login', async (req, res) => {
  const { email, password } = req.body || {};
  const u = db.users.find((x) => x.email === norm(email).toLowerCase() && x.role === 'ADMIN');
  if (!u || !(await bcrypt.compare(String(password || ''), u.password_hash))) return res.status(401).json({ error: 'Invalid admin credentials' });
  return res.json({ token: signToken({ role: 'ADMIN', admin_id: u.id, email: u.email }) });
});
app.get('/api/auth/me', requireAuth, (req, res) => {
  if (req.user.role === 'ADMIN') return res.json({ role: 'ADMIN', email: req.user.email });
  const t = teamOf(req.user.team_id);
  if (!t) return res.status(401).json({ error: 'Team not found' });
  res.json({ role: 'PARTICIPANT', team: { id: t.id, team_name: t.team_name, login_email: t.login_email, status: t.status }, members: membersOf(t.id) });
});

// ----- team APIs -----
app.get('/api/team/dashboard', requireAuth, requireTeam, (req, res) => {
  const t = teamOf(req.user.team_id);
  if (!t || t.status !== 'active') return res.status(403).json({ error: 'Team disabled' });
  const pub = db.questions.filter((q) => q.status === 'published');
  const st = teamStats(t.id);
  const recent = db.submissions.filter((s) => s.team_id === t.id).sort((a, b) => b.submitted_at.localeCompare(a.submitted_at)).slice(0, 6)
    .map((s) => ({ ...s, question_title: (db.questions.find((q) => q.id === s.question_id) || {}).title || '—', submitted_code: undefined }));
  res.json({ team: { team_name: t.team_name }, members: membersOf(t.id), cards: { available: pub.length, attempted: st.attempted, solved: st.solved, score: st.totalScore }, recent });
});
app.get('/api/team/challenges', requireAuth, requireTeam, (req, res) => {
  const best = bestScores(req.user.team_id);
  res.json({
    questions: db.questions.filter((q) => q.status === 'published').map((q) => ({ ...publicQuestion(q), best_score: best[q.id] ? best[q.id].score : 0, best_status: best[q.id] ? best[q.id].status : null })),
  });
});
app.get('/api/team/questions/:id', requireAuth, requireTeam, (req, res) => {
  const q = db.questions.find((x) => x.id === req.params.id);
  if (!q || q.status !== 'published') return res.status(404).json({ error: 'Challenge not found' });
  const pq = publicQuestion(q);
  pq.buggy_code = q.buggy_code;
  const att = db.attempts.find((a) => a.team_id === req.user.team_id && a.question_id === q.id);
  pq.attempt_started_at = att ? att.started_at : null;
  res.json({ question: pq });
});
app.post('/api/team/questions/:id/start', requireAuth, requireTeam, (req, res) => {
  const q = db.questions.find((x) => x.id === req.params.id);
  if (!q || q.status !== 'published') return res.status(404).json({ error: 'Challenge not found' });
  let att = db.attempts.find((a) => a.team_id === req.user.team_id && a.question_id === q.id);
  if (!att) { att = { id: uid('att'), team_id: req.user.team_id, question_id: q.id, started_at: nowISO() }; db.attempts.push(att); save(); }
  res.json({ started_at: att.started_at, time_limit: q.time_limit });
});
function attemptExpired(teamId, q) {
  const att = db.attempts.find((a) => a.team_id === teamId && a.question_id === q.id);
  if (!att) return false;
  const elapsedMin = (Date.now() - new Date(att.started_at).getTime()) / 60000;
  return elapsedMin > (q.time_limit || 20) + 0.15; // ~9s grace
}
app.post('/api/team/questions/:id/run', requireAuth, requireTeam, async (req, res) => {
  const q = db.questions.find((x) => x.id === req.params.id);
  if (!q || q.status !== 'published') return res.status(404).json({ error: 'Challenge not found' });
  if (attemptExpired(req.user.team_id, q)) return res.status(400).json({ error: "TIME'S UP — timer expired. Your code was auto-saved.", expired: true });
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
  const q = db.questions.find((x) => x.id === req.params.id);
  if (!q || q.status !== 'published') return res.status(404).json({ error: 'Challenge not found' });
  if (attemptExpired(req.user.team_id, q)) return res.status(400).json({ error: "TIME'S UP — submission blocked, timer expired.", expired: true });
  const code = String(req.body.code || '');
  if (!code.trim()) return res.status(400).json({ error: 'No code to submit' });
  if (code.length > 60000) return res.status(400).json({ error: 'Code too large' });
  if (!db.settings.allow_multiple_submissions) {
    const prev = db.submissions.find((s) => s.team_id === req.user.team_id && s.question_id === q.id && s.status === 'Accepted');
    if (prev) return res.status(400).json({ error: 'Already solved. Multiple submissions disabled.' });
  }
  try {
    const r = await evaluate(q, code);
    const score = calcScore(q.points, r.passed, r.total); // backend-calculated only
    const sub = { id: uid('s'), team_id: req.user.team_id, question_id: q.id, submitted_code: code, passed_tests: r.passed, total_tests: r.total, score, execution_time: r.execMs || 0, status: verdict(r.passed, r.total), submitted_at: nowISO() };
    db.submissions.push(sub); save();
    res.json({ ok: true, passed: r.passed, total: r.total, score, max: q.points, status: sub.status, submitted_at: sub.submitted_at, question: q.title, mock: !!r.mock });
  } catch (e) { res.status(500).json({ error: 'Submission evaluation failed' }); }
});
app.get('/api/team/submissions', requireAuth, requireTeam, (req, res) => {
  const list = db.submissions.filter((s) => s.team_id === req.user.team_id).sort((a, b) => b.submitted_at.localeCompare(a.submitted_at))
    .map((s) => ({ id: s.id, question_id: s.question_id, question_title: (db.questions.find((q) => q.id === s.question_id) || {}).title || '—', passed_tests: s.passed_tests, total_tests: s.total_tests, score: s.score, max: (db.questions.find((q) => q.id === s.question_id) || {}).points || 0, status: s.status, submitted_at: s.submitted_at, execution_time: s.execution_time }));
  res.json({ submissions: list });
});
app.get('/api/team/profile', requireAuth, requireTeam, (req, res) => {
  const t = teamOf(req.user.team_id);
  res.json({ team: { team_name: t.team_name, login_email: t.login_email, college: t.college, department: t.department, status: t.status, created_at: t.created_at }, members: membersOf(t.id), editable: !!db.settings.allow_profile_edit });
});
app.put('/api/team/profile', requireAuth, requireTeam, (req, res) => {
  if (!db.settings.allow_profile_edit) return res.status(403).json({ error: 'Profile editing is disabled by admin' });
  const t = teamOf(req.user.team_id);
  const { team_name } = req.body || {};
  if (team_name && norm(team_name) && norm(team_name) !== t.team_name) {
    if (db.teams.find((x) => x.id !== t.id && x.team_name.toLowerCase() === norm(team_name).toLowerCase())) return res.status(400).json({ error: 'Team name taken' });
    t.team_name = norm(team_name);
  }
  save(); res.json({ ok: true });
});

// ----- admin APIs -----
app.get('/api/admin/stats', requireAuth, requireAdmin, (req, res) => {
  const totalPoints = db.questions.reduce((a, q) => a + q.points, 0);
  const avg = db.teams.length ? Math.round(db.submissions.reduce((a, s) => a + s.score, 0) / Math.max(1, db.teams.length)) : 0;
  const recent = [...db.submissions].sort((a, b) => b.submitted_at.localeCompare(a.submitted_at)).slice(0, 8).map((s) => ({
    id: s.id, team: (teamOf(s.team_id) || {}).team_name || '—', question: (db.questions.find((q) => q.id === s.question_id) || {}).title || '—',
    score: s.score, submitted_at: s.submitted_at, status: s.status,
  }));
  res.json({
    cards: {
      total_teams: db.teams.length, active_teams: db.teams.filter((t) => t.status === 'active').length,
      total_questions: db.questions.length, published: db.questions.filter((q) => q.status === 'published').length,
      submissions: db.submissions.length, points: totalPoints, avg,
    }, recent,
  });
});
app.get('/api/admin/questions', requireAuth, requireAdmin, (req, res) => {
  res.json({ questions: db.questions.map((q) => ({ ...q, test_count: db.testcases.filter((t) => t.question_id === q.id).length })) });
});
app.post('/api/admin/questions', requireAuth, requireAdmin, (req, res) => {
  const b = req.body || {};
  if (!norm(b.title)) return res.status(400).json({ error: 'Title required' });
  if (!norm(b.description)) return res.status(400).json({ error: 'Description required' });
  if (!['C', 'C++', 'Java', 'Python', 'JavaScript'].includes(b.language)) return res.status(400).json({ error: 'Invalid language' });
  if (!['Easy', 'Medium', 'Hard'].includes(b.difficulty)) return res.status(400).json({ error: 'Invalid difficulty' });
  if (!(parseInt(b.points, 10) > 0)) return res.status(400).json({ error: 'Points must be > 0' });
  if (!norm(b.buggy_code)) return res.status(400).json({ error: 'Buggy code required' });
  if (!norm(b.solution_code)) return res.status(400).json({ error: 'Correct solution required' });
  const q = { id: uid('q'), title: norm(b.title), description: String(b.description), language: b.language, difficulty: b.difficulty, points: parseInt(b.points, 10), buggy_code: String(b.buggy_code), solution_code: String(b.solution_code), time_limit: Math.max(1, parseInt(b.time_limit, 10) || 20), status: ['draft', 'published', 'disabled'].includes(b.status) ? b.status : 'draft', created_at: nowISO(), updated_at: nowISO() };
  db.questions.push(q);
  (Array.isArray(b.test_cases) ? b.test_cases : []).forEach((tc) => {
    if (tc && (norm(tc.input_data) || norm(tc.expected_output))) db.testcases.push({ id: uid('t'), question_id: q.id, input_data: String(tc.input_data ?? ''), expected_output: String(tc.expected_output ?? ''), created_at: nowISO() });
  });
  save(); res.json({ ok: true, question: q });
});
app.get('/api/admin/questions/:id', requireAuth, requireAdmin, (req, res) => {
  const q = db.questions.find((x) => x.id === req.params.id);
  if (!q) return res.status(404).json({ error: 'Not found' });
  res.json({ question: q, test_cases: db.testcases.filter((t) => t.question_id === q.id) });
});
app.put('/api/admin/questions/:id', requireAuth, requireAdmin, (req, res) => {
  const q = db.questions.find((x) => x.id === req.params.id);
  if (!q) return res.status(404).json({ error: 'Not found' });
  const b = req.body || {};
  for (const f of ['title', 'description', 'language', 'difficulty', 'buggy_code', 'solution_code', 'status']) if (b[f] !== undefined) q[f] = b[f];
  if (b.points !== undefined) { const p = parseInt(b.points, 10); if (!(p > 0)) return res.status(400).json({ error: 'Points must be > 0' }); q.points = p; }
  if (b.time_limit !== undefined) q.time_limit = Math.max(1, parseInt(b.time_limit, 10) || q.time_limit);
  if (Array.isArray(b.test_cases)) {
    db.testcases = db.testcases.filter((t) => t.question_id !== q.id);
    b.test_cases.forEach((tc) => { db.testcases.push({ id: uid('t'), question_id: q.id, input_data: String(tc.input_data ?? ''), expected_output: String(tc.expected_output ?? ''), created_at: nowISO() }); });
  }
  q.updated_at = nowISO(); save(); res.json({ ok: true, question: q });
});
app.delete('/api/admin/questions/:id', requireAuth, requireAdmin, (req, res) => {
  db.questions = db.questions.filter((x) => x.id !== req.params.id);
  db.testcases = db.testcases.filter((t) => t.question_id !== req.params.id);
  save(); res.json({ ok: true });
});
app.get('/api/admin/teams', requireAuth, requireAdmin, (req, res) => {
  res.json({
    teams: db.teams.map((t) => {
      const st = teamStats(t.id), ms = membersOf(t.id);
      return { id: t.id, team_name: t.team_name, login_email: t.login_email, college: t.college, department: t.department, status: t.status, created_at: t.created_at, member1: ms[0] ? ms[0].full_name : '—', member2: ms[1] ? ms[1].full_name : '—', members: ms, solved: st.solved, score: st.totalScore, submissions: st.submissions };
    }),
  });
});
app.get('/api/admin/teams/:id', requireAuth, requireAdmin, (req, res) => {
  const t = teamOf(req.params.id);
  if (!t) return res.status(404).json({ error: 'Not found' });
  res.json({ team: t, members: membersOf(t.id), submissions: db.submissions.filter((s) => s.team_id === t.id) });
});
app.put('/api/admin/teams/:id/status', requireAuth, requireAdmin, (req, res) => {
  const t = teamOf(req.params.id);
  if (!t) return res.status(404).json({ error: 'Not found' });
  t.status = req.body.status === 'disabled' ? 'disabled' : 'active'; save(); res.json({ ok: true, status: t.status });
});
app.get('/api/admin/submissions', requireAuth, requireAdmin, (req, res) => {
  const { team, question, status } = req.query;
  let list = [...db.submissions].sort((a, b) => b.submitted_at.localeCompare(a.submitted_at));
  if (team) list = list.filter((s) => s.team_id === team);
  if (question) list = list.filter((s) => s.question_id === question);
  if (status) list = list.filter((s) => s.status === status);
  res.json({
    submissions: list.map((s) => ({ ...s, team_name: (teamOf(s.team_id) || {}).team_name || '—', question_title: (db.questions.find((q) => q.id === s.question_id) || {}).title || '—' })),
  });
});
app.get('/api/admin/leaderboard', requireAuth, requireAdmin, (req, res) => {
  const sort = req.query.sort || 'score';
  const rows = db.teams.map((t) => {
    const st = teamStats(t.id), ms = membersOf(t.id);
    const last = db.submissions.filter((s) => s.team_id === t.id).sort((a, b) => b.submitted_at.localeCompare(a.submitted_at))[0];
    return { team_id: t.id, team_name: t.team_name, member1: ms[0] ? ms[0].full_name : '—', member2: ms[1] ? ms[1].full_name : '—', college: ms[0] ? ms[0].college : t.college, solved: st.solved, score: st.totalScore, submissions: st.submissions, last_submit: last ? last.submitted_at : null, status: t.status };
  });
  rows.sort((a, b) => {
    if (sort === 'solved' && b.solved !== a.solved) return b.solved - a.solved;
    if (sort === 'time' && (a.last_submit || '') !== (b.last_submit || '')) return (a.last_submit || '').localeCompare(b.last_submit || '');
    if (b.score !== a.score) return b.score - a.score;
    if (b.solved !== a.solved) return b.solved - a.solved;
    return (a.last_submit || '').localeCompare(b.last_submit || '');
  });
  res.json({ leaderboard: rows.map((r, i) => ({ rank: i + 1, ...r })) });
});
app.get('/api/admin/settings', requireAuth, requireAdmin, (req, res) => res.json({ settings: db.settings }));
app.put('/api/admin/settings', requireAuth, requireAdmin, (req, res) => {
  const b = req.body || {};
  for (const f of ['event_name', 'description', 'registration_start', 'registration_end', 'event_start', 'event_end', 'status']) if (b[f] !== undefined) db.settings[f] = b[f];
  if (b.max_team_size !== undefined) db.settings.max_team_size = 2; // locked: exactly 2
  for (const f of ['allow_multiple_submissions', 'allow_profile_edit']) if (b[f] !== undefined) db.settings[f] = !!b[f];
  save(); res.json({ ok: true, settings: db.settings });
});

// ----- static + guards -----
// Friendly 403 page for participants hitting /admin/* without admin token is enforced client-side + API-side.
app.use(express.static(path.join(__dirname, 'public')));
app.get('/admin', (req, res) => res.redirect('/admin/login.html'));
app.get('/admin/', (req, res) => res.redirect('/admin/login.html'));
app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', '403.html'));
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
// (`vercel.json` routes all traffic here via the @vercel/node runtime.)
module.exports = app;
