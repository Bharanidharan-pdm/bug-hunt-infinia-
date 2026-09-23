/* shared helpers */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const api = async (path, opts = {}) => {
  const res = await fetch(path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
};
const authed = (path, opts = {}) => {
  const t = localStorage.getItem(path.startsWith('/api/admin') ? 'bh_admin_token' : 'bh_team_token');
  if (!t) throw new Error('Not logged in');
  return api(path, { ...opts, headers: { Authorization: 'Bearer ' + t, ...((opts || {}).headers || {}) } });
};
function toast(msg, kind = '') {
  const box = $('.toast') || (() => { const d = document.createElement('div'); d.className = 'toast'; document.body.appendChild(d); return d; })();
  const d = document.createElement('div'); if (kind) d.className = kind; d.textContent = msg; box.appendChild(d);
  setTimeout(() => d.remove(), 4200);
}
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function fmtTime(iso) { try { return new Date(iso).toLocaleString(); } catch { return iso || '—'; } }
function diffTag(d) { return d === 'Easy' ? 'easy' : d === 'Hard' ? 'hard' : 'med'; }
function statusTag(s) {
  const m = { published: 'pub', draft: 'draft', disabled: 'dis', Accepted: 'acc', Partial: 'par', Failed: 'fail', active: 'acc' };
  return `<span class="tag ${m[s] || ''}">${esc(s)}</span>`;
}
function icons() { if (window.lucide) lucide.createIcons(); }
async function guardTeam() {
  const t = localStorage.getItem('bh_team_token');
  if (!t) { location.href = '/login.html'; return null; }
  try { const me = await authed('/api/auth/me'); if (me.role !== 'PARTICIPANT') throw new Error('x'); return me; }
  catch { localStorage.removeItem('bh_team_token'); location.href = '/login.html'; return null; }
}
async function guardAdmin() {
  const t = localStorage.getItem('bh_admin_token');
  if (!t) { location.href = '/admin/login.html'; return null; }
  try { const me = await authed('/api/admin/stats'); return me; }
  catch (e) { if (/401|403|logged/i.test(e.message)) { document.body.innerHTML = '<div class="wrap" style="padding:80px 20px;text-align:center"><h1>403 – Access Denied</h1><p class="mut">Admins only. <a href="/admin/login.html">Admin login</a></p></div>'; return null; } throw e; }
}
function logout(team = true) { localStorage.removeItem(team ? 'bh_team_token' : 'bh_admin_token'); location.href = team ? '/' : '/admin/login.html'; }
function teamStrap(me) {
  if (!me || !me.team) return '';
  const ms = (me.members || []).map((m) => esc(m.full_name)).join(' + ');
  return `<div class="teamstrap"><i data-lucide="shield-check"></i><span><b>TEAM: ${esc(me.team.team_name).toUpperCase()}</b></span><span class="mut">MEMBERS: ${ms.toUpperCase()}</span></div>`;
}
