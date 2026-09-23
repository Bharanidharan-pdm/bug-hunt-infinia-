# BUG HUNT — Find the Bug. Fix the Code. Win the Hunt.

Team-based debugging competition platform. Core rule: **2 Members → 1 Team → 1 Login → 1 Shared Score**.

## Quick start (demo, no database needed)

```bash
npm install
cp .env.example .env   # Windows: copy .env.example .env
npm start
```

Open http://localhost:4000

**DEMO account (seeded, clearly labelled demo):**

| Role | Login | Password |
|---|---|---|
| Admin | `admin@bughunt.com` | `admin123` |

Teams are never seeded — every team must self-register with an `@sasurie.com` login.

> Change `JWT_SECRET` and demo passwords before any real event.

## Routes

| Who | Page |
|---|---|
| Public | `/` landing, `/register.html`, `/login.html`, `/rules.html` |
| Team | `/dashboard.html`, `/challenges.html`, `/challenge.html?id=…`, `/submissions.html`, `/profile.html` |
| Admin | `/admin/login.html` → `/admin/dashboard.html` (Dashboard, Questions, Teams, Submissions, Leaderboard, Settings) |

Participant hitting an admin page/API gets **403 – Access Denied**. Teams never receive `solution_code`, test-case I/O, other teams' data, or the leaderboard.

## API summary

- `POST /api/auth/register` — team registration (exactly 2 members, one shared login)
- `POST /api/auth/team-login` / `POST /api/auth/admin-login` / `GET /api/auth/me`
- Team: `GET /api/team/dashboard|challenges|questions/:id|submissions|profile`, `POST /api/team/questions/:id/start|run|submit`
- Admin: `GET /api/admin/stats|questions|teams|submissions|leaderboard|settings` + CRUD

Scoring is backend-only: `score = round(points × passed/total)`, capped at question points. Timer is validated server-side via attempt `started_at`.

## Code execution & security

- Python: spawned `python -c <driver>` with timeout (`EXEC_TIMEOUT_MS`), output cap, no network inheritance. Function harness calls `calculate/factorial/is_palindrome/fizzbuzz/solve/main`; if code uses `input()`, raw stdin is fed instead.
- JavaScript: Node `vm` context with timeout.
- C / C++ / Java: **DEMO mock evaluator** (compares against reference solution) unless `MOCK_NON_PYTHON=false` and toolchains are configured. Production must use isolated containers (CPU/mem limits, no network, seccomp) — see README notes in code header of `server.js`.

## Production (PostgreSQL)

1. Create DB, run `schema.sql` (`psql $DATABASE_URL -f schema.sql`).
2. Port the JSON store (`data/db.json`) to Postgres tables (same column names) or wire your ORM to the schema.
3. Set `DATABASE_URL`, strong `JWT_SECRET`, `MOCK_NON_PYTHON=false` + sandbox executor.
4. Put the app behind HTTPS, disable demo seeds.

## Project layout

```
server.js            Express API + evaluator + file JSON store (data/db.json)
schema.sql           Postgres production schema + leaderboard view
public/              static frontend (dark navy/cyber theme, Monaco, Lucide)
  index|login|register|rules|dashboard|challenges|challenge|submissions|profile.html
  admin/login.html, admin/dashboard.html
  css/style.css, js/common.js
```

## Event flows

Team: Landing → Register (team + 2 members + 1 login) → Team Login → Dashboard → Challenges → Debug (Run/Submit) → My Submissions.
Admin: Login → Dashboard → Create question (points, buggy code, solution, hidden tests, time limit) → Publish → monitor Submissions → private Leaderboard.
