-- BUG HUNT — PostgreSQL production schema
-- Dev/demo runs on a file-based JSON store with the same shape (see server.js).
-- Point DATABASE_URL at Postgres and run this file with psql to go live.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email CITEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('ADMIN','PARTICIPANT')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS teams (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_name TEXT NOT NULL,
  login_email CITEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  college TEXT DEFAULT '',
  department TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS team_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  member_number INT NOT NULL CHECK (member_number IN (1,2)),
  full_name TEXT NOT NULL,
  email CITEXT NOT NULL,
  phone TEXT NOT NULL,
  college TEXT NOT NULL,
  department TEXT NOT NULL,
  year TEXT NOT NULL,
  UNIQUE(team_id, member_number)
);

CREATE TABLE IF NOT EXISTS questions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  language TEXT NOT NULL CHECK (language IN ('C','C++','Java','Python','JavaScript')),
  difficulty TEXT NOT NULL CHECK (difficulty IN ('Easy','Medium','Hard')),
  points INT NOT NULL CHECK (points > 0),
  buggy_code TEXT NOT NULL,
  solution_code TEXT NOT NULL,
  time_limit INT NOT NULL DEFAULT 20,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS test_cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  question_id UUID NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
  input_data TEXT NOT NULL,
  expected_output TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  question_id UUID NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(team_id, question_id)
);

CREATE TABLE IF NOT EXISTS submissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  question_id UUID NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
  submitted_code TEXT NOT NULL,
  passed_tests INT NOT NULL DEFAULT 0,
  total_tests INT NOT NULL DEFAULT 0,
  score INT NOT NULL DEFAULT 0,
  execution_time INT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'Failed' CHECK (status IN ('Accepted','Partial','Failed')),
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS event_settings (
  id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  event_name TEXT NOT NULL DEFAULT 'BUG HUNT',
  description TEXT NOT NULL DEFAULT 'A competitive debugging challenge where two-member teams test their coding skills by finding and fixing bugs.',
  registration_start TIMESTAMPTZ,
  registration_end TIMESTAMPTZ,
  event_start TIMESTAMPTZ,
  event_end TIMESTAMPTZ,
  max_team_size INT NOT NULL DEFAULT 2,
  allow_multiple_submissions BOOLEAN NOT NULL DEFAULT true,
  allow_profile_edit BOOLEAN NOT NULL DEFAULT false,
  status TEXT NOT NULL DEFAULT 'live' CHECK (status IN ('upcoming','live','completed'))
);

INSERT INTO event_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Leaderboard view (admin only — never expose to participants)
CREATE OR REPLACE VIEW leaderboard AS
SELECT
  t.id AS team_id, t.team_name, t.college, t.status,
  COALESCE(s.total_score, 0) AS total_score,
  COALESCE(s.solved, 0) AS questions_solved,
  COALESCE(s.subs, 0) AS total_submissions,
  s.last_submit AS last_submission_at
FROM teams t
LEFT JOIN (
  SELECT team_id,
    COALESCE(SUM(sub.best),0)::INT AS total_score,
    COUNT(*) FILTER (WHERE sub.best = sub.pts)::INT AS solved,
    (SELECT COUNT(*) FROM submissions x WHERE x.team_id = sub.team_id)::INT AS subs,
    (SELECT MAX(submitted_at) FROM submissions y WHERE y.team_id = sub.team_id) AS last_submit
  FROM (
    SELECT s.team_id, s.question_id, MAX(s.score) AS best, MAX(q.points) AS pts
    FROM submissions s JOIN questions q ON q.id = s.question_id
    GROUP BY s.team_id, s.question_id
  ) sub GROUP BY team_id
) s ON s.team_id = t.id
ORDER BY total_score DESC, questions_solved DESC, last_submit ASC NULLS LAST;
