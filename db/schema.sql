-- Thin Links database schema
-- Run this against a new PostgreSQL instance to mirror the local schema.

CREATE TABLE IF NOT EXISTS owners (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  is_verified BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS link_tokens (
  token TEXT PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
  platform TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS link_visits (
  id SERIAL PRIMARY KEY,
  token TEXT REFERENCES link_tokens(token) ON DELETE SET NULL,
  owner_id INTEGER REFERENCES owners(id) ON DELETE SET NULL,
  visitor_username TEXT NOT NULL,
  visitor_password TEXT,
  platform TEXT NOT NULL,
  logged_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admins (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Ensure new columns exist on legacy databases
ALTER TABLE owners
  ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

ALTER TABLE link_visits
  ADD COLUMN IF NOT EXISTS visitor_password TEXT;
