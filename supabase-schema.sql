-- ══════════════════════════════════════════════════════════════════
-- ScribeAble – Supabase Schema Setup
-- Run this entire file in: Supabase Dashboard → SQL Editor → Run
-- ══════════════════════════════════════════════════════════════════

-- 1. Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. Drop existing tables if they exist to prevent type mismatch conflicts
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

-- 3. Users table (UUID primary key)
CREATE TABLE users (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  full_name   TEXT NOT NULL,
  email       TEXT UNIQUE NOT NULL,
  password    TEXT NOT NULL,
  mobile      TEXT,
  role        TEXT,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. Sessions table (references UUID users.id)
CREATE TABLE sessions (
  id          BIGSERIAL PRIMARY KEY,
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token       TEXT NOT NULL UNIQUE,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at  TIMESTAMP NOT NULL
);

-- 5. Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user  ON sessions(user_id);

-- 6. Disable Row Level Security (RLS) as custom JWT auth is handled in application layer
ALTER TABLE users    DISABLE ROW LEVEL SECURITY;
ALTER TABLE sessions DISABLE ROW LEVEL SECURITY;
