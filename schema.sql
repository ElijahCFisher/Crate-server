CREATE TABLE users (
  id TEXT PRIMARY KEY,
  google_sub TEXT NOT NULL UNIQUE,
  email TEXT,
  refresh_token TEXT NOT NULL,
  access_token TEXT,
  access_token_expires_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);