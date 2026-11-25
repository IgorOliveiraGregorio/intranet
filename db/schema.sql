-- Esquema do banco (SQLite). Aplicado de forma idempotente na inicialização.
-- Datas de usuários em ISO-8601 (UTC); datas de sessão/token em epoch (segundos).

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL COLLATE NOCASE,   -- unicidade sem diferenciar maiúsculas
  email         TEXT NOT NULL COLLATE NOCASE,
  phone         TEXT NOT NULL,
  password_hash TEXT NOT NULL,                   -- Argon2id (inclui salt e parâmetros)
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Índices únicos: garantem duplicidade impossível mesmo sob concorrência
-- e aceleram as buscas por login e e-mail.
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username ON users (username);
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email    ON users (email);

-- Uma sessão por login. Revogar a sessão invalida o access token (via "sid") e os refresh tokens.
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,                                   -- UUID v4
  user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,                                   -- limite absoluto da sessão
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS ix_sessions_expires ON sessions (expires_at);

-- Refresh tokens opacos, guardados apenas como hash SHA-256. Uso único (rotação).
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER,                                            -- preenchido ao rotacionar
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_session ON refresh_tokens (session_id);
