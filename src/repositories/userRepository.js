'use strict';

/**
 * Acesso a dados de usuários. TODAS as consultas usam parâmetros ligados (?),
 * nunca concatenação de strings: isso elimina injeção de SQL.
 */
function createUserRepository(db) {
  const stmts = {
    insert: db.prepare(
      'INSERT INTO users (username, email, phone, password_hash) VALUES (@username, @email, @phone, @passwordHash)',
    ),
    authByUsername: db.prepare('SELECT id, username, password_hash FROM users WHERE username = ?'),
    byId: db.prepare('SELECT id, username, email, phone, created_at FROM users WHERE id = ?'),
    usernameExists: db.prepare('SELECT 1 FROM users WHERE username = ?'),
    emailExists: db.prepare('SELECT 1 FROM users WHERE email = ?'),
  };

  const toPublic = (row) =>
    row && {
      id: row.id,
      username: row.username,
      email: row.email,
      phone: row.phone,
      createdAt: row.created_at,
    };

  return {
    create({ username, email, phone, passwordHash }) {
      const info = stmts.insert.run({ username, email, phone, passwordHash });
      return Number(info.lastInsertRowid);
    },
    /** Único método que expõe o hash — uso restrito ao fluxo de login. */
    findCredentialsByUsername(username) {
      const row = stmts.authByUsername.get(username);
      return row && { id: row.id, username: row.username, passwordHash: row.password_hash };
    },
    findById: (id) => toPublic(stmts.byId.get(id)),
    existsByUsername: (username) => Boolean(stmts.usernameExists.get(username)),
    existsByEmail: (email) => Boolean(stmts.emailExists.get(email)),
  };
}

module.exports = { createUserRepository };
