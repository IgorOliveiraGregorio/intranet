'use strict';

/** Sessões de login e seus refresh tokens (guardados apenas como hash). */
function createSessionRepository(db) {
  const stmts = {
    createSession: db.prepare(
      'INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
    ),
    findActive: db.prepare(
      'SELECT id, user_id, expires_at FROM sessions WHERE id = ? AND revoked_at IS NULL AND expires_at > ?',
    ),
    revoke: db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL'),
    revokeAllForUser: db.prepare(
      'UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL',
    ),
    insertToken: db.prepare(
      'INSERT INTO refresh_tokens (session_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)',
    ),
    findToken: db.prepare(
      'SELECT id, session_id, expires_at, used_at FROM refresh_tokens WHERE token_hash = ?',
    ),
    // Atômico: só uma requisição consegue "consumir" o token.
    markTokenUsed: db.prepare('UPDATE refresh_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL'),
    purge: db.prepare(
      'DELETE FROM sessions WHERE expires_at <= ? OR (revoked_at IS NOT NULL AND revoked_at <= ?)',
    ),
  };

  return {
    createSession({ id, userId, createdAt, expiresAt }) {
      stmts.createSession.run(id, userId, createdAt, expiresAt);
    },
    findActive(id, now) {
      const row = stmts.findActive.get(id, now);
      return row && { id: row.id, userId: row.user_id, expiresAt: row.expires_at };
    },
    revoke: (id, now) => stmts.revoke.run(now, id).changes > 0,
    revokeAllForUser: (userId, now) => stmts.revokeAllForUser.run(now, userId).changes,

    addRefreshToken({ sessionId, tokenHash, expiresAt, createdAt }) {
      stmts.insertToken.run(sessionId, tokenHash, expiresAt, createdAt);
    },
    findRefreshToken(tokenHash) {
      const row = stmts.findToken.get(tokenHash);
      return (
        row && {
          id: row.id,
          sessionId: row.session_id,
          expiresAt: row.expires_at,
          usedAt: row.used_at,
        }
      );
    },
    markRefreshTokenUsed: (id, now) => stmts.markTokenUsed.run(now, id).changes === 1,

    /** Remove sessões expiradas e sessões revogadas há mais de 1 dia (cascata apaga os tokens). */
    purgeStale(now) {
      return stmts.purge.run(now, now - 24 * 3600).changes;
    },
  };
}

module.exports = { createSessionRepository };
