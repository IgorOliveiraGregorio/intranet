'use strict';

const crypto = require('node:crypto');
const { AppError } = require('../utils/AppError');
const { nowSeconds } = require('../utils/time');

function createAuthService({ userRepository, sessionRepository, passwordService, tokenService, config, logger }) {
  const { accessTtlSeconds, refreshTtlSeconds } = config.jwt;

  const invalidCredentials = () =>
    new AppError(401, 'INVALID_CREDENTIALS', 'Usuário ou senha inválidos.');
  const invalidRefresh = () =>
    new AppError(401, 'INVALID_REFRESH_TOKEN', 'Sessão inválida ou expirada. Faça login novamente.');

  function conflictsFor({ username, email }) {
    const details = {};
    if (userRepository.existsByUsername(username)) details.username = 'Este nome de usuário já está em uso.';
    if (userRepository.existsByEmail(email)) details.email = 'Este e-mail já está cadastrado.';
    return details;
  }

  function issueTokens({ userId, sessionId, refreshExpiresAt, now }) {
    const refreshToken = tokenService.generateRefreshToken();
    sessionRepository.addRefreshToken({
      sessionId,
      tokenHash: tokenService.hashRefreshToken(refreshToken),
      expiresAt: refreshExpiresAt,
      createdAt: now,
    });
    return {
      accessToken: tokenService.signAccessToken({ userId, sessionId }),
      expiresIn: accessTtlSeconds,
      refreshToken,
      refreshExpiresAt,
    };
  }

  return {
    async register({ username, email, phone, password }) {
      const conflicts = conflictsFor({ username, email });
      if (Object.keys(conflicts).length) {
        throw new AppError(409, 'CONFLICT', 'Usuário ou e-mail já cadastrado.', conflicts);
      }
      const passwordHash = await passwordService.hash(password);
      try {
        const id = userRepository.create({ username, email, phone, passwordHash });
        return userRepository.findById(id);
      } catch (err) {
        // Corrida entre duas requisições: o índice UNIQUE é a garantia final.
        if (String(err.code).startsWith('SQLITE_CONSTRAINT')) {
          throw new AppError(409, 'CONFLICT', 'Usuário ou e-mail já cadastrado.', conflictsFor({ username, email }));
        }
        throw err;
      }
    },

    async login({ username, password }) {
      const user = userRepository.findCredentialsByUsername(username);
      const ok = user
        ? await passwordService.verify(user.passwordHash, password)
        : await passwordService.verifyDummy(password);
      // Mesma resposta para "usuário não existe" e "senha errada".
      if (!ok) throw invalidCredentials();

      const now = nowSeconds();
      const sessionId = crypto.randomUUID();
      const expiresAt = now + refreshTtlSeconds;
      sessionRepository.createSession({ id: sessionId, userId: user.id, createdAt: now, expiresAt });
      return {
        ...issueTokens({ userId: user.id, sessionId, refreshExpiresAt: expiresAt, now }),
        user: userRepository.findById(user.id),
      };
    },

    /**
     * Rotação com detecção de reutilização: cada refresh token só vale uma vez.
     * Se um token já usado reaparece, assumimos vazamento e revogamos a sessão inteira.
     */
    refresh(rawToken) {
      if (typeof rawToken !== 'string' || rawToken.length < 20 || rawToken.length > 200) {
        throw invalidRefresh();
      }
      const now = nowSeconds();
      const record = sessionRepository.findRefreshToken(tokenService.hashRefreshToken(rawToken));
      if (!record) throw invalidRefresh();

      if (record.usedAt) {
        sessionRepository.revoke(record.sessionId, now);
        logger.warn({ sessionId: record.sessionId }, 'Reutilização de refresh token detectada; sessão revogada');
        throw invalidRefresh();
      }
      const session = sessionRepository.findActive(record.sessionId, now);
      if (!session || record.expiresAt <= now) throw invalidRefresh();

      if (!sessionRepository.markRefreshTokenUsed(record.id, now)) {
        sessionRepository.revoke(record.sessionId, now);
        throw invalidRefresh();
      }
      // A sessão tem validade absoluta: a rotação não a estende.
      return issueTokens({
        userId: session.userId,
        sessionId: session.id,
        refreshExpiresAt: session.expiresAt,
        now,
      });
    },

    /** Idempotente: sempre "funciona", mesmo com cookie ausente/inválido. */
    logout(rawToken) {
      if (typeof rawToken !== 'string' || !rawToken) return;
      const record = sessionRepository.findRefreshToken(tokenService.hashRefreshToken(rawToken));
      if (record) sessionRepository.revoke(record.sessionId, nowSeconds());
    },

    logoutAll(userId) {
      return sessionRepository.revokeAllForUser(userId, nowSeconds());
    },

    getProfile(userId) {
      const user = userRepository.findById(userId);
      if (!user) throw new AppError(404, 'NOT_FOUND', 'Usuário não encontrado.');
      return user;
    },

    purgeStaleSessions: () => sessionRepository.purgeStale(nowSeconds()),
  };
}

module.exports = { createAuthService };
