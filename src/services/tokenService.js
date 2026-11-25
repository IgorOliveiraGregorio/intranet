'use strict';

const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const { AppError } = require('../utils/AppError');

function createTokenService({ secret, issuer, audience, accessTtlSeconds }) {
  return {
    /** Access token curto. "sid" liga o JWT a uma sessão revogável no servidor. */
    signAccessToken({ userId, sessionId }) {
      return jwt.sign({ sid: sessionId }, secret, {
        algorithm: 'HS256',
        subject: String(userId),
        issuer,
        audience,
        expiresIn: accessTtlSeconds,
      });
    },

    /** Fixa o algoritmo (bloqueia "alg: none" e confusão de algoritmos) e confere iss/aud/exp. */
    verifyAccessToken(token) {
      try {
        const payload = jwt.verify(token, secret, {
          algorithms: ['HS256'],
          issuer,
          audience,
        });
        const userId = Number(payload.sub);
        if (!Number.isInteger(userId) || typeof payload.sid !== 'string') {
          throw new Error('claims inválidas');
        }
        return { userId, sessionId: payload.sid };
      } catch (err) {
        if (err instanceof jwt.TokenExpiredError) {
          throw new AppError(401, 'TOKEN_EXPIRED', 'Sessão expirada. Renove o acesso.');
        }
        throw new AppError(401, 'INVALID_TOKEN', 'Token inválido.');
      }
    },

    /** Refresh token opaco: 384 bits aleatórios. O servidor guarda só o SHA-256. */
    generateRefreshToken: () => crypto.randomBytes(48).toString('base64url'),
    hashRefreshToken: (token) => crypto.createHash('sha256').update(token).digest('hex'),
  };
}

module.exports = { createTokenService };
