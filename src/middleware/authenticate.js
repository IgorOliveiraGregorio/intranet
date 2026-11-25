'use strict';

const { AppError } = require('../utils/AppError');
const { nowSeconds } = require('../utils/time');

/**
 * Protege rotas: exige "Authorization: Bearer <jwt>", valida assinatura/expiração
 * e confirma que a sessão ainda não foi revogada (logout / reutilização de refresh token).
 */
function createAuthenticate({ tokenService, sessionRepository }) {
  return function authenticate(req, res, next) {
    const [scheme, token, extra] = (req.get('authorization') || '').split(' ');
    if (scheme?.toLowerCase() !== 'bearer' || !token || extra) {
      res.set('WWW-Authenticate', 'Bearer');
      return next(new AppError(401, 'UNAUTHORIZED', 'Autenticação necessária.'));
    }
    try {
      const claims = tokenService.verifyAccessToken(token);
      const session = sessionRepository.findActive(claims.sessionId, nowSeconds());
      if (!session || session.userId !== claims.userId) {
        throw new AppError(401, 'SESSION_REVOKED', 'Sessão encerrada. Faça login novamente.');
      }
      req.auth = claims;
      return next();
    } catch (err) {
      res.set('WWW-Authenticate', 'Bearer');
      return next(err);
    }
  };
}

module.exports = { createAuthenticate };
