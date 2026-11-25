'use strict';

const { AppError } = require('../utils/AppError');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Proteção CSRF para requisições que mudam estado (principalmente /refresh e /logout,
 * que dependem de cookie). Três camadas somadas:
 *  1. Cookie SameSite=Strict (o navegador não o envia em requisições entre sites);
 *  2. Verificação do cabeçalho Origin contra a lista de origens permitidas;
 *  3. Cabeçalho customizado obrigatório: um <form> de outro site não consegue enviá-lo, e
 *     um fetch() de outro site exigiria preflight, que o CORS restritivo nega.
 */
function createCsrfGuard(allowedOrigins) {
  const allowed = new Set(allowedOrigins);
  return function csrfGuard(req, res, next) {
    if (SAFE_METHODS.has(req.method)) return next();
    const origin = req.get('origin');
    if (origin && !allowed.has(origin)) {
      return next(new AppError(403, 'CSRF_ORIGIN_DENIED', 'Origem não autorizada.'));
    }
    if (req.get('x-requested-with') !== 'XMLHttpRequest') {
      return next(new AppError(403, 'CSRF_HEADER_MISSING', 'Requisição não autorizada.'));
    }
    return next();
  };
}

module.exports = { createCsrfGuard };
