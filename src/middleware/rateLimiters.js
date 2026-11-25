'use strict';

const rateLimit = require('express-rate-limit');
const { AppError } = require('../utils/AppError');

/**
 * Limitação de tentativas. O armazenamento é em memória (suficiente para 1 instância).
 * Com várias instâncias, troque por um store compartilhado (ex.: Redis).
 */
function createRateLimiters(config) {
  const { windowMs, loginPerAccount, loginPerIp, registerPerHour, apiPerWindow } = config.rateLimit;

  // Resposta 429 no mesmo formato padronizado de erros.
  const handler = (req, res, next) =>
    next(new AppError(429, 'TOO_MANY_REQUESTS', 'Muitas tentativas. Aguarde alguns minutos e tente novamente.'));

  const base = { standardHeaders: 'draft-7', legacyHeaders: false, handler };

  return {
    // Teto geral da API, por IP.
    api: rateLimit({ ...base, windowMs, limit: apiPerWindow }),

    // Força bruta (1): por IP — só tentativas que FALHAM contam.
    loginByIp: rateLimit({ ...base, windowMs, limit: loginPerIp, skipSuccessfulRequests: true }),

    // Força bruta (2): por nome de usuário informado, independentemente do IP (para ataques
    // distribuídos). Usa o texto enviado, exista a conta ou não, então o comportamento é
    // idêntico para usuários reais e inexistentes (não permite enumeração).
    loginByAccount: rateLimit({
      ...base,
      windowMs,
      limit: loginPerAccount,
      skipSuccessfulRequests: true,
      skip: (req) => typeof req.body?.username !== 'string',
      keyGenerator: (req) => `acct:${req.body.username.trim().toLowerCase().slice(0, 64)}`,
    }),

    // Cadastro: evita criação em massa de contas e uso do endpoint para sondar duplicidade.
    register: rateLimit({ ...base, windowMs: 60 * 60 * 1000, limit: registerPerHour }),
  };
}

module.exports = { createRateLimiters };
