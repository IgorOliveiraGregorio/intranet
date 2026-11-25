'use strict';

const pino = require('pino');

/**
 * Logger estruturado. Cabeçalhos sensíveis são mascarados; corpos de requisição
 * (que contêm senhas) nunca são registrados.
 */
function createLogger(config) {
  return pino({
    level: config.logLevel,
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'res.headers["set-cookie"]',
      ],
      censor: '[REDACTED]',
    },
  });
}

module.exports = { createLogger };
