'use strict';

/**
 * Erro "esperado" da aplicação. O errorHandler converte em resposta padronizada:
 *   { error: { code, message, details?, requestId } }
 * Mensagens aqui são seguras para o cliente; nunca inclua dados sensíveis.
 */
class AppError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

module.exports = { AppError };
