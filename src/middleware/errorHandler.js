'use strict';

const { AppError } = require('../utils/AppError');

/** 404 para qualquer rota não tratada. */
function notFoundHandler(req, res, next) {
  next(new AppError(404, 'NOT_FOUND', 'Recurso não encontrado.'));
}

/**
 * Tratamento centralizado. Formato único: { error: { code, message, details?, requestId } }.
 * Erros inesperados viram 500 genérico — detalhes/stack ficam só no log do servidor.
 */
function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);

  let status = 500;
  let code = 'INTERNAL_ERROR';
  let message = 'Erro interno. Tente novamente mais tarde.';
  let details;

  if (err instanceof AppError) {
    ({ status, code, message, details } = err);
  } else if (err?.type === 'entity.parse.failed') {
    status = 400;
    code = 'INVALID_JSON';
    message = 'Corpo da requisição não é um JSON válido.';
  } else if (err?.type === 'entity.too.large') {
    status = 413;
    code = 'PAYLOAD_TOO_LARGE';
    message = 'Corpo da requisição muito grande.';
  } else if (err?.type === 'charset.unsupported' || err?.type === 'encoding.unsupported') {
    status = 415;
    code = 'UNSUPPORTED_MEDIA_TYPE';
    message = 'Codificação não suportada.';
  } else {
    req.log?.error({ err }, 'Erro não tratado');
  }

  res.status(status).json({ error: { code, message, ...(details && { details }), requestId: req.id } });
}

module.exports = { notFoundHandler, errorHandler };
