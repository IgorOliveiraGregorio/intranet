'use strict';

const { AppError } = require('../utils/AppError');

/** Valida/normaliza req.body com um schema zod; substitui o corpo pelos dados já sanitizados. */
function validateBody(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body ?? {});
    if (!result.success) {
      const details = {};
      for (const issue of result.error.issues) {
        const field = issue.path[0] ?? '_form';
        if (!(field in details)) details[field] = issue.message; // primeira mensagem por campo
      }
      return next(new AppError(400, 'VALIDATION_ERROR', 'Dados inválidos.', details));
    }
    req.body = result.data;
    return next();
  };
}

module.exports = { validateBody };
