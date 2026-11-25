'use strict';

const { Router } = require('express');
const { validateBody } = require('../middleware/validate');
const { registerSchema, loginSchema } = require('../validators/authSchemas');
const { notFoundHandler } = require('../middleware/errorHandler');

function createApiRouter({ controller, authenticate, csrfGuard, limiters }) {
  const router = Router();

  router.get('/health', (req, res) => res.json({ status: 'ok' }));

  const auth = Router();
  auth.use(csrfGuard);
  auth.post('/register', limiters.register, validateBody(registerSchema), controller.register);
  auth.post('/login', limiters.loginByIp, limiters.loginByAccount, validateBody(loginSchema), controller.login);
  auth.post('/refresh', controller.refresh);
  auth.post('/logout', controller.logout);
  auth.post('/logout-all', authenticate, controller.logoutAll);
  router.use('/auth', auth);

  // Rotas protegidas por JWT
  router.get('/users/me', authenticate, controller.me);

  router.use(notFoundHandler);
  return router;
}

module.exports = { createApiRouter };
