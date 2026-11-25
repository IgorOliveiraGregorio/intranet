'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const pinoHttp = require('pino-http');

const { createLogger } = require('./utils/logger');
const { createDatabase } = require('./db/database');
const { createUserRepository } = require('./repositories/userRepository');
const { createSessionRepository } = require('./repositories/sessionRepository');
const { createPasswordService } = require('./services/passwordService');
const { createTokenService } = require('./services/tokenService');
const { createAuthService } = require('./services/authService');
const { createAuthController } = require('./controllers/authController');
const { createAuthenticate } = require('./middleware/authenticate');
const { createCsrfGuard } = require('./middleware/csrf');
const { createRateLimiters } = require('./middleware/rateLimiters');
const { notFoundHandler, errorHandler } = require('./middleware/errorHandler');
const { createApiRouter } = require('./routes');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

/** Fábrica da aplicação: recebe a config e monta tudo (facilita testes isolados). */
function createApp(config) {
  const logger = createLogger(config);
  const db = createDatabase(config.dbPath);

  // Composição das camadas: repositórios -> serviços -> controladores -> rotas
  const userRepository = createUserRepository(db);
  const sessionRepository = createSessionRepository(db);
  const passwordService = createPasswordService(config.argon2);
  const tokenService = createTokenService({ ...config.jwt });
  const authService = createAuthService({
    userRepository, sessionRepository, passwordService, tokenService, config, logger,
  });
  const controller = createAuthController({ authService, config });
  const authenticate = createAuthenticate({ tokenService, sessionRepository });
  const csrfGuard = createCsrfGuard(config.allowedOrigins);
  const limiters = createRateLimiters(config);

  const app = express();
  app.set('trust proxy', config.trustProxy); // necessário para o IP real atrás de proxy reverso

  app.use(
    pinoHttp({
      logger,
      genReqId: (req, res) => {
        const id = crypto.randomUUID(); // nunca confiar em IDs enviados pelo cliente
        res.setHeader('X-Request-Id', id);
        return id;
      },
      autoLogging: { ignore: (req) => req.url === '/api/health' },
    }),
  );

  // Cabeçalhos de segurança. CSP sem 'unsafe-inline': todo JS/CSS é de arquivos próprios.
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", 'data:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
        },
      },
      referrerPolicy: { policy: 'no-referrer' },
      // HSTS só faz sentido (e só é seguro) quando o site é servido por HTTPS.
      strictTransportSecurity: config.cookieSecure ? { maxAge: 15552000, includeSubDomains: true } : false,
    }),
  );

  // API: nunca em cache, CORS restritivo (lista de origens), teto geral de requisições.
  const allowed = new Set(config.allowedOrigins);
  app.use(
    '/api',
    (req, res, next) => {
      res.set('Cache-Control', 'no-store');
      next();
    },
    cors({
      origin: (origin, cb) => cb(null, !origin || allowed.has(origin)),
      credentials: true,
      methods: ['GET', 'POST', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
      maxAge: 600,
    }),
    limiters.api,
    express.json({ limit: '10kb' }), // corpo pequeno: reduz superfície de DoS
    cookieParser(),
    createApiRouter({ controller, authenticate, csrfGuard, limiters }),
  );

  // Front-end estático (mesma origem da API). "extensions" permite /login em vez de /login.html.
  app.use(express.static(PUBLIC_DIR, { extensions: ['html'], dotfiles: 'ignore' }));

  app.use(notFoundHandler);
  app.use(errorHandler);

  return {
    app,
    db,
    logger,
    purgeStaleSessions: () => authService.purgeStaleSessions(),
    close: () => db.close(),
  };
}

module.exports = { createApp };
