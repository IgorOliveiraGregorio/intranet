'use strict';

require('dotenv').config();
const { loadConfig } = require('./config');
const { createApp } = require('./app');

let config;
try {
  config = loadConfig();
} catch (err) {
  console.error(err.message); // lista só nomes de variáveis, nunca valores
  process.exit(1);
}

const { app, logger, close, purgeStaleSessions } = createApp(config);

const server = app.listen(config.port, () => {
  logger.info({ port: config.port, env: config.env }, 'Servidor iniciado');
  if (config.isProduction && !config.cookieSecure) {
    logger.warn('COOKIE_SECURE=false em produção: use HTTPS sempre que possível.');
  }
});

// Limpeza periódica de sessões vencidas.
const cleanup = setInterval(() => {
  try {
    const removed = purgeStaleSessions();
    if (removed) logger.info({ removed }, 'Sessões antigas removidas');
  } catch (err) {
    logger.error({ err }, 'Falha na limpeza de sessões');
  }
}, 60 * 60 * 1000);
cleanup.unref();

function shutdown(signal) {
  logger.info({ signal }, 'Encerrando...');
  server.close(() => {
    close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref(); // força saída se algo travar
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
