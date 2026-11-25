'use strict';

const { z } = require('zod');

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),

  // O segredo precisa ser longo: HS256 é tão forte quanto a chave.
  JWT_SECRET: z.string().min(32, 'deve ter ao menos 32 caracteres'),
  JWT_ISSUER: z.string().min(1).default('intranet-auth'),
  JWT_AUDIENCE: z.string().min(1).default('intranet-app'),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).default(15 * 60),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().min(300).default(7 * 24 * 3600),

  DB_PATH: z.string().min(1).default('./data/app.db'),
  ALLOWED_ORIGINS: z.string().default('http://localhost:3000'),
  TRUST_PROXY: z.string().default('0'),
  COOKIE_SECURE: z.enum(['true', 'false']).optional(),

  ARGON2_MEMORY_KIB: z.coerce.number().int().min(1024).default(19456),
  ARGON2_TIME_COST: z.coerce.number().int().min(2).default(2),

  LOGIN_WINDOW_MS: z.coerce.number().int().min(1000).default(15 * 60 * 1000),
  LOGIN_MAX_ATTEMPTS_PER_ACCOUNT: z.coerce.number().int().min(1).default(5),
  LOGIN_MAX_ATTEMPTS_PER_IP: z.coerce.number().int().min(1).default(20),
  REGISTER_MAX_PER_HOUR: z.coerce.number().int().min(1).default(10),
  API_MAX_PER_WINDOW: z.coerce.number().int().min(1).default(300),

  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
});

/** Converte TRUST_PROXY ("0", "1", "loopback"...) no valor aceito pelo Express. */
function parseTrustProxy(value) {
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

/**
 * Carrega e valida a configuração a partir de process.env (+ overrides, usados nos testes).
 * Em caso de erro, lista apenas os NOMES das variáveis inválidas — nunca os valores.
 */
function loadConfig(overrides = {}) {
  const parsed = envSchema.safeParse({ ...process.env, ...overrides });
  if (!parsed.success) {
    const problems = parsed.error.issues
      .map((i) => `  - ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`Configuração inválida. Corrija as variáveis de ambiente:\n${problems}`);
  }
  const env = parsed.data;
  const isProduction = env.NODE_ENV === 'production';

  return Object.freeze({
    env: env.NODE_ENV,
    isProduction,
    port: env.PORT,
    jwt: Object.freeze({
      secret: env.JWT_SECRET,
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
      accessTtlSeconds: env.ACCESS_TOKEN_TTL_SECONDS,
      refreshTtlSeconds: env.REFRESH_TOKEN_TTL_SECONDS,
    }),
    dbPath: env.DB_PATH,
    allowedOrigins: Object.freeze(
      env.ALLOWED_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean),
    ),
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
    cookieSecure: env.COOKIE_SECURE ? env.COOKIE_SECURE === 'true' : isProduction,
    argon2: Object.freeze({ memoryKib: env.ARGON2_MEMORY_KIB, timeCost: env.ARGON2_TIME_COST }),
    rateLimit: Object.freeze({
      windowMs: env.LOGIN_WINDOW_MS,
      loginPerAccount: env.LOGIN_MAX_ATTEMPTS_PER_ACCOUNT,
      loginPerIp: env.LOGIN_MAX_ATTEMPTS_PER_IP,
      registerPerHour: env.REGISTER_MAX_PER_HOUR,
      apiPerWindow: env.API_MAX_PER_WINDOW,
    }),
    logLevel: env.LOG_LEVEL,
  });
}

module.exports = { loadConfig };
