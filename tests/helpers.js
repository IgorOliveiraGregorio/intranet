'use strict';

const request = require('supertest');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/app');

const ORIGIN = 'http://localhost:3000';
const JWT_SECRET = 'segredo-de-teste-com-mais-de-32-caracteres!!';

const VALID_USER = Object.freeze({
  username: 'maria.silva',
  email: 'maria@empresa.com.br',
  phone: '(11) 91234-5678',
  password: 'SenhaForte123',
});

/** Cria uma instância isolada (banco em memória, limites configuráveis). */
function buildTestApp(overrides = {}) {
  const config = loadConfig({
    NODE_ENV: 'test',
    JWT_SECRET,
    DB_PATH: ':memory:',
    LOG_LEVEL: 'silent',
    ALLOWED_ORIGINS: ORIGIN,
    ARGON2_MEMORY_KIB: '1024', // barato nos testes
    ARGON2_TIME_COST: '2',
    LOGIN_MAX_ATTEMPTS_PER_ACCOUNT: '100',
    LOGIN_MAX_ATTEMPTS_PER_IP: '100',
    REGISTER_MAX_PER_HOUR: '100',
    ...overrides,
  });
  const ctx = createApp(config);
  return { ...ctx, config };
}

/** POST com os cabeçalhos que o front-end envia (Origin + X-Requested-With). */
function post(app, path, body, { cookie, token, headers } = {}) {
  const req = request(app)
    .post(path)
    .set('Origin', ORIGIN)
    .set('X-Requested-With', 'XMLHttpRequest');
  if (cookie) req.set('Cookie', cookie);
  if (token) req.set('Authorization', `Bearer ${token}`);
  if (headers) for (const [k, v] of Object.entries(headers)) req.set(k, v);
  return req.send(body);
}

const get = (app, path, token) => {
  const req = request(app).get(path);
  return token ? req.set('Authorization', `Bearer ${token}`) : req;
};

/** Extrai "refresh_token=valor" do Set-Cookie para reenviar manualmente. */
function refreshCookieFrom(res) {
  const raw = (res.headers['set-cookie'] || []).find((c) => c.startsWith('refresh_token='));
  return raw ? raw.split(';')[0] : null;
}

async function registerAndLogin(app, user = VALID_USER) {
  await post(app, '/api/auth/register', user).expect(201);
  const res = await post(app, '/api/auth/login', { username: user.username, password: user.password }).expect(200);
  return { res, accessToken: res.body.accessToken, cookie: refreshCookieFrom(res) };
}

module.exports = { ORIGIN, JWT_SECRET, VALID_USER, buildTestApp, post, get, refreshCookieFrom, registerAndLogin };
