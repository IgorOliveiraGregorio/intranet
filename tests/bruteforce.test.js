'use strict';

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { VALID_USER, buildTestApp, post } = require('./helpers');

describe('Proteção contra força bruta', () => {
  let ctx;
  afterEach(() => ctx?.close());

  const attempt = (username, password) => post(ctx.app, '/api/auth/login', { username, password });

  it('bloqueia o usuário após N falhas, mesmo com a senha correta depois', async () => {
    ctx = buildTestApp({ LOGIN_MAX_ATTEMPTS_PER_ACCOUNT: '3' });
    await post(ctx.app, '/api/auth/register', VALID_USER).expect(201);

    for (let i = 0; i < 3; i += 1) {
      await attempt(VALID_USER.username, `errada-${i}`).expect(401);
    }
    const blocked = await attempt(VALID_USER.username, VALID_USER.password).expect(429);
    assert.equal(blocked.body.error.code, 'TOO_MANY_REQUESTS');
    assert.ok(blocked.headers['retry-after']);
  });

  it('não afeta outros usuários', async () => {
    ctx = buildTestApp({ LOGIN_MAX_ATTEMPTS_PER_ACCOUNT: '2' });
    await post(ctx.app, '/api/auth/register', VALID_USER).expect(201);
    await post(ctx.app, '/api/auth/register', { ...VALID_USER, username: 'outro.user', email: 'o@empresa.com.br' }).expect(201);

    await attempt(VALID_USER.username, 'x1').expect(401);
    await attempt(VALID_USER.username, 'x2').expect(401);
    await attempt(VALID_USER.username, 'x3').expect(429);
    await attempt('outro.user', VALID_USER.password).expect(200);
  });

  it('trata usuário inexistente exatamente como existente (sem enumeração)', async () => {
    ctx = buildTestApp({ LOGIN_MAX_ATTEMPTS_PER_ACCOUNT: '2' });
    await attempt('fantasma', 'x1').expect(401);
    await attempt('fantasma', 'x2').expect(401);
    const res = await attempt('fantasma', 'x3').expect(429);
    assert.equal(res.body.error.code, 'TOO_MANY_REQUESTS');
  });

  it('logins bem-sucedidos não consomem a cota de tentativas', async () => {
    ctx = buildTestApp({ LOGIN_MAX_ATTEMPTS_PER_ACCOUNT: '2' });
    await post(ctx.app, '/api/auth/register', VALID_USER).expect(201);
    for (let i = 0; i < 5; i += 1) {
      await attempt(VALID_USER.username, VALID_USER.password).expect(200);
    }
  });

  it('limita por IP ao variar nomes de usuário (password spraying)', async () => {
    ctx = buildTestApp({ LOGIN_MAX_ATTEMPTS_PER_IP: '3' });
    for (let i = 0; i < 3; i += 1) {
      await attempt(`alvo${i}`, 'chute').expect(401);
    }
    await attempt('alvo-novo', 'chute').expect(429);
  });

  it('limita a criação de contas por IP', async () => {
    ctx = buildTestApp({ REGISTER_MAX_PER_HOUR: '2' });
    await post(ctx.app, '/api/auth/register', { ...VALID_USER, username: 'user1', email: '1@e.com' }).expect(201);
    await post(ctx.app, '/api/auth/register', { ...VALID_USER, username: 'user2', email: '2@e.com' }).expect(201);
    await post(ctx.app, '/api/auth/register', { ...VALID_USER, username: 'user3', email: '3@e.com' }).expect(429);
  });
});
