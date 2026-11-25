'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { VALID_USER, buildTestApp, post, refreshCookieFrom } = require('./helpers');

describe('Login', () => {
  let ctx;
  before(async () => {
    ctx = buildTestApp();
    await post(ctx.app, '/api/auth/register', VALID_USER).expect(201);
  });
  after(() => ctx.close());

  it('autentica e devolve access token JWT + refresh token em cookie seguro', async () => {
    const res = await post(ctx.app, '/api/auth/login', {
      username: VALID_USER.username, password: VALID_USER.password,
    }).expect(200);

    assert.equal(res.body.tokenType, 'Bearer');
    assert.equal(res.body.expiresIn, 900);
    assert.equal(res.body.accessToken.split('.').length, 3);
    assert.equal(res.body.user.username, VALID_USER.username);
    assert.equal(res.body.refreshToken, undefined); // refresh só vai no cookie

    const cookie = res.headers['set-cookie'].find((c) => c.startsWith('refresh_token='));
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=Strict/i);
    assert.match(cookie, /Path=\/api\/auth/i);
    assert.equal(res.headers['cache-control'], 'no-store');
  });

  it('o usuário é encontrado sem diferenciar maiúsculas', async () => {
    await post(ctx.app, '/api/auth/login', {
      username: 'MARIA.SILVA', password: VALID_USER.password,
    }).expect(200);
  });

  it('não revela se o usuário existe: mesma resposta para senha errada e usuário inexistente', async () => {
    const wrongPassword = await post(ctx.app, '/api/auth/login', {
      username: VALID_USER.username, password: 'SenhaErrada999',
    }).expect(401);
    const unknownUser = await post(ctx.app, '/api/auth/login', {
      username: 'fantasma', password: 'SenhaErrada999',
    }).expect(401);

    assert.equal(wrongPassword.body.error.code, 'INVALID_CREDENTIALS');
    assert.equal(wrongPassword.body.error.code, unknownUser.body.error.code);
    assert.equal(wrongPassword.body.error.message, unknownUser.body.error.message);
    assert.equal(refreshCookieFrom(wrongPassword), null);
  });

  it('valida campos obrigatórios e tipos', async () => {
    const empty = await post(ctx.app, '/api/auth/login', {}).expect(400);
    assert.ok(empty.body.error.details.username);
    assert.ok(empty.body.error.details.password);
    await post(ctx.app, '/api/auth/login', { username: { $gt: '' }, password: { $gt: '' } }).expect(400);
  });

  it('não é vulnerável a SQL injection no login', async () => {
    for (const username of ["' OR '1'='1", "maria.silva' --", '" OR ""="']) {
      const res = await post(ctx.app, '/api/auth/login', { username, password: "' OR '1'='1" });
      assert.equal(res.status, 401);
    }
  });

  it('rejeita JSON malformado e corpo grande com erro padronizado', async () => {
    const bad = await post(ctx.app, '/api/auth/login', '{"username": ', { headers: { 'Content-Type': 'application/json' } }).expect(400);
    assert.equal(bad.body.error.code, 'INVALID_JSON');
    assert.ok(bad.body.error.requestId);

    const big = await post(ctx.app, '/api/auth/login', { username: 'a', password: 'x'.repeat(20_000) }).expect(413);
    assert.equal(big.body.error.code, 'PAYLOAD_TOO_LARGE');
  });
});
