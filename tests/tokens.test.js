'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { JWT_SECRET, VALID_USER, buildTestApp, post, get, refreshCookieFrom, registerAndLogin } = require('./helpers');

describe('Tokens e rotas protegidas', () => {
  let ctx;
  before(() => { ctx = buildTestApp(); });
  after(() => ctx.close());

  const sign = (claims, opts = {}, secret = JWT_SECRET) =>
    jwt.sign(claims, secret, {
      algorithm: 'HS256', issuer: 'intranet-auth', audience: 'intranet-app', subject: '1', expiresIn: 60, ...opts,
    });

  it('permite acessar rota protegida com token válido e não vaza o hash', async () => {
    const { accessToken } = await registerAndLogin(ctx.app);
    const res = await get(ctx.app, '/api/users/me', accessToken).expect(200);
    assert.equal(res.body.user.username, VALID_USER.username);
    assert.equal(res.body.user.email, VALID_USER.email);
    assert.equal(JSON.stringify(res.body).toLowerCase().includes('hash'), false);
  });

  it('nega acesso sem token, com esquema errado ou token malformado', async () => {
    await get(ctx.app, '/api/users/me').expect(401);
    await get(ctx.app, '/api/users/me', 'lixo.lixo.lixo').expect(401);
    await get(ctx.app, '/api/users/me').set('Authorization', 'Basic abc').expect(401);
  });

  it('nega token expirado com código específico', async () => {
    const expired = sign({ sid: 'x' }, { expiresIn: -10 });
    const res = await get(ctx.app, '/api/users/me', expired).expect(401);
    assert.equal(res.body.error.code, 'TOKEN_EXPIRED');
  });

  it('nega token assinado com outra chave, "alg: none", issuer ou audience incorretos', async () => {
    const forged = sign({ sid: 'x' }, {}, 'outra-chave-qualquer-com-mais-de-32-chars!!');
    await get(ctx.app, '/api/users/me', forged).expect(401);

    const none = jwt.sign({ sid: 'x', sub: '1' }, '', { algorithm: 'none' });
    await get(ctx.app, '/api/users/me', none).expect(401);

    await get(ctx.app, '/api/users/me', sign({ sid: 'x' }, { issuer: 'outro' })).expect(401);
    await get(ctx.app, '/api/users/me', sign({ sid: 'x' }, { audience: 'outro' })).expect(401);
  });

  it('nega token válido cuja sessão não existe', async () => {
    const res = await get(ctx.app, '/api/users/me', sign({ sid: 'sessao-inexistente' })).expect(401);
    assert.equal(res.body.error.code, 'SESSION_REVOKED');
  });

  describe('renovação (refresh)', () => {
    it('emite novo access token e rotaciona o refresh token', async () => {
      const { cookie } = await registerAndLogin(ctx.app, { ...VALID_USER, username: 'ana.lima', email: 'ana@empresa.com.br' });
      const res = await post(ctx.app, '/api/auth/refresh', undefined, { cookie }).expect(200);
      assert.ok(res.body.accessToken);
      const newCookie = refreshCookieFrom(res);
      assert.ok(newCookie);
      assert.notEqual(newCookie, cookie);
      await get(ctx.app, '/api/users/me', res.body.accessToken).expect(200);
    });

    it('nega refresh sem cookie ou com cookie inválido', async () => {
      await post(ctx.app, '/api/auth/refresh', undefined).expect(401);
      await post(ctx.app, '/api/auth/refresh', undefined, { cookie: 'refresh_token=invalido' }).expect(401);
    });

    it('detecta reutilização de refresh token e revoga a sessão inteira', async () => {
      const { cookie: first, accessToken } = await registerAndLogin(ctx.app, { ...VALID_USER, username: 'bia.reis', email: 'bia@empresa.com.br' });
      const rotated = await post(ctx.app, '/api/auth/refresh', undefined, { cookie: first }).expect(200);
      const second = refreshCookieFrom(rotated);

      // Token antigo reaparece (possível roubo) => 401 e sessão revogada
      await post(ctx.app, '/api/auth/refresh', undefined, { cookie: first }).expect(401);
      await post(ctx.app, '/api/auth/refresh', undefined, { cookie: second }).expect(401);
      await get(ctx.app, '/api/users/me', accessToken).expect(401);
      await get(ctx.app, '/api/users/me', rotated.body.accessToken).expect(401);
    });

    it('guarda apenas o hash do refresh token no banco', async () => {
      const { cookie } = await registerAndLogin(ctx.app, { ...VALID_USER, username: 'caio.neto', email: 'caio@empresa.com.br' });
      const raw = cookie.split('=')[1];
      const rows = ctx.db.prepare('SELECT token_hash FROM refresh_tokens').all();
      assert.ok(rows.length > 0);
      assert.ok(rows.every((r) => r.token_hash !== raw && /^[0-9a-f]{64}$/.test(r.token_hash)));
    });
  });

  describe('revogação (logout)', () => {
    it('logout invalida o access token imediatamente e limpa o cookie', async () => {
      const { cookie, accessToken } = await registerAndLogin(ctx.app, { ...VALID_USER, username: 'dani.cruz', email: 'dani@empresa.com.br' });
      const res = await post(ctx.app, '/api/auth/logout', undefined, { cookie }).expect(204);
      assert.match(res.headers['set-cookie'].find((c) => c.startsWith('refresh_token=')), /refresh_token=;/);

      await get(ctx.app, '/api/users/me', accessToken).expect(401);
      await post(ctx.app, '/api/auth/refresh', undefined, { cookie }).expect(401);
    });

    it('logout é idempotente', async () => {
      await post(ctx.app, '/api/auth/logout', undefined).expect(204);
    });

    it('logout-all encerra todas as sessões do usuário', async () => {
      const user = { ...VALID_USER, username: 'edu.alves', email: 'edu@empresa.com.br' };
      const a = await registerAndLogin(ctx.app, user);
      const b = await post(ctx.app, '/api/auth/login', { username: user.username, password: user.password }).expect(200);

      await post(ctx.app, '/api/auth/logout-all', undefined, { token: a.accessToken }).expect(204);
      await get(ctx.app, '/api/users/me', a.accessToken).expect(401);
      await get(ctx.app, '/api/users/me', b.body.accessToken).expect(401);
    });

    it('logout-all exige autenticação', async () => {
      await post(ctx.app, '/api/auth/logout-all', undefined).expect(401);
    });
  });
});
