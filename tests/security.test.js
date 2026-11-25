'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { ORIGIN, VALID_USER, buildTestApp, post } = require('./helpers');

describe('Cabeçalhos, CORS e CSRF', () => {
  let ctx;
  before(() => { ctx = buildTestApp(); });
  after(() => ctx.close());

  it('envia cabeçalhos de segurança e esconde a tecnologia', async () => {
    const res = await request(ctx.app).get('/').expect(200);
    const csp = res.headers['content-security-policy'];
    assert.ok(csp.includes("default-src 'self'"));
    assert.ok(csp.includes("script-src 'self'"));
    assert.ok(!csp.includes("'unsafe-inline'"));
    assert.ok(csp.includes("frame-ancestors 'none'"));
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['referrer-policy'], 'no-referrer');
    assert.equal(res.headers['x-powered-by'], undefined);
  });

  it('serve as páginas do front-end', async () => {
    for (const page of ['/', '/login', '/register', '/dashboard']) {
      const res = await request(ctx.app).get(page).expect(200);
      assert.match(res.headers['content-type'], /html/);
    }
  });

  it('CORS só libera origens da lista', async () => {
    const ok = await request(ctx.app).options('/api/auth/login')
      .set('Origin', ORIGIN).set('Access-Control-Request-Method', 'POST');
    assert.equal(ok.headers['access-control-allow-origin'], ORIGIN);
    assert.equal(ok.headers['access-control-allow-credentials'], 'true');

    const evil = await request(ctx.app).options('/api/auth/login')
      .set('Origin', 'https://evil.example').set('Access-Control-Request-Method', 'POST');
    assert.equal(evil.headers['access-control-allow-origin'], undefined);
  });

  it('CSRF: bloqueia POST de origem não autorizada', async () => {
    const res = await post(ctx.app, '/api/auth/logout', undefined, { headers: { Origin: 'https://evil.example' } }).expect(403);
    assert.equal(res.body.error.code, 'CSRF_ORIGIN_DENIED');
  });

  it('CSRF: bloqueia POST sem o cabeçalho X-Requested-With', async () => {
    const res = await request(ctx.app).post('/api/auth/refresh').set('Origin', ORIGIN).expect(403);
    assert.equal(res.body.error.code, 'CSRF_HEADER_MISSING');
    // e um <form> clássico (urlencoded) também não passa
    await request(ctx.app).post('/api/auth/login').type('form').send('username=a&password=b').expect(403);
  });

  it('respostas de erro seguem o formato padrão e não vazam detalhes internos', async () => {
    const res = await request(ctx.app).get('/api/nao-existe').expect(404);
    assert.deepEqual(Object.keys(res.body), ['error']);
    assert.equal(res.body.error.code, 'NOT_FOUND');
    assert.ok(res.body.error.requestId);
    assert.ok(!JSON.stringify(res.body).includes('stack'));
  });

  it('API responde com Cache-Control: no-store', async () => {
    const res = await request(ctx.app).get('/api/health').expect(200);
    assert.equal(res.headers['cache-control'], 'no-store');
  });

  it('o banco usa índices únicos nos campos de busca', () => {
    const idx = ctx.db.prepare("SELECT name FROM sqlite_master WHERE type='index'").all().map((r) => r.name);
    for (const name of ['ux_users_username', 'ux_users_email', 'ix_sessions_user_id', 'ix_refresh_tokens_session']) {
      assert.ok(idx.includes(name), `índice ausente: ${name}`);
    }
    const plan = ctx.db.prepare('EXPLAIN QUERY PLAN SELECT id FROM users WHERE username = ?').all('x');
    assert.match(plan.map((p) => p.detail).join(' '), /USING (COVERING )?INDEX ux_users_username/);
  });

  it('dados de usuário ficam persistidos (cadastro real)', async () => {
    await post(ctx.app, '/api/auth/register', VALID_USER).expect(201);
    const row = ctx.db.prepare('SELECT username, email, phone FROM users WHERE username = ?').get(VALID_USER.username);
    assert.deepEqual({ ...row }, { username: 'maria.silva', email: 'maria@empresa.com.br', phone: '11912345678' });
  });
});
