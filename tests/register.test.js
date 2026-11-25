'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { VALID_USER, buildTestApp, post } = require('./helpers');

describe('Cadastro', () => {
  let ctx;
  before(() => { ctx = buildTestApp(); });
  after(() => ctx.close());

  it('cria o usuário, normaliza dados e não devolve a senha', async () => {
    const res = await post(ctx.app, '/api/auth/register', { ...VALID_USER, email: 'MARIA@Empresa.com.br' }).expect(201);
    assert.equal(res.body.user.username, 'maria.silva');
    assert.equal(res.body.user.email, 'maria@empresa.com.br'); // minúsculas
    assert.equal(res.body.user.phone, '11912345678'); // máscara removida
    assert.equal(JSON.stringify(res.body).includes('password'), false);
    assert.equal(JSON.stringify(res.body).includes('SenhaForte123'), false);
  });

  it('armazena a senha somente como hash Argon2id com salt', () => {
    const row = ctx.db.prepare('SELECT password_hash FROM users WHERE username = ?').get('maria.silva');
    assert.match(row.password_hash, /^\$argon2id\$/);
    assert.ok(!row.password_hash.includes(VALID_USER.password));
  });

  it('gera hashes diferentes para a mesma senha (salt único)', async () => {
    await post(ctx.app, '/api/auth/register', {
      ...VALID_USER, username: 'joao.souza', email: 'joao@empresa.com.br',
    }).expect(201);
    const rows = ctx.db.prepare('SELECT password_hash FROM users').all();
    assert.equal(rows.length, 2);
    assert.notEqual(rows[0].password_hash, rows[1].password_hash);
  });

  it('rejeita usuário duplicado (sem diferenciar maiúsculas)', async () => {
    const res = await post(ctx.app, '/api/auth/register', {
      ...VALID_USER, username: 'MARIA.SILVA', email: 'outra@empresa.com.br',
    }).expect(409);
    assert.equal(res.body.error.code, 'CONFLICT');
    assert.ok(res.body.error.details.username);
    assert.equal(res.body.error.details.email, undefined);
  });

  it('rejeita e-mail duplicado', async () => {
    const res = await post(ctx.app, '/api/auth/register', {
      ...VALID_USER, username: 'outra.pessoa',
    }).expect(409);
    assert.ok(res.body.error.details.email);
  });

  it('valida o formato de cada campo e informa todos os erros', async () => {
    const res = await post(ctx.app, '/api/auth/register', {
      username: 'a b', email: 'nao-e-email', phone: '123', password: 'curta',
    }).expect(400);
    assert.equal(res.body.error.code, 'VALIDATION_ERROR');
    for (const field of ['username', 'email', 'phone', 'password']) {
      assert.ok(res.body.error.details[field], `esperava erro em ${field}`);
    }
  });

  it('exige senha com minúscula, maiúscula e número', async () => {
    for (const password of ['somenteminusculas1', 'SOMENTEMAIUSCULAS1', 'SemNumeroNenhum']) {
      const res = await post(ctx.app, '/api/auth/register', { ...VALID_USER, username: 'novo.user', password }).expect(400);
      assert.ok(res.body.error.details.password);
    }
  });

  it('rejeita senha que contém o nome de usuário', async () => {
    const res = await post(ctx.app, '/api/auth/register', {
      ...VALID_USER, username: 'carlos', email: 'c@empresa.com.br', password: 'Carlos12345!',
    }).expect(400);
    assert.ok(res.body.error.details.password);
  });

  it('rejeita campos desconhecidos (mass assignment)', async () => {
    const res = await post(ctx.app, '/api/auth/register', {
      ...VALID_USER, username: 'hacker', email: 'h@empresa.com.br', isAdmin: true,
    }).expect(400);
    assert.equal(res.body.error.code, 'VALIDATION_ERROR');
  });

  it('bloqueia SQL injection e HTML/JS nos campos (allowlist)', async () => {
    const before = ctx.db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
    for (const username of ["admin' OR '1'='1", "x'; DROP TABLE users;--", '<script>alert(1)</script>']) {
      await post(ctx.app, '/api/auth/register', {
        ...VALID_USER, username, email: 'inj@empresa.com.br',
      }).expect(400);
    }
    assert.equal(ctx.db.prepare('SELECT COUNT(*) AS n FROM users').get().n, before);
  });

  it('rejeita tipos inesperados (objetos NoSQL-style) e corpo ausente', async () => {
    await post(ctx.app, '/api/auth/register', { ...VALID_USER, username: { $ne: null } }).expect(400);
    await post(ctx.app, '/api/auth/register', {}).expect(400);
  });
});
