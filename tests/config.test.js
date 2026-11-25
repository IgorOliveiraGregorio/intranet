'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { loadConfig } = require('../src/config');

describe('Configuração', () => {
  it('falha sem JWT_SECRET e não imprime valores', () => {
    assert.throws(() => loadConfig({ JWT_SECRET: undefined }), (err) => {
      assert.match(err.message, /JWT_SECRET/);
      return true;
    });
  });

  it('rejeita segredo curto sem ecoar o valor', () => {
    assert.throws(() => loadConfig({ JWT_SECRET: 'curto-demais' }), (err) => {
      assert.match(err.message, /JWT_SECRET/);
      assert.ok(!err.message.includes('curto-demais'));
      return true;
    });
  });

  it('usa cookie Secure por padrão em produção', () => {
    const prod = loadConfig({ NODE_ENV: 'production', JWT_SECRET: 'x'.repeat(40) });
    const dev = loadConfig({ NODE_ENV: 'development', JWT_SECRET: 'x'.repeat(40) });
    assert.equal(prod.cookieSecure, true);
    assert.equal(dev.cookieSecure, false);
  });
});
