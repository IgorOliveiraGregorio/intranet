'use strict';

const argon2 = require('argon2');

/**
 * Hash de senhas com Argon2id (vencedor do PHC; resistente a GPU/ASIC).
 * O sal aleatório de 16 bytes é gerado pela lib e embutido no hash.
 */
function createPasswordService({ memoryKib, timeCost }) {
  const options = { type: argon2.argon2id, memoryCost: memoryKib, timeCost, parallelism: 1 };
  let dummyHash;

  const hash = (plain) => argon2.hash(plain, options);

  async function verify(storedHash, plain) {
    try {
      return await argon2.verify(storedHash, plain);
    } catch {
      return false; // hash corrompido/formato inesperado => falha fechada
    }
  }

  /**
   * Usuário inexistente: gasta o mesmo tempo de uma verificação real, para que o tempo de
   * resposta não revele se o usuário existe (mitigação de enumeração por timing).
   */
  async function verifyDummy(plain) {
    dummyHash ??= await hash('senha-ficticia-para-equalizar-tempo');
    await verify(dummyHash, plain);
    return false;
  }

  return { hash, verify, verifyDummy };
}

module.exports = { createPasswordService };
