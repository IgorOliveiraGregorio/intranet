'use strict';

const { z } = require('zod');

/**
 * Validação por lista de permissão (allowlist): só entra o que casa com o formato esperado.
 * Como username/e-mail/telefone não aceitam "<", ">", aspas etc., não há como gravar HTML/JS
 * no banco (defesa em profundidade contra XSS armazenado).
 * Estas regras são espelhadas em public/js/validators.js (a validação do front é só UX).
 */
const required = (label) => ({
  required_error: `Informe ${label}.`,
  invalid_type_error: `${label[0].toUpperCase()}${label.slice(1)} inválido.`,
});

const username = z
  .string(required('o nome de usuário'))
  .trim()
  .min(3, 'O nome de usuário deve ter ao menos 3 caracteres.')
  .max(30, 'O nome de usuário deve ter no máximo 30 caracteres.')
  .regex(/^[A-Za-z0-9_.-]+$/, 'Use apenas letras, números, ponto, hífen e sublinhado.');

const email = z
  .string(required('o e-mail'))
  .trim()
  .toLowerCase()
  .max(254, 'E-mail muito longo.')
  .email('Informe um e-mail válido.');

// Aceita máscaras comuns "(11) 91234-5678" e normaliza para "11912345678" / "+5511912345678".
const phone = z
  .string(required('o telefone'))
  .trim()
  .max(30, 'Telefone inválido.')
  .transform((v) => v.replace(/[\s().-]/g, ''))
  .refine((v) => /^\+?\d{10,15}$/.test(v), 'Telefone inválido. Use DDD + número, ex.: (11) 91234-5678.');

// Comprimento mínimo + composição; máximo evita DoS no hash (Argon2 consome memória/CPU).
const password = z
  .string(required('a senha'))
  .min(10, 'A senha deve ter ao menos 10 caracteres.')
  .max(128, 'A senha deve ter no máximo 128 caracteres.')
  .regex(/[a-z]/, 'A senha deve ter ao menos uma letra minúscula.')
  .regex(/[A-Z]/, 'A senha deve ter ao menos uma letra maiúscula.')
  .regex(/\d/, 'A senha deve ter ao menos um número.');

const registerSchema = z
  .object({ username, email, phone, password })
  .strict() // rejeita campos desconhecidos (evita mass assignment)
  .refine((d) => !d.password.toLowerCase().includes(d.username.toLowerCase()), {
    path: ['password'],
    message: 'A senha não pode conter o nome de usuário.',
  });

// No login só exigimos presença e limites de tamanho: nada que ajude a enumerar usuários.
const loginSchema = z
  .object({
    username: z
      .string(required('o nome de usuário'))
      .trim()
      .min(1, 'Informe o nome de usuário.')
      .max(30, 'Usuário ou senha inválidos.'),
    password: z
      .string(required('a senha'))
      .min(1, 'Informe a senha.')
      .max(128, 'Usuário ou senha inválidos.'),
  })
  .strict();

module.exports = { registerSchema, loginSchema };
