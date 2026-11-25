// Validação do lado do cliente (apenas UX). O servidor revalida tudo — nunca confie só no front-end.
// Mantenha estas regras alinhadas com src/validators/authSchemas.js.

const USERNAME_RE = /^[A-Za-z0-9_.-]+$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const normalizePhone = (value) => value.trim().replace(/[\s().-]/g, '');

export function validateLogin({ username, password }) {
  const errors = {};
  if (!username.trim()) errors.username = 'Informe o nome de usuário.';
  if (!password) errors.password = 'Informe a senha.';
  return errors;
}

export function validateRegister({ username, email, phone, password, confirm }) {
  const errors = {};
  const user = username.trim();

  if (user.length < 3 || user.length > 30) errors.username = 'O nome de usuário deve ter de 3 a 30 caracteres.';
  else if (!USERNAME_RE.test(user)) errors.username = 'Use apenas letras, números, ponto, hífen e sublinhado.';

  const mail = email.trim();
  if (!mail) errors.email = 'Informe o e-mail.';
  else if (mail.length > 254 || !EMAIL_RE.test(mail)) errors.email = 'Informe um e-mail válido.';

  if (!/^\+?\d{10,15}$/.test(normalizePhone(phone))) {
    errors.phone = 'Telefone inválido. Use DDD + número, ex.: (11) 91234-5678.';
  }

  if (password.length < 10) errors.password = 'A senha deve ter ao menos 10 caracteres.';
  else if (password.length > 128) errors.password = 'A senha deve ter no máximo 128 caracteres.';
  else if (!/[a-z]/.test(password)) errors.password = 'A senha deve ter ao menos uma letra minúscula.';
  else if (!/[A-Z]/.test(password)) errors.password = 'A senha deve ter ao menos uma letra maiúscula.';
  else if (!/\d/.test(password)) errors.password = 'A senha deve ter ao menos um número.';
  else if (user && password.toLowerCase().includes(user.toLowerCase())) {
    errors.password = 'A senha não pode conter o nome de usuário.';
  }

  if (!errors.password && confirm !== password) errors.confirm = 'As senhas não coincidem.';
  return errors;
}
