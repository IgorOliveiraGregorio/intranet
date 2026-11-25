// Cliente da API. O access token (curto) fica só em memória: não vai para localStorage,
// então um XSS não consegue "levar" um token de longa duração. O refresh token fica em
// cookie HttpOnly, que o JavaScript nem enxerga.

let accessToken = null;
let refreshInFlight = null;

export class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

async function send(path, { method = 'GET', body, token } = {}) {
  const headers = { Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest' }; // anti-CSRF
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;

  let res;
  try {
    res = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'NETWORK_ERROR', 'Não foi possível conectar ao servidor. Verifique sua conexão.');
  }
  if (res.status === 204) return null;

  let data = null;
  try { data = await res.json(); } catch { /* resposta sem JSON */ }
  if (!res.ok) {
    const e = data?.error;
    throw new ApiError(res.status, e?.code ?? 'UNKNOWN', e?.message ?? 'Erro inesperado. Tente novamente.', e?.details);
  }
  return data;
}

export async function login(credentials) {
  const data = await send('/api/auth/login', { method: 'POST', body: credentials });
  accessToken = data.accessToken;
  return data.user;
}

export const register = (payload) => send('/api/auth/register', { method: 'POST', body: payload });

/** Renova o access token usando o cookie. Chamadas simultâneas compartilham a mesma requisição. */
export function refreshSession() {
  refreshInFlight ??= send('/api/auth/refresh', { method: 'POST' })
    .then((data) => { accessToken = data.accessToken; })
    .finally(() => { refreshInFlight = null; });
  return refreshInFlight;
}

/** Requisição autenticada: renova o token se faltar ou expirar (1 nova tentativa). */
async function authed(path, options = {}) {
  if (!accessToken) await refreshSession();
  try {
    return await send(path, { ...options, token: accessToken });
  } catch (err) {
    if (err.status !== 401) throw err;
    await refreshSession();
    return send(path, { ...options, token: accessToken });
  }
}

export const getMe = async () => (await authed('/api/users/me')).user;

export async function logout() {
  try {
    await send('/api/auth/logout', { method: 'POST' });
  } finally {
    accessToken = null;
  }
}

export async function logoutAll() {
  await authed('/api/auth/logout-all', { method: 'POST' });
  accessToken = null;
}
