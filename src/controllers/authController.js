'use strict';

const REFRESH_COOKIE = 'refresh_token';
const COOKIE_PATH = '/api/auth'; // o cookie só viaja para as rotas de autenticação

function createAuthController({ authService, config }) {
  const baseCookie = {
    httpOnly: true, // inacessível a JavaScript => um XSS não consegue roubar o refresh token
    secure: config.cookieSecure,
    sameSite: 'strict',
    path: COOKIE_PATH,
  };

  const setRefreshCookie = (res, token, expiresAtSeconds) =>
    res.cookie(REFRESH_COOKIE, token, {
      ...baseCookie,
      maxAge: Math.max(0, expiresAtSeconds * 1000 - Date.now()),
    });
  const clearRefreshCookie = (res) => res.clearCookie(REFRESH_COOKIE, baseCookie);

  const accessPayload = (t) => ({ accessToken: t.accessToken, tokenType: 'Bearer', expiresIn: t.expiresIn });

  return {
    async register(req, res) {
      const user = await authService.register(req.body);
      res.status(201).json({ user });
    },

    async login(req, res) {
      const result = await authService.login(req.body);
      setRefreshCookie(res, result.refreshToken, result.refreshExpiresAt);
      res.json({ ...accessPayload(result), user: result.user });
    },

    refresh(req, res) {
      try {
        const result = authService.refresh(req.cookies?.[REFRESH_COOKIE]);
        setRefreshCookie(res, result.refreshToken, result.refreshExpiresAt);
        res.json(accessPayload(result));
      } catch (err) {
        clearRefreshCookie(res); // cookie inválido não deve ser reenviado
        throw err;
      }
    },

    logout(req, res) {
      authService.logout(req.cookies?.[REFRESH_COOKIE]);
      clearRefreshCookie(res);
      res.status(204).end();
    },

    logoutAll(req, res) {
      authService.logoutAll(req.auth.userId);
      clearRefreshCookie(res);
      res.status(204).end();
    },

    me(req, res) {
      res.json({ user: authService.getProfile(req.auth.userId) });
    },
  };
}

module.exports = { createAuthController };
