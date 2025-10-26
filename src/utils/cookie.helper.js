// src/utils/cookie.helper.js
const REFRESH_COOKIE_NAME = process.env.REFRESH_COOKIE_NAME || 'refreshToken';
const COOKIE_MAX_AGE = parseInt(process.env.REFRESH_COOKIE_MAX_AGE || String(7 * 24 * 60 * 60 * 1000), 10);

/**
 * Build cookie options for refresh token.
 * - In production (NODE_ENV === 'production') we use SameSite=None and Secure=true (requires HTTPS).
 * - In development we fall back to SameSite=Lax and Secure=false so local dev works without HTTPS.
 */
function buildRefreshCookieOptions() {
  const isProd = process.env.NODE_ENV === 'production';

  const opts = {
    httpOnly: true,
    secure: !!isProd, // must be true for SameSite=None to be accepted in browsers
    sameSite: isProd ? 'None' : 'Lax', // None for cross-site (prod with HTTPS), Lax simpler for dev
    path: process.env.REFRESH_COOKIE_PATH || '/',
    maxAge: COOKIE_MAX_AGE,
  };

  // optional domain (useful for multi-subdomain setups)
  if (process.env.REFRESH_COOKIE_DOMAIN) {
    opts.domain = process.env.REFRESH_COOKIE_DOMAIN;
  }

  return opts;
}

function setRefreshCookie(res, token) {
  if (!token || !res || typeof res.cookie !== 'function') return;
  const opts = buildRefreshCookieOptions();
  // set cookie (httpOnly) — token is opaque string (JWT or JTI wrapper)
  res.cookie(REFRESH_COOKIE_NAME, token, opts);
}

function clearRefreshCookie(res) {
  if (!res || typeof res.clearCookie !== 'function') return;
  const opts = buildRefreshCookieOptions();
  // clearCookie uses same options to ensure the cookie removed matches the one set
  res.clearCookie(REFRESH_COOKIE_NAME, opts);
  // additionally set an expired cookie as a fallback
  res.cookie(REFRESH_COOKIE_NAME, '', {
    ...opts,
    maxAge: 0,
    expires: new Date(0)
  });
}

module.exports = { setRefreshCookie, clearRefreshCookie };
