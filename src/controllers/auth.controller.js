// controllers/auto.controller.js
const authService = require('../services/auth.service');
const HttpError = require('../utils/httpError');
const validator = require('validator');
const { setRefreshCookie, clearRefreshCookie } = require('../utils/cookie.helper');

const REFRESH_COOKIE_NAME = process.env.REFRESH_COOKIE_NAME || 'refreshToken';
const REFRESH_COOKIE_SECURE = process.env.NODE_ENV === 'production';
const REFRESH_COOKIE_HTTPONLY = true;
const REFRESH_COOKIE_SAMESITE = process.env.REFRESH_COOKIE_SAMESITE || 'Strict'; // 'Lax' often useful for SPA flows
const REFRESH_COOKIE_MAX_AGE = parseInt(process.env.REFRESH_COOKIE_MAX_AGE || String(7 * 24 * 60 * 60 * 1000), 10);
const REFRESH_COOKIE_PATH = process.env.REFRESH_COOKIE_PATH || '/';
const REFRESH_COOKIE_DOMAIN = process.env.REFRESH_COOKIE_DOMAIN; // optional
// Toggle: if true, controller will include refreshToken in JSON body (not recommended in production)
const RETURN_REFRESH_IN_BODY = (process.env.RETURN_REFRESH_IN_BODY || 'false').toLowerCase() === 'true';

// Helper: normalize + sanitize an email
function normalizeEmail(email) {
  if (!email) return '';
  return validator.normalizeEmail(String(email).trim(), { gmail_remove_dots: false }) || String(email).trim().toLowerCase();
}
// small helpers to keep responses consistent
function badRequest(res, message = 'Bad Request', details = []) {
  return res.status(400).json({ error: message, details });
}
function unauthorized(res, message = 'Unauthorized') {
  return res.status(401).json({ error: message });
}
function conflict(res, message = 'Conflict') {
  return res.status(409).json({ error: message });
}
function sendJson(res, status, payload) {
  res.type('application/json');
  return res.status(status).json(payload);
}
// small audit/log hook (replace with Winston/OpenTelemetry)
function auditLog(event, meta = {}) {
  // implement real logging here; do NOT log passwords
  // e.g., logger.info(`[auth] ${event}`, meta)
  // For now just a debug console in non-prod
  if (process.env.NODE_ENV !== 'production') {
    console.debug('[AUDIT]', event, meta);
  }
}

/* -------------------------
   Controller functions
   ------------------------- */
async function signup(req, res, next) {
  try {
    if (!req.body || Object.keys(req.body).length === 0) {
      return badRequest(res, 'Request body is required');
    }

    let { email, password, name } = req.body;
    email = normalizeEmail(email);
    name = (name || '').toString().trim();

    const problems = [];
    if (!email) problems.push({ field: 'email', message: 'Email is required' });
    else if (!validator.isEmail(email)) problems.push({ field: 'email', message: 'Invalid email format' });

    if (!password) problems.push({ field: 'password', message: 'Password is required' });
    else if (typeof password !== 'string' || password.length < 8) problems.push({ field: 'password', message: 'Password must be at least 8 characters long' });

    if (name && name.length > 100) problems.push({ field: 'name', message: 'Name is too long (max 100 chars)' });

    if (problems.length) return badRequest(res, 'Invalid signup payload', problems);

    // anti-abuse hook (optional): check rate-limiter or captcha
    // if (req.rateLimit && req.rateLimit.remaining === 0) return res.status(429).json({ error: 'Too many requests' });

    const user = await authService.signup({ email, password, name });

    auditLog('user.signup', { userId: user._id.toString(), email });

    // RESTful: Location header for created resource
    res.location(`/users/${user._id}`);
    return sendJson(res, 201, { id: user._id, email: user.email, name: user.name });
  } catch (err) {
    if (err instanceof HttpError) {
      // Map expected HttpError codes; do not leak internal details.
      if (err.status === 409) return conflict(res, 'User already exists');
      return res.status(err.status).json({ error: err.message });
    }

    // Mongoose schema validation errors -> 400
    if (err && err.name === 'ValidationError' && err.errors) {
      const details = Object.keys(err.errors).map((k) => ({ field: k, message: err.errors[k].message }));
      return badRequest(res, 'Validation failed', details);
    }

    console.error('[SIGNUP] unexpected error', err && err.stack ? err.stack : err);
    return next(err);
  }
}

async function login(req, res, next) {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' });
    }

    // call service and wait for tokens + user
    const result = await authService.login({ email, password });
    // result expected shape: { user, accessToken, refreshToken }
    if (!result || !result.accessToken || !result.user) {
      // defensive: unexpected service response
      console.error('[LOGIN] unexpected service response', result);
      return res.status(500).json({ error: 'Authentication failed' });
    }

    // destructure after result is available
    const { user, accessToken, refreshToken } = result;

    // set refresh token as cookie (only if refreshToken present)
    if (refreshToken) {
      // setRefreshCookie should use the same cookie options as clearRefreshCookie
      setRefreshCookie(res, refreshToken);
    }

    // respond with user + access token (do NOT include refreshToken when using cookie mode)
    return res.json({
      user: { id: user._id, email: user.email, name: user.name },
      accessToken
    });
  } catch (err) {
    // map known service errors or let global handler handle unexpected ones
    if (err instanceof HttpError) {
      return res.status(err.status || 400).json({ error: err.message });
    }
    console.error('[LOGIN] unexpected error', err && (err.stack || err));
    return next(err);
  }
}

async function refresh(req, res, next) {
  try {
    // prefer cookie, fallback to body
    const incomingRefresh = req.cookies?.[REFRESH_COOKIE_NAME] || req.body?.refreshToken;
    if (!incomingRefresh) {
      return badRequest(res, 'refreshToken required');
    }

    // call service to rotate / validate
    const { accessToken, refreshToken: newRefresh, user } = await authService.refreshTokens(incomingRefresh);

    // rotate cookie when backend produced a new refresh token
    if (newRefresh) {
      // setRefreshCookie should encapsulate cookie options (httpOnly, sameSite, secure, path, maxAge)
      setRefreshCookie(res, newRefresh);
    }

    // audit (do not include token values)
    try {
      auditLog('token.refresh', { userId: user._id.toString(), ip: req.ip });
    } catch (auditErr) {
      // do not break the flow for audit failures; just log server-side
      console.warn('[REFRESH] audit failed', auditErr && (auditErr.message || auditErr));
    }

    // If you're using cookie-mode for refresh tokens, don't send the token in JSON.
    // Return only access token + user. If you explicitly want the refresh token in the body,
    // include `refreshToken: newRefresh` here (but avoid doing that in production).
    return sendJson(res, 200, {
      user: { id: user._id, email: user.email, name: user.name },
      accessToken
    });
  } catch (err) {
    // expected authentication failures -> 401
    if (
      err &&
      (err.code === 'INVALID_REFRESH_TOKEN' ||
        err.code === 'REFRESH_NOT_FOUND' ||
        (err instanceof HttpError && err.status === 401))
    ) {
      return unauthorized(res, 'Invalid or expired refresh token');
    }

    // unexpected -> log and forward
    console.error('[REFRESH] unexpected error', err && (err.stack || err));
    return next(err);
  }
}


async function logout(req, res, next) {
  try {
    const refreshToken = req.cookies?.[REFRESH_COOKIE_NAME] || req.body?.refreshToken;
    if (!refreshToken) return badRequest(res, 'refreshToken required');

    await authService.revokeRefreshToken(refreshToken);

    // clear cookie
    clearRefreshCookie(res);

    auditLog('user.logout', { ip: req.ip });

    // 204 No Content — logout succeeded
    return res.status(204).send();
  } catch (err) {
    console.error('[LOGOUT] unexpected error', err && err.stack ? err.stack : err);
    return next(err);
  }
}

// POST /auth/request-password-reset
async function requestPasswordResetController(req, res, next) {
  try {
    const { email } = req.body;
    // optional: pass origin so the service can build frontend link
    const origin = req.headers.origin || req.body.origin;
    await authService.requestPasswordReset({ email, origin });
    // Always return 200 OK to avoid user enumeration
    return res.json({ ok: true });
  } catch (err) {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
    console.error('[PASSWORD_RESET_REQUEST] unexpected error', err);
    return next(err);
  }
}

// POST /auth/reset-password
async function resetPasswordController(req, res, next) {
  try {
    const { token, newPassword } = req.body;
    await authService.resetPassword({ token, newPassword });
    return res.json({ ok: true });
  } catch (err) {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
    console.error('[PASSWORD_RESET] unexpected error', err);
    return next(err);
  }
}

// POST /auth/change-password (authenticated route)
// expects req.user.id (ensure your auth middleware sets req.user)
async function changePasswordController(req, res, next) {
  try {
    const userId = req.user && req.user.id;
    const { currentPassword, newPassword } = req.body;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    await authService.changePassword({ userId, currentPassword, newPassword });
    return res.json({ ok: true });
  } catch (err) {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
    console.error('[CHANGE_PASSWORD] unexpected error', err);
    return next(err);
  }
}

module.exports = {
  signup, login, refresh, logout,
  requestPasswordResetController,
  resetPasswordController,
  changePasswordController
};

