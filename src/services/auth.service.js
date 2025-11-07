// services/auth.service.js
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const dayjs = require('dayjs');
const validator = require('validator'); // npm i validator
const ms = require('ms'); // npm i ms
const mongoose = require('mongoose');

const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const PasswordResetToken = require('../models/PasswordResetToken');
const { signAccessToken, signRefreshToken, verifyRefreshToken } = require('../utils/jwt');
const HttpError = require('../utils/httpError');
const mailer = require('../utils/mailer'); // implement sendPasswordResetEmail(email, link)

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10);
const REFRESH_TOKEN_EXPIRES = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';
const REFRESH_TOKEN_EXPIRES_MS = parseDurationToMs(REFRESH_TOKEN_EXPIRES) || 7 * 24 * 60 * 60 * 1000;
const PASSWORD_RESET_TOKEN_EXPIRES = process.env.PASSWORD_RESET_TOKEN_EXPIRES || '1h'; // e.g. 1h
const PASSWORD_RESET_TOKEN_EXPIRES_MS = parseDurationToMs(process.env.PASSWORD_RESET_TOKEN_EXPIRES || '1h') || 3600_000;

// --- safe transaction & optional-session helpers ----------------
/**
 * Attempts to start a real transaction; returns session or null.
 * Does NOT throw when transactions are unsupported (standalone mongod).
 */
async function safeStartTransaction() {
  // immediate opt-out via env var (useful for dev or standalone mongod)
  if (process.env.DISABLE_MONGO_TRANSACTIONS === 'true') {
    return null;
  }

  let session;
  try {
    session = await mongoose.startSession();
  } catch (e) {
    return null;
  }
  try {
    session.startTransaction();
    return session;
  } catch (e) {
    try { await session.endSession(); } catch (_) { /* ignore */ }
    return null;
  }
}

/**
 * UpdateMany that only passes session option when session exists.
 */
async function updateManyOptionalSession(Model, filter, update, session, options = {}) {
  if (session) {
    const opts = Object.assign({}, options, { session });
    return Model.updateMany(filter, update, opts);
  }
  return Model.updateMany(filter, update, options);
}

function normalizeEmail(email) {
  return validator.normalizeEmail(String(email || '').trim(), { gmail_remove_dots: false }) || String(email || '').trim().toLowerCase();
}

function ensurePasswordPolicy(password) {
  if (!password || String(password).length < 8) {
    throw new HttpError('Password must be at least 8 characters long.', 400, 'WEAK_PASSWORD');
  }
}

async function signup({ email, name, password }) {
  email = normalizeEmail(email);
  if (!validator.isEmail(email)) throw new HttpError('Invalid email', 400, 'INVALID_EMAIL');
  ensurePasswordPolicy(password);

  const existing = await User.findOne({ email }).lean();
  if (existing) throw new HttpError('User already exists', 409, 'USER_EXISTS');

  const user = new User({
    email,
    name: String(name || '').trim(),
  });

  await user.setPassword(password);
  await user.save();

  return user;
}

async function login({ email, password }) {
  email = normalizeEmail(email);
  if (!validator.isEmail(email)) {

    throw new HttpError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
  }
  if (!password) throw new HttpError('Invalid credentials', 401, 'INVALID_CREDENTIALS');

  const user = await User.findOne({ email });
  if (!user) {
    throw new HttpError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
  }

  const ok = await user.validatePassword(password);
  if (!ok) {
    throw new HttpError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
  }

  const accessToken = signAccessToken({
    id: user._id.toString(),
    email: user.email,
    role: user.role,
    tokenVersion: user.tokenVersion
  });

  const { refreshToken } = await createRefreshTokenForUser(user);
  console.log(refreshToken)
  return { user, accessToken, refreshToken };
}

async function createRefreshTokenForUser(user, session = null) {
  // Generate a random token id (jti)
  const jti = crypto.randomBytes(32).toString('hex');
  // Hash the token id before storing (we store only hash)
  const tokenHash = await bcrypt.hash(jti, BCRYPT_ROUNDS);

  const expiresIn = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';
  const expiresMs = parseDurationToMs(expiresIn);

  let expiresAt;
  if (expiresMs > 0) {
    expiresAt = dayjs().add(expiresMs, 'ms').toDate();
  } else {
    expiresAt = dayjs().add(7, 'day').toDate();
  }

  // create document using session if provided (so it participates in transaction)
  if (session) {
    const doc = new RefreshToken({
      userId: user._id,
      tokenHash,
      jti,
      expiresAt
    });
    await doc.save({ session });
  } else {
    await RefreshToken.create({
      userId: user._id,
      tokenHash,
      jti,
      expiresAt
    });
  }

  // sign refresh token JWT containing jti & userId
  const refreshToken = signRefreshToken({ id: user._id.toString(), jti });

  return { refreshToken, jti };
}

// Rotate refresh tokens - atomic using mongoose session
// Rotate refresh tokens - session-safe
async function refreshTokens(refreshTokenStr) {
  if (!refreshTokenStr) {
    const e = new HttpError('refreshToken required', 400, 'MISSING_REFRESH_TOKEN');
    throw e;
  }

  let payload;
  try {
    payload = verifyRefreshToken(refreshTokenStr);
  } catch (err) {
    const e = new HttpError('Invalid refresh token (verify failed)', 401, 'INVALID_REFRESH_TOKEN');
    throw e;
  }

  const { id: userId, jti } = payload || {};
  if (!userId || !jti) {
    throw new HttpError('Invalid refresh token payload', 401, 'INVALID_REFRESH_TOKEN');
  }

  const session = await safeStartTransaction();
  const usedTransaction = !!session;

  try {
    // Query matching non-revoked tokens for this user (attach session only if available)
    let candidatesQuery = RefreshToken.find({ userId, revoked: false }).sort({ createdAt: -1 });
    if (usedTransaction) candidatesQuery = candidatesQuery.session(session);
    const candidates = await candidatesQuery.exec();

    // find the record whose hashed jti matches (and is not expired)
    let tokenRecord = null;
    for (const rec of candidates) {
      if (rec.expiresAt && rec.expiresAt < new Date()) continue;
      // compare hashed jti -> tokenHash using bcrypt
      // eslint-disable-next-line no-await-in-loop
      const match = await bcrypt.compare(jti, rec.tokenHash);
      if (match) {
        tokenRecord = rec;
        break;
      }
    }

    // no matching record -> not found or revoked
    if (!tokenRecord) {
      if (usedTransaction && session) {
        try { await session.abortTransaction(); } catch (_) { /* ignore */ }
        try { await session.endSession(); } catch (_) { /* ignore */ }
      }
      throw new HttpError('Refresh token not found or revoked', 401, 'REFRESH_NOT_FOUND');
    }

    // If token found but already revoked (defensive)
    if (tokenRecord.revoked) {
      if (usedTransaction && session) {
        try { await session.abortTransaction(); } catch (_) { /* ignore */ }
        try { await session.endSession(); } catch (_) { /* ignore */ }
      }
      throw new HttpError('Refresh token already revoked', 401, 'REFRESH_REVOKED');
    }

    // mark old token revoked & update lastUsedAt (use session if available)
    tokenRecord.revoked = true;
    tokenRecord.lastUsedAt = new Date();
    if (usedTransaction && session) await tokenRecord.save({ session });
    else await tokenRecord.save();

    // fetch user (attach session if available)
    let userQuery = User.findById(userId);
    if (usedTransaction && session) userQuery = userQuery.session(session);
    const user = await userQuery.exec();

    if (!user) {
      if (usedTransaction && session) {
        try { await session.abortTransaction(); } catch (_) { /* ignore */ }
        try { await session.endSession(); } catch (_) { /* ignore */ }
      }
      throw new HttpError('User not found', 401, 'USER_NOT_FOUND');
    }

    // Optionally bump tokenVersion to force logout across devices when necessary
    // (uncomment if you want refresh rotation to also invalidate older access tokens)
    // user.tokenVersion = (user.tokenVersion || 0) + 1;
    // if (usedTransaction && session) await user.save({ session }); else await user.save();

    // create new tokens (createRefreshTokenForUser accepts optional session)
    const accessToken = signAccessToken({
      id: user._id.toString(),
      email: user.email,
      role: user.role,
      tokenVersion: user.tokenVersion
    });

    const { refreshToken, jti: newJti } = await createRefreshTokenForUser(user, session);

    // commit transaction if used
    if (usedTransaction && session) {
      await session.commitTransaction();
      await session.endSession();
    }

    // return the new tokens and the user object (lean if you want to strip fields)
    return { accessToken, refreshToken, user };
  } catch (err) {
    // cleanup if transaction was used
    if (usedTransaction && session) {
      try { await session.abortTransaction(); } catch (_) { /* ignore */ }
      try { await session.endSession(); } catch (_) { /* ignore */ }
    }
    // Rethrow the error so controller can map codes -> status
    throw err;
  }
}

async function revokeRefreshToken(refreshTokenStr) {
  // verify signature first - but don't throw raw errors
  let payload;
  try {
    payload = verifyRefreshToken(refreshTokenStr);
  } catch (err) {
    return false;
  }
  const { id: userId, jti } = payload || {};
  if (!userId || !jti) return false;

  // find candidates for user and compare hashed jti (we avoid raw jti storage)
  const candidates = await RefreshToken.find({ userId });
  for (const rec of candidates) {
    // eslint-disable-next-line no-await-in-loop
    const match = await bcrypt.compare(jti, rec.tokenHash);
    if (match) {
      rec.revoked = true;
      await rec.save();
      return true;
    }
  }
  return false;
}

function parseDurationToMs(s) {
  if (!s) return 0;
  try {
    // prefer ms package
    const val = ms(s);
    if (typeof val === 'number') return val;
  } catch (e) { /* ignore */ }

  // fallback to custom parsing like "7d", "15m", "1h"
  const m = /^(\d+)([mhd])$/.exec(s);
  if (m) {
    const num = parseInt(m[1], 10);
    const unit = m[2];
    switch (unit) {
      case 'm': return num * 60 * 1000;
      case 'h': return num * 60 * 60 * 1000;
      case 'd': return num * 24 * 60 * 60 * 1000;
      default: return 0;
    }
  }
  const parsed = parseInt(s, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

/**
 * Request a password reset for the given email.
 * - Does NOT reveal whether the user exists (returns success regardless).
 * - Creates a one-time token, stores hashed token, and sends email with raw token.
 */
async function requestPasswordReset({ email, origin }) {
  if (!email) {
    throw new HttpError('Invalid request', 400, 'INVALID_REQUEST');
  }
  // normalize email if you use normalization elsewhere
  // email = normalizeEmail(email);

  // Find user; if not found we still respond success to avoid enumeration
  const user = await User.findOne({ email });

  // If user not found -> still return success (but do NOT create token)
  if (!user) {
    // optionally log suspicious request
    return { ok: true };
  }

  // Rate-limit / abuse checks should be applied here (Redis counters, etc).
  // Generate raw token (sufficient length)
  const rawToken = crypto.randomBytes(32).toString('hex'); // 64 hex chars
  const tokenHash = await bcrypt.hash(rawToken, BCRYPT_ROUNDS);
  const expiresAt = new Date(Date.now() + PASSWORD_RESET_TOKEN_EXPIRES_MS);

  // Save hashed token (single-use). If you want multiple outstanding tokens, keep as-is.
  await PasswordResetToken.create({
    userId: user._id,
    tokenHash,
    expiresAt,
    used: false
  });

  // Build reset link (frontend route) - origin should be provided by caller or from env
  // e.g., https://app.example.com/reset-password?token=RAW_TOKEN
  const frontendOrigin = origin || process.env.FRONTEND_ORIGIN || 'http://localhost:4200';
  const resetPath = process.env.PASSWORD_RESET_PATH || '/reset-password';
  const resetUrl = `${frontendOrigin.replace(/\/$/, '')}${resetPath}?token=${rawToken}&uid=${user._id.toString()}`;

  // send email (non-blocking best practice: queue send); here we await for simplicity
  try {
    await mailer.sendPasswordResetEmail(user.email, resetUrl, { name: user.name });
  } catch (e) {
    // If mail failed, you can choose to delete created token to avoid orphan tokens — or keep and let retry.
    console.error('Failed to send password reset email', e);
    // We intentionally don't reveal to caller; still return ok (or return partial info)
  }

  return { ok: true };
}

/**
 * Reset the password using the raw token received by email + new password.
 * - validates token (exists, not used, not expired)
 * - sets new password on user
 * - marks token used
 * - increments tokenVersion and revokes all refresh tokens for that user
 */
// Reset the password using the raw token received by email + new password.
async function resetPassword({ token: rawToken, newPassword, uid = null }) {
  // Validate inputs
  if (!rawToken || !newPassword) {
    throw new HttpError('Invalid request', 400, 'INVALID_REQUEST');
  }
  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    throw new HttpError('Password must be at least 8 characters long', 400, 'WEAK_PASSWORD');
  }

  const now = new Date();

  // Find matching token record efficiently by uid if provided
  let tokenRecord = null;
  if (uid) {
    const candidates = await PasswordResetToken.find({
      userId: uid,
      used: false,
      expiresAt: { $gt: now }
    }).sort({ createdAt: -1 }).limit(10);

    for (const rec of candidates) {
      if (await bcrypt.compare(rawToken, rec.tokenHash)) { tokenRecord = rec; break; }
    }
  } else {
    const candidates = await PasswordResetToken.find({
      used: false,
      expiresAt: { $gt: now }
    }).sort({ createdAt: -1 }).limit(50);

    for (const rec of candidates) {
      if (await bcrypt.compare(rawToken, rec.tokenHash)) { tokenRecord = rec; break; }
    }
  }

  if (!tokenRecord) {
    throw new HttpError('Invalid or expired password reset token', 400, 'INVALID_RESET_TOKEN');
  }

  // Attempt to start a session & transaction, safely
  const session = await safeStartTransaction();
  const usedTransaction = !!session;

  try {
    if (usedTransaction) {
      // transactional path
      tokenRecord.used = true;
      tokenRecord.usedAt = new Date();
      await tokenRecord.save({ session });

      const user = await User.findById(tokenRecord.userId).session(session);
      if (!user) throw new HttpError('User not found', 400, 'USER_NOT_FOUND');

      await user.setPassword(newPassword);
      user.tokenVersion = (user.tokenVersion || 0) + 1;
      await user.save({ session });

      // revoke refresh tokens using optional-session helper
      await updateManyOptionalSession(RefreshToken, { userId: user._id }, { $set: { revoked: true } }, session);

      await session.commitTransaction();
      await session.endSession();
    } else {
      // non-transactional fallback
      tokenRecord.used = true;
      tokenRecord.usedAt = new Date();
      await tokenRecord.save();

      const user = await User.findById(tokenRecord.userId);
      if (!user) throw new HttpError('User not found', 400, 'USER_NOT_FOUND');

      await user.setPassword(newPassword);
      user.tokenVersion = (user.tokenVersion || 0) + 1;
      await user.save();

      // best-effort revoke refresh tokens (no session)
      await RefreshToken.updateMany({ userId: user._id }, { $set: { revoked: true } });
    }

    // best-effort notify
    try {
      const userData = await User.findById(tokenRecord.userId).lean();
      if (userData && userData.email) {
        await mailer.sendPasswordChangedNotification(userData.email, { name: userData.name || '' });
      }
    } catch (mailErr) {
      console.warn('[resetPassword] notification failed', mailErr && mailErr.message);
    }

    return { ok: true };
  } catch (err) {
    // cleanup if transaction used
    if (usedTransaction && session) {
      try { await session.abortTransaction(); } catch (e) { /* ignore */ }
      try { await session.endSession(); } catch (e) { /* ignore */ }
    }
    throw err;
  }
}

/**
 * changePassword for logged-in user (must pass current password)
 */
async function changePassword({ userId, currentPassword, newPassword }) {
  if (!userId || !currentPassword || !newPassword) {
    throw new HttpError('Invalid request', 400, 'INVALID_REQUEST');
  }
  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    throw new HttpError('Password must be at least 8 characters long', 400, 'WEAK_PASSWORD');
  }
  const user = await User.findById(userId);
  if (!user) {
    throw new HttpError('User not found', 404, 'USER_NOT_FOUND');
  }

  const ok = await user.validatePassword(currentPassword);
  if (!ok) {
    // increment failed attempt counters if you have them
    throw new HttpError('Current password is incorrect', 401, 'INVALID_CREDENTIALS');
  }

  // Everything fine — update password & revoke refresh tokens
  user.setPassword && await user.setPassword(newPassword);
  user.tokenVersion = (user.tokenVersion || 0) + 1;
  await user.save();

  // revoke refresh tokens
  await revokeAllRefreshTokensForUser(user._id);

  // notify user
  try {
    await mailer.sendPasswordChangedNotification(user.email, { name: user.name });
  } catch (e) {
    console.warn('Failed to send password changed notification', e);
  }

  return { ok: true };
}

/**
 * Revoke all refresh tokens for a user (mark revoked = true)
 * Accepts optional mongoose session for transactional use.
 */
// Revoke all refresh tokens for a user (supports optional session)
async function revokeAllRefreshTokensForUser(userId, session = null) {
  if (session) {
    return RefreshToken.updateMany({ userId }, { $set: { revoked: true } }, { session });
  }
  return RefreshToken.updateMany({ userId }, { $set: { revoked: true } });
}


module.exports = {
  signup,
  login,
  refreshTokens,
  revokeRefreshToken,
  requestPasswordReset,
  resetPassword,
  changePassword,
  revokeAllRefreshTokensForUser
};

