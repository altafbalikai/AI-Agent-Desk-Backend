// utils/mailer.js
'use strict';

const sgMail = require('@sendgrid/mail');
const nodemailer = require('nodemailer');
const Handlebars = require('handlebars');
// defensive p-retry import handled below
const validator = require('validator');

const LOG_PREFIX = '[MAIL]';

// Load config from env
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || '';
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : undefined;
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const MAIL_FROM = process.env.MAIL_FROM || 'no-reply@example.com';
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || 'My App';

// Retry config
const MAX_RETRIES = parseInt(process.env.MAIL_MAX_RETRIES || '3', 10);
const RETRY_MIN_TIMEOUT_MS = parseInt(process.env.MAIL_RETRY_MIN_MS || '500', 10);

// defensive pRetry import + fallback
let pRetryFunc = null;
try {
  const maybe = require('p-retry');
  pRetryFunc = (typeof maybe === 'function') ? maybe : (maybe && typeof maybe.default === 'function' ? maybe.default : null);
} catch (e) {
  pRetryFunc = null;
}

// fallback retry helper if pRetry is not available
async function retryExec(fn, opts = {}) {
  const retries = typeof opts.retries === 'number' ? opts.retries : 3;
  const minTimeout = typeof opts.minTimeout === 'number' ? opts.minTimeout : 500;

  // if pRetry available, use it (preserves its behavior)
  if (typeof pRetryFunc === 'function') {
    return pRetryFunc(fn, { retries, minTimeout });
  }

  // simple fallback: attempt fn up to (retries + 1) times with exponential backoff + jitter
  let attempt = 0;
  let lastErr;
  while (attempt <= retries) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      attempt += 1;
      if (attempt > retries) break;
      const backoff = minTimeout * Math.pow(2, attempt - 1);
      const jitter = Math.floor(Math.random() * Math.min(1000, backoff));
      const wait = backoff + jitter;
      await new Promise((r) => setTimeout(r, wait));
    }
  }
  throw lastErr;
}

// initialize provider (prefer SendGrid)
let transportType = null;
if (SENDGRID_API_KEY) {
  try {
    sgMail.setApiKey(SENDGRID_API_KEY);
    transportType = 'sendgrid';
    console.info(`${LOG_PREFIX} Using SendGrid transport`);
  } catch (err) {
    console.warn(`${LOG_PREFIX} SendGrid init failed, falling back if SMTP configured`, err && err.message);
  }
}

let smtpTransporter = null;
if (!transportType && SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS) {
  smtpTransporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465, // true for 465, false for other ports
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  transportType = 'smtp';
  console.info(`${LOG_PREFIX} Using SMTP transport (${SMTP_HOST}:${SMTP_PORT})`);
}

if (!transportType) {
  console.warn(`${LOG_PREFIX} No mail transport configured. Set SENDGRID_API_KEY or SMTP_* env vars.`);
}

/* -------------------------
   Minimal templating helper
   ------------------------- */
function compileTemplate(templateStr) {
  return Handlebars.compile(templateStr);
}

function renderTemplate(compiled, data) {
  try {
    return compiled(data || {});
  } catch (err) {
    // avoid leaking data in logs
    console.error(`${LOG_PREFIX} Template render failed`, err && err.message);
    return '';
  }
}

/* -------------------------
   Basic validators
   ------------------------- */
function ensureEmail(to) {
  if (!to || !validator.isEmail(String(to))) {
    const e = new Error('Invalid email address');
    e.code = 'INVALID_EMAIL';
    throw e;
  }
}

/* -------------------------
   Core send function with retry (uses retryExec)
   ------------------------- */
async function _sendMailRaw({ to, subject, html, text, fromName, fromEmail }) {
  if (!transportType) {
    const e = new Error('No mail transport configured');
    e.code = 'NO_TRANSPORT';
    throw e;
  }

  // SendGrid path
  if (transportType === 'sendgrid') {
    const msg = {
      to,
      from: { email: fromEmail || MAIL_FROM, name: fromName || MAIL_FROM_NAME },
      subject,
      text,
      html
    };
    return retryExec(
      async () => {
        const res = await sgMail.send(msg);
        return res;
      },
      { retries: MAX_RETRIES, minTimeout: RETRY_MIN_TIMEOUT_MS }
    );
  }

  // SMTP path
  if (transportType === 'smtp') {
    const mailOptions = {
      from: `"${fromName || MAIL_FROM_NAME}" <${fromEmail || MAIL_FROM}>`,
      to,
      subject,
      text,
      html
    };
    return retryExec(
      async () => {
        const info = await smtpTransporter.sendMail(mailOptions);
        return info;
      },
      { retries: MAX_RETRIES, minTimeout: RETRY_MIN_TIMEOUT_MS }
    );
  }

  // unreachable
  throw new Error('Unsupported transport');
}

/* -------------------------
   Exported helpers
   ------------------------- */

/**
 * sendMail: low-level mail sender
 * - accepts plain text and html. Use templates helper below for templating.
 */
async function sendMail({ to, subject, html, text, fromName, fromEmail }) {
  ensureEmail(to);

  try {
    const res = await _sendMailRaw({ to, subject, html, text, fromName, fromEmail });
    // Lightweight success log (do NOT log message body or tokens)
    console.info(`${LOG_PREFIX} Email queued/sent to=${to} subject=${subject}`);
    return { ok: true, result: res };
  } catch (err) {
    console.error(
      `${LOG_PREFIX} sendMail failed to=${to} subject=${subject} err=${err && err.code ? err.code : err && err.message}`,
    );
    // propagate structured error
    const e = new Error('Failed to send email');
    e.original = err;
    e.code = err && err.code ? err.code : 'MAIL_SEND_FAILED';
    throw e;
  }
}

/**
 * sendTemplateMail: compile + render template on the fly
 * template can be { htmlTemplate, textTemplate } or strings
 */
async function sendTemplateMail({ to, subject, htmlTemplate, textTemplate, templateData = {}, fromName, fromEmail }) {
  ensureEmail(to);

  // compile templates (you can cache compiled templates in production)
  const htmlCompiled = htmlTemplate ? compileTemplate(htmlTemplate) : null;
  const textCompiled = textTemplate ? compileTemplate(textTemplate) : null;

  const html = htmlCompiled ? renderTemplate(htmlCompiled, templateData) : undefined;
  const text = textCompiled ? renderTemplate(textCompiled, templateData) : undefined;

  return sendMail({ to, subject, html, text, fromName, fromEmail });
}

/* -------------------------
   Convenience functions for auth flow
   ------------------------- */

async function sendPasswordResetEmail(to, resetUrl, opts = {}) {
  ensureEmail(to);
  const subject = opts.subject || 'Reset your password';
  // Simple templates (replace with real HTML templates stored on disk or in db)
  const htmlTemplate =
    opts.htmlTemplate ||
    `<p>Hello {{name}},</p>
     <p>We received a request to reset your password. Click the link below to reset it:</p>
     <p><a href="{{resetUrl}}">Reset password</a></p>
     <p>If you didn't request this, you can safely ignore this email.</p>
     <p>Regards,<br/>{{appName}}</p>`;

  const textTemplate =
    opts.textTemplate ||
    `Hello {{name}},\n\nWe received a request to reset your password. Open the link to reset it:\n\n{{resetUrl}}\n\nIf you didn't request this, ignore this email.\n\nRegards,\n{{appName}}`;

  const templateData = {
    name: opts.name || '',
    resetUrl,
    appName: opts.appName || MAIL_FROM_NAME
  };

  return sendTemplateMail({ to, subject, htmlTemplate, textTemplate, templateData, fromName: opts.fromName, fromEmail: opts.fromEmail });
}

async function sendPasswordChangedNotification(to, opts = {}) {
  ensureEmail(to);
  const subject = opts.subject || 'Your password was changed';
  const htmlTemplate =
    opts.htmlTemplate ||
    `<p>Hello {{name}},</p>
     <p>Your account password was recently changed. If you initiated this change, you can ignore this email.</p>
     <p>If you did NOT change your password, please <a href="{{supportUrl}}">contact support</a> immediately or reset your password.</p>
     <p>Regards,<br/>{{appName}}</p>`;

  const textTemplate =
    opts.textTemplate ||
    `Hello {{name}},\n\nYour account password was recently changed. If you did NOT change it, contact support or reset your password.\n\nRegards,\n{{appName}}`;

  const templateData = {
    name: opts.name || '',
    appName: opts.appName || MAIL_FROM_NAME,
    supportUrl: opts.supportUrl || (process.env.SUPPORT_URL || '')
  };

  return sendTemplateMail({ to, subject, htmlTemplate, textTemplate, templateData, fromName: opts.fromName, fromEmail: opts.fromEmail });
}

/* -------------------------
   Exports
   ------------------------- */
module.exports = {
  sendMail,
  sendTemplateMail,
  sendPasswordResetEmail,
  sendPasswordChangedNotification,
  _transportType: transportType
};
