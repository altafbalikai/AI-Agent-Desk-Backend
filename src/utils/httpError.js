// utils/httpError.js
class HttpError extends Error {
  constructor(message, status = 500, code = undefined) {
    super(message);
    this.status = status;
    if (code) this.code = code;
    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = HttpError;
