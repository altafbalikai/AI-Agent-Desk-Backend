// models/PasswordResetToken.js
const mongoose = require('mongoose');

const PasswordResetTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  tokenHash: { type: String, required: true }, // bcrypt hash of raw token
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  used: { type: Boolean, default: false }
});

// TTL index to auto-delete expired tokens (optional, uses expiresAt)
PasswordResetTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('PasswordResetToken', PasswordResetTokenSchema);
