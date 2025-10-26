const mongoose = require('mongoose');

const RefreshTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  tokenHash: { type: String, required: true }, // hashed tokenId
  revoked: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  lastUsedAt: { type: Date },
  expiresAt: { type: Date, required: true }
});

RefreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('RefreshToken', RefreshTokenSchema);
