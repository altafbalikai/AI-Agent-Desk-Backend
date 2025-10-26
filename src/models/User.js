const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, index: true },
  name: { type: String },
  passwordHash: { type: String },
  role: { type: String, enum: ['user','admin'], default: 'user' },
  tokenVersion: { type: Number, default: 0 },
  settings: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true });

UserSchema.methods.setPassword = async function(plain) {
  const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_SALT_ROUNDS || '10'));
  this.passwordHash = await bcrypt.hash(plain, salt);
};

UserSchema.methods.validatePassword = function(plain) {
  if (!this.passwordHash) return false;
  return bcrypt.compare(plain, this.passwordHash);
};

module.exports = mongoose.model('User', UserSchema);
