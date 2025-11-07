// src/db/mongoose.js
const mongoose = require('mongoose');

async function connect() {
  const uri = process.env.MONGO_URI;
  if (!uri) throw new Error('MONGO_URI not set in .env');

  await mongoose.connect(uri, {
    maxPoolSize: parseInt(process.env.MONGO_POOL_SIZE || '50'),
    minPoolSize: parseInt(process.env.MONGO_MIN_POOL_SIZE || '0'),
    retryWrites: true,
    w: 'majority'
  });

  console.log('MongoDB connected');
}

module.exports = { connect, mongoose };
