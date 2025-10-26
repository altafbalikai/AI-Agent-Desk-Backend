require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const authRoutes = require('./routes/auth.routes');
const convRoutes = require('./routes/conversation.routes');
const llmRoutes = require('./routes/llm.routes');
const summaryRoutes = require('./routes/summary.routes');

const app = express();

// enable JSON body parsing
app.use(express.json());
app.use(cookieParser());


// configure and enable CORS before routes
const allowedOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:4200';
app.use(cors({
  origin: allowedOrigin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With']
}));


// define routes
app.use('/api/auth', authRoutes);
app.use('/api/conversations', convRoutes);
app.use('/api/llm', llmRoutes);
app.use('/api/summary', summaryRoutes);

// health check endpoint
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// global error handler
app.use((err, req, res, next) => {
  console.error(err);
  res
    .status(err.status || 500)
    .json({ error: err.message || 'Internal Server Error' });
});

module.exports = app;
