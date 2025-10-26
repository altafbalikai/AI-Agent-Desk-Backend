const express = require('express');
const router = express.Router();
const { ask } = require('../controllers/llm.controller');
const auth = require('../middlewares/auth.middleware');

// require JWT auth for AI interaction
router.use(auth);

// POST /api/llm/ask
router.post('/ask', ask);

module.exports = router;
