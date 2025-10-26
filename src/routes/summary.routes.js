const express = require('express');
const router = express.Router();
const { summarizeConversation } = require('../services/summary.service');
const auth = require('../middlewares/auth.middleware');

router.use(auth);

// POST /api/summary/:conversationId
router.post('/:conversationId', async (req, res, next) => {
  try {
    const { conversationId } = req.params;
    const summary = await summarizeConversation(conversationId);
    res.json(summary);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
