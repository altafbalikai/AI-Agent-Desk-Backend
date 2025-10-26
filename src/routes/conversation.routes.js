// src/routes/conversation.routes.js
const express = require('express');
const router = express.Router();
const convController = require('../controllers/conversation.controller');
const auth = require('../middlewares/auth.middleware');

// ensure auth middleware is required before protected routes
router.use(auth);

router.post('/', convController.createConversation);
router.get('/my', convController.listConversations);
router.post('/:cid/messages', convController.addMessage);
router.get('/:cid/messages', convController.getMessages);

module.exports = router;
