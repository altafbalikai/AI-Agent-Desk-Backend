// src/controllers/llm.controller.js
const { askGemini } = require('../services/gemini.service');
const ConversationService = require('../services/conversation.service');
const Message = require('../models/Message');

async function createConversation(req, res, next) {
  try {
    const userId = req.user?.id;
    const { agentId } = req.body;
    const { title } = req.body;
    const conv = await ConversationService.createConversation(userId, agentId, title);
    res.status(201).json(conv);
  } catch (err) {
    next(err);
  }
}

async function listConversations(req, res, next) {
  try {
    const userId = req.user && req.user.id;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    // read from query params: /api/conversations/my?agent=...&page=1&limit=50
    const agent = typeof req.query.agent === 'string' && req.query.agent.trim() ? req.query.agent.trim() : undefined;
    const page = req.query.page;
    const limit = req.query.limit;

    const data = await ConversationService.listConversations(userId, agent, page, limit);
    res.json(data);
  } catch (err) {
    next(err);
  }
}

async function addMessage(req, res, next) {
  try {
    const userId = req.user?.id;
    const { cid } = req.params;
    const { role = 'user', text } = req.body;
    const msg = await ConversationService.addMessage(userId, cid, { role, text });
    res.status(201).json(msg);
  } catch (err) {
    next(err);
  }
}

async function getMessages(req, res, next) {
  try {
    const userId = req.user?.id;
    const { cid } = req.params;
    const page = parseInt(req.query.page || '1');
    const limit = parseInt(req.query.limit || '50');
    const data = await ConversationService.getMessages(userId, cid, { page, limit });
    res.json(data);
  } catch (err) {
    next(err);
  }
}

module.exports = { createConversation, listConversations, addMessage, getMessages };
