// src/controllers/llm.controller.js
const { askGemini } = require('../services/gemini.service');
const ConversationService = require('../services/conversation.service');
const Message = require('../models/Message');

async function ask(req, res, next) {
  try {
    const userId = req.user && req.user.id;
    const { message, conversationId } = req.body;
    if (!message) return res.status(400).json({ error: 'message required' });

    // 1) Save the user's message first
    const userMsg = await ConversationService.addMessage(userId, conversationId, {
      role: 'user',
      text: message,
    });

    // 2) Retrieve last N messages for context (most recent first, then reverse to chronological)
    const recentMessages = await Message.find({ conversationId })
      .sort({ createdAt: -1 })
      .limit(20)   // change this number if you want more/less context
      .lean();

    const ordered = recentMessages.reverse(); // earliest -> latest

    // Optional: include the newly saved user message at the end if not present
    // (should already be present because we saved it above and then read from DB,
    // but keep this guard for race-safety)
    if (!ordered.length || ordered[ordered.length - 1].text !== userMsg.text) {
      ordered.push({
        role: userMsg.role,
        text: userMsg.text
      });
    }

    // 3) Debug log so you can verify the exact payload sent to Gemini
    console.log('--- Gemini payload ---');
    console.log(
      JSON.stringify(
        ordered.map((m) => ({ role: m.role, parts: [{ text: m.text }] })),
        null,
        2
      )
    );
    console.log('--- end payload ---');

    // 4) Call Gemini with the ordered context
    const ConversationSummary = require('../models/ConversationSummary');

    // Try to fetch latest summary for this conversation
    const latestSummary = await ConversationSummary.findOne({ conversationId }).sort({ version: -1 }).lean();

    let contextWithMemory = [];
    if (latestSummary) {
      contextWithMemory.push({
        role: 'system',
        text: `Memory Summary: ${latestSummary.summaryText}`,
      });
    }
    contextWithMemory = [...contextWithMemory, ...ordered];

    // Ask Gemini with memory + current context
    const reply = await askGemini(contextWithMemory);


    // 5) Save assistant's reply as new message
    const aiMsg = await ConversationService.addMessage(userId, conversationId, {
      role: 'assistant',
      text: reply,
    });

    // 6) Return both saved messages and the reply text
    return res.status(200).json({
      success: true,
      reply: reply || aiMsg?.text || '',
      userMessage: userMsg || null,
      aiMessage: aiMsg || null,
    });

  } catch (err) {
    next(err);
  }
}

module.exports = { ask };
