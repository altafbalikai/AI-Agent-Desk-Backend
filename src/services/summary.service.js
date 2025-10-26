// src/services/summary.service.js
const { askGemini } = require('./gemini.service');
const ConversationSummary = require('../models/ConversationSummary');
const Message = require('../models/Message');

async function summarizeConversation(conversationId) {
  const messages = await Message.find({ conversationId })
    .sort({ createdAt: 1 })
    .limit(50)
    .lean();

  if (!messages || messages.length === 0) return null;

  const instructionText = `
Summarize the key facts, user preferences, and important context from the following chat.
Keep it concise, factual, and under 150 words.
Use a neutral tone.
`.trim();

  // Build the payload: instruction (as user) + chat messages (role + text)
  const payload = [
    { role: 'user', text: instructionText },
    // convert each stored message to simple {role, text} objects
    ...messages.map((m) => ({ role: m.role || 'user', text: m.text })),
  ];

  const reply = await askGemini(payload);

  const latest = await ConversationSummary.findOne({ conversationId })
    .sort({ version: -1 })
    .lean();
  const version = latest ? latest.version + 1 : 1;

  const summary = await ConversationSummary.create({
    conversationId,
    summaryText: reply,
    version,
  });

  return summary;
}

module.exports = { summarizeConversation };
