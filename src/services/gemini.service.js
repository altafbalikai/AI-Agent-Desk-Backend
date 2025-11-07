// src/services/gemini.service.js
const axios = require('axios');

const GEMINI_URL =
  'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent';

function normalizeMessages(messages) {
  if (Array.isArray(messages)) {
    return messages.map((m) => {
      let role = (m.role || 'user').toLowerCase();
      let text =
        m.text ??
        (m.parts && m.parts[0] && m.parts[0].text) ??
        '';

      if (role === 'assistant') role = 'model';
      if (role === 'system') {
        role = 'user';
        text = `INSTRUCTION: ${text.trim()}`;
      }

      return { role, text };
    });
  } else if (typeof messages === 'string') {
    return [{ role: 'user', text: messages }];
  } else if (messages && messages.text) {
    return [{ role: 'user', text: messages.text }];
  }
  return [];
}

async function askGemini(messages) {
  try {
    const normalized = normalizeMessages(messages);

    const contents = normalized.map((m) => ({
      role: m.role, // "user" or "model"
      parts: [{ text: m.text }],
    }));

    const response = await axios.post(
      `${GEMINI_URL}?key=${process.env.GEMINI_API_KEY}`,
      { contents },
      { headers: { 'Content-Type': 'application/json' } }
    );

    const reply =
      response.data?.candidates?.[0]?.content?.parts?.[0]?.text ||
      'No reply from Gemini';

    return reply;
  } catch (err) {
    console.error('Gemini API error:', err.response?.data || err.message);
    throw new Error('Failed to fetch response from Gemini');
  }
}

module.exports = { askGemini };
