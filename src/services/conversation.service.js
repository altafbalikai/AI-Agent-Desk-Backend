// src/services/conversation.service.js
const Conversation = require('../models/Conversation');
const Message = require('../models/Message');
const mongoose = require('mongoose');

async function createConversation(userId, agentId, title) {
  if (!mongoose.isValidObjectId(userId)) throw Object.assign(new Error('Invalid userId'), { status: 400 });

  // You can pass the string userId directly; Mongoose will cast it.
  const conv = await Conversation.create({ userId: new mongoose.Types.ObjectId(userId), agentId:agentId, title: title || 'New Conversation' });
  return conv.toObject();
}

/**
 * List conversations for a user, optionally filtered by agentId (or title fallback).
 * Supports pagination (page, limit).
 */
async function listConversations(userId, agentId, page = 1, limit = 50) {
  if (!mongoose.isValidObjectId(userId)) {
    throw Object.assign(new Error('Invalid userId'), { status: 400 });
  }

  page = Math.max(1, parseInt(page, 10) || 1);
  limit = Math.max(1, Math.min(200, parseInt(limit, 10) || 50)); // cap limit for safety

  const filter = { userId: new mongoose.Types.ObjectId(userId) };

  if (agentId) {
    // Prefer exact agentId match; if not present then fallback to title contains (case-insensitive)
    filter.$or = [
      { agentId: agentId },
      { title: new RegExp(agentId, 'i') }
    ];
  }

  const skip = (page - 1) * limit;

  const [items, total] = await Promise.all([
    Conversation.find(filter)
      .select({ title: 1, agentId: 1, createdAt: 1, updatedAt: 1 })
      .sort({ updatedAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean(),
    Conversation.countDocuments(filter)
  ]);

  return {
    items,
    total,
    page,
    limit
  };
}


async function addMessage(userId, conversationId, { role, text }) {
  if (!mongoose.isValidObjectId(userId)) throw Object.assign(new Error('Invalid userId'), { status: 400 });
  if (!mongoose.isValidObjectId(conversationId)) throw Object.assign(new Error('Invalid conversationId'), { status: 400 });

  const conv = await Conversation.findById(conversationId);
  if (!conv) throw Object.assign(new Error('Conversation not found'), { status: 404 });
  if (conv.userId.toString() !== userId) throw Object.assign(new Error('Forbidden'), { status: 403 });

  const msg = await Message.create({
    conversationId: conv._id,
    userId: new mongoose.Types.ObjectId(userId),
    role,
    text,
    createdAt: new Date()
  });

  // update conversation updatedAt for sorting
  conv.updatedAt = new Date();
  await conv.save();

  return msg.toObject();
}

async function getMessages(userId, conversationId, { page = 1, limit = 50 }) {
  if (!mongoose.isValidObjectId(userId)) throw Object.assign(new Error('Invalid userId'), { status: 400 });
  if (!mongoose.isValidObjectId(conversationId)) throw Object.assign(new Error('Invalid conversationId'), { status: 400 });

  const conv = await Conversation.findById(conversationId);
  if (!conv) throw Object.assign(new Error('Conversation not found'), { status: 404 });
  if (conv.userId.toString() !== userId) throw Object.assign(new Error('Forbidden'), { status: 403 });

  const skip = (page - 1) * limit;
  const items = await Message.find({ conversationId: new mongoose.Types.ObjectId(conversationId) }).sort({ createdAt: 1 }).skip(skip).limit(limit).lean();
  return { items, page, limit };
}

module.exports = { createConversation, listConversations, addMessage, getMessages };
