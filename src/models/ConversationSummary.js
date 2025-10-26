const mongoose = require('mongoose');

const ConversationSummarySchema = new mongoose.Schema(
  {
    conversationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Conversation',
      required: true,
      index: true,
    },
    summaryText: { type: String, required: true },
    version: { type: Number, default: 1 }, // in case we store multiple versions
  },
  { timestamps: true }
);

ConversationSummarySchema.index({ conversationId: 1, version: -1 });

module.exports = mongoose.model('ConversationSummary', ConversationSummarySchema);
