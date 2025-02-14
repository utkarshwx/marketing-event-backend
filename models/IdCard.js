const mongoose = require('mongoose');
const generateId = require('../worker/generateId');
const { Schema } = mongoose;

const idCardSchema = new Schema({
    cardId: {
        type: String,
        unique: true
    },
    userId: {
        type: String,
        ref: 'User',
        required: true
    },
    isIssued: {
        type: Boolean,
        default: false
    },
    issuedBy: {
        type: String,
        ref: 'Admin'
    },
    issuedAt: {
        type: Date
    }
}, {
    timestamps: true
});

idCardSchema.index({ userId: 1, cardId: 1 });

idCardSchema.pre('save', function (next) {
    if (!this.cardId) {
        this.cardId = generateId('CRD');
    }
    next();
});

module.exports = mongoose.model('IdCard', idCardSchema);
