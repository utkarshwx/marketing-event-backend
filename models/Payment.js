const mongoose = require('mongoose');
const generateId = require('../worker/generateId');
const { Schema } = mongoose;

const paymentSchema = new Schema({
    paymentId: {
        type: String,
        unique: true
    },
    userId: {
        type: String,
        ref: 'User',
        required: true
    },
    amount: {
        type: Number,
        required: true
    },
    status: {
        type: String,
        enum: ['success', 'pending', 'failed'],
        default: 'pending'
    },
    transactionId: {
        type: String
    },
    paymentDate: {
        type: Date
    },
    gatewayResponse: {
        type: String
    }
}, {
    timestamps: true
});

paymentSchema.index({ userId: 1, paymentId: 1 });

paymentSchema.pre('save', function (next) {
    if (!this.paymentId) {
        this.paymentId = generateId('PAY');
    }
    next();
});

module.exports = mongoose.model('Payment', paymentSchema);