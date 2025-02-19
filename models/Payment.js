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
    razorpayOrderId: {
        type: String
    },
    paymentDate: {
        type: Date
    },
    gatewayResponse: {
        type: String
    },
    refundStatus: {
        type: String,
        enum: ['none', 'requested', 'processing', 'completed'],
        default: 'none'
    },
    refundId: {
        type: String
    },
    refundAmount: {
        type: Number
    },
    refundDate: {
        type: Date
    }
}, {
    timestamps: true
});

paymentSchema.index({ userId: 1, paymentId: 1 });
paymentSchema.index({ razorpayOrderId: 1 }, { sparse: true });

// Fix: Generate ID before saving - make it synchronous to ensure ID exists
// Change to awaiting the ID generation before saving the document
paymentSchema.pre('save', async function (next) {
    try {
        if (!this.paymentId) {
            this.paymentId = await generateId('PAY');
        }
        next();
    } catch (error) {
        next(error);
    }
});

module.exports = mongoose.model('Payment', paymentSchema);