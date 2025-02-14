const mongoose = require('mongoose');
const { Schema } = mongoose;

const otpVerificationSchema = new Schema({
    userId: {
        type: String,
        ref: 'User',
        required: true
    },
    otp: {
        type: String,
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('OtpVerification', otpVerificationSchema);