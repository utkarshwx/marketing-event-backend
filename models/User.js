const mongoose = require('mongoose');
const generateId = require('../worker/generateId');
const { Schema } = mongoose;

const userSchema = new Schema({
    userId: {
        type: String,
        unique: true
    },
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    phoneNumber: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['user', 'moderator', 'admin'],
        default: 'user'
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    qrCode: {
        code: {
            type: String,
            sparse: true
        },
        isUsed: {
            type: Boolean,
            default: false
        },
        usedBy: {
            type: String,
            ref: 'User',
            default: null
        },
        usedAt: {
            type: Date,
            default: null
        }
    },
    currentEvent: {
        type: String,
        ref: 'Event',
        default: null
    },
    hasValidPayment: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

// Single compound index for user lookup
userSchema.index({ email: 1, userId: 1 });

userSchema.pre('save', async function(next) {
    try {
        if (!this.userId) {
            const prefix = this.role === 'admin' ? 'ADM' : 
                          this.role === 'moderator' ? 'MOD' : 'USR';
            this.userId = await generateId(prefix);
        }
        next();
    } catch (error) {
        console.error("Error generating userId:", error);
        next(error);
    }
});

userSchema.methods.generateQRCode = async function() {
    if (!this.hasValidPayment) {
        throw new Error('Payment required before generating QR code');
    }
    
    if (!this.qrCode.code) {
        this.qrCode.code = await generateId('QR');
        await this.save();
    }
    return this.qrCode.code;
};

userSchema.methods.useQRCode = async function(moderatorId) {
    if (this.qrCode.isUsed) {
        throw new Error('QR code has already been used');
    }
    
    this.qrCode.isUsed = true;
    this.qrCode.usedBy = moderatorId;
    this.qrCode.usedAt = new Date();
    await this.save();
    
    return true;
};

module.exports = mongoose.model('User', userSchema);