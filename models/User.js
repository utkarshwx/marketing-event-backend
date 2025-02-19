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
        unique: function() {
            // Only enforce uniqueness for non-admin accounts
            return this.role !== 'admin';
        },
        validate: {
            validator: function(v) {
                // Basic phone validation - can be customized
                return /^\d{10,15}$/.test(v);
            },
            message: props => `${props.value} is not a valid phone number!`
        }
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
    },
    lastLogin: {
        type: Date,
        default: null
    },
    loginHistory: [{
        ip: String,
        userAgent: String,
        timestamp: {
            type: Date,
            default: Date.now
        }
    }]
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

// Add method to record login
userSchema.methods.recordLogin = async function(ipAddress, userAgent) {
    this.lastLogin = new Date();
    this.loginHistory.push({
        ip: ipAddress,
        userAgent: userAgent,
        timestamp: new Date()
    });
    
    // Keep only last 10 logins
    if (this.loginHistory.length > 10) {
        this.loginHistory = this.loginHistory.slice(-10);
    }
    
    await this.save();
};

module.exports = mongoose.model('User', userSchema);