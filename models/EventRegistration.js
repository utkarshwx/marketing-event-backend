const mongoose = require('mongoose');
const generateId = require('../worker/generateId');
const { Schema } = mongoose;

const eventRegistrationSchema = new Schema({
    registrationId: {
        type: String,
        unique: true
    },
    userId: {
        type: String,
        ref: 'User',
        required: true
    },
    eventId: {
        type: String,
        ref: 'Event',
        required: true
    },
    isActive: {
        type: Boolean,
        default: true
    },
    registeredAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true,
    updatedAt: 'updatedAt'
});

eventRegistrationSchema.index({ userId: 1, eventId: 1 });

eventRegistrationSchema.pre('save', function (next) {
    if (!this.registrationId) {
        this.registrationId = generateId('REG');
    }
    next();
});

module.exports = mongoose.model('EventRegistration', eventRegistrationSchema);