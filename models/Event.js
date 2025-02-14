const mongoose = require('mongoose');
const generateId = require('../worker/generateId');
const { Schema } = mongoose;

const eventSchema = new Schema({
    eventId: {
        type: String,
        unique: true
    },
    eventName: {
        type: String,
        required: true
    },
    description: {
        type: String
    },
    eventDate: {
        type: Date,
        required: true
    },
    capacity: {
        type: Number,
        required: true
    },
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

eventSchema.index({ eventId: 1 });

eventSchema.pre('save', function (next) {
    if (!this.eventId) {
        this.eventId = generateId('EVT');
    }
    next();
});

module.exports = mongoose.model('Event', eventSchema);