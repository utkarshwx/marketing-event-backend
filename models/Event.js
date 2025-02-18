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
        type: String,
        required: true
    },
    eventDate: {
        type: Date,
        required: true
    },
    capacity: {
        type: Number,
        required: true,
        min: 1
    },
    registeredCount: {
        type: Number,
        default: 0
    },
    location: {
        type: String,
        required: true
    },
    isActive: {
        type: Boolean,
        default: true
    },
    createdBy: {
        type: String,
        ref: 'User',
        required: true
    },
    updatedBy: {
        type: String,
        ref: 'User'
    },
    deactivatedBy: {
        type: String,
        ref: 'User'
    },
    deactivationReason: {
        type: String
    },
    deactivatedAt: {
        type: Date
    },
    eventStatus: {
        type: String,
        enum: ['upcoming', 'ongoing', 'completed', 'cancelled'],
        default: 'upcoming'
    },
    registrationDeadline: {
        type: Date,
        required: true
    }
}, {
    timestamps: true
});

eventSchema.index({ eventStatus: 1, isActive: 1 });

eventSchema.pre('save', async function(next) {
    try {
        if (!this.eventId) {
            this.eventId = await generateId('EVT');
        }
        
        // Auto-update event status based on dates
        const now = new Date();
        if (this.eventDate < now) {
            this.eventStatus = 'completed';
        } else if (this.eventDate.getTime() === now.getTime()) {
            this.eventStatus = 'ongoing';
        }
        
        next();
    } catch (error) {
        next(error);
    }
});

// Static method to check event availability
eventSchema.statics.checkAvailability = async function(eventId) {
    const event = await this.findOne({ eventId });
    if (!event) {
        throw new Error('Event not found');
    }
    
    if (!event.isActive) {
        throw new Error('Event is not active');
    }
    
    if (event.registeredCount >= event.capacity) {
        throw new Error('Event is fully booked');
    }
    
    if (event.registrationDeadline < new Date()) {
        throw new Error('Registration deadline has passed');
    }
    
    return {
        available: true,
        remainingSlots: event.capacity - event.registeredCount
    };
};

// Method to increment registration count
eventSchema.methods.incrementRegistration = async function() {
    if (this.registeredCount >= this.capacity) {
        throw new Error('Event capacity reached');
    }
    
    this.registeredCount += 1;
    await this.save();
    return this.registeredCount;
};

// Method to decrement registration count
eventSchema.methods.decrementRegistration = async function() {
    if (this.registeredCount > 0) {
        this.registeredCount -= 1;
        await this.save();
    }
    return this.registeredCount;
};

module.exports = mongoose.model('Event', eventSchema);