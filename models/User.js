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
    isEmailVerified: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true // Adds createdAt and updatedAt
});

userSchema.index({ email: 1, userId: 1 });

userSchema.pre('save', async function (next) { 
    try {
        if (!this.userId) {
            this.userId = await generateId('USR'); 
            console.log("Generated userId:", this.userId);
        }
        next();
    } catch (error) {
        console.error("Error generating userId:", error);
        next(error); 
    }
});

module.exports = mongoose.model('User', userSchema);