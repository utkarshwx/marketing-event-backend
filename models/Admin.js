const mongoose = require('mongoose');
const generateId = require('../worker/generateId');
const { Schema } = mongoose;

const adminSchema = new Schema({

    adminId: {
        type: String,
        unique: true
    },

    username: {
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
        required: true
    }
}, {
    timestamps: true
});

adminSchema.index({ username: 1 });

adminSchema.pre('save', function (next) {
    
    if (!this.adminId) {
        this.adminId = generateId('ADM');
    }
    next();
});

module.exports = mongoose.model('Admin', adminSchema);