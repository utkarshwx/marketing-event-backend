const mongoose = require('mongoose');
const { Schema } = mongoose;

const scanLogSchema = new Schema({
    qrCode: {
        type: String,
        required: true
    },
    userId: {
        type: String,
        ref: 'User',
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    },
    location: {
        type: String
    },
    deviceInfo: {
        deviceId: String,
        deviceModel: String,
        deviceOS: String,
        appVersion: String
    },
    eventId: {
        type: String,
        ref: 'Event',
        required: true
    }
});

const moderatorSchema = new Schema({
    userId: {
        type: String,
        ref: 'User',
        required: true,
        unique: true
    },
    assignedEvents: [{
        type: String,
        ref: 'Event'
    }],
    activeStatus: {
        type: String,
        enum: ['active', 'inactive', 'suspended'],
        default: 'active'
    },
    lastActive: {
        type: Date
    },
    deviceInfo: {
        deviceId: {
            type: String,
            unique: true,
            sparse: true
        },
        registeredAt: Date,
        lastUsed: Date
    },
    scanHistory: [scanLogSchema],
    totalScans: {
        type: Number,
        default: 0
    },
    scansToday: {
        type: Number,
        default: 0
    },
    lastScanReset: {
        type: Date
    },
    permissions: {
        canScanQR: {
            type: Boolean,
            default: true
        },
        canViewEventDetails: {
            type: Boolean,
            default: true
        }
    },
    notes: {
        type: String
    },
    createdBy: {
        type: String,
        ref: 'Admin',
        required: true
    }
}, {
    timestamps: true
});

// Indexes for better query performance
moderatorSchema.index({ 'scanHistory.timestamp': 1 });
moderatorSchema.index({ activeStatus: 1 });

// Reset daily scan count
moderatorSchema.methods.resetDailyScans = async function() {
    const today = new Date();
    const lastReset = this.lastScanReset;
    
    if (!lastReset || lastReset.getDate() !== today.getDate()) {
        this.scansToday = 0;
        this.lastScanReset = today;
        await this.save();
    }
};

// Log a new scan
moderatorSchema.methods.logScan = async function(qrCode, userId, eventId, location, deviceInfo) {
    // Reset daily scans if needed
    await this.resetDailyScans();
    
    // Create scan log
    const scanLog = {
        qrCode,
        userId,
        eventId,
        location,
        deviceInfo,
        timestamp: new Date()
    };
    
    // Add to scan history
    this.scanHistory.push(scanLog);
    
    // Update counts
    this.totalScans += 1;
    this.scansToday += 1;
    this.lastActive = new Date();
    
    await this.save();
    return scanLog;
};

// Register or update device
moderatorSchema.methods.registerDevice = async function(deviceInfo) {
    this.deviceInfo = {
        ...deviceInfo,
        registeredAt: this.deviceInfo?.registeredAt || new Date(),
        lastUsed: new Date()
    };
    await this.save();
    return this.deviceInfo;
};

// Get scan statistics
moderatorSchema.methods.getScanStats = async function(startDate, endDate) {
    const scans = this.scanHistory.filter(scan => 
        scan.timestamp >= startDate && scan.timestamp <= endDate
    );
    
    return {
        totalScans: scans.length,
        scansPerDay: scans.reduce((acc, scan) => {
            const date = scan.timestamp.toISOString().split('T')[0];
            acc[date] = (acc[date] || 0) + 1;
            return acc;
        }, {}),
        averageScansPerDay: scans.length / (
            Math.ceil((endDate - startDate) / (1000 * 60 * 60 * 24))
        ),
        eventBreakdown: scans.reduce((acc, scan) => {
            acc[scan.eventId] = (acc[scan.eventId] || 0) + 1;
            return acc;
        }, {}),
        lastScan: scans.length > 0 ? scans[scans.length - 1] : null
    };
};

// Verify device ID
moderatorSchema.methods.verifyDevice = function(deviceId) {
    return this.deviceInfo?.deviceId === deviceId;
};

// Static method to get active moderators
moderatorSchema.statics.getActiveModerators = function() {
    return this.find({ 
        activeStatus: 'active',
        'deviceInfo.deviceId': { $exists: true }
    }).populate('userId', 'name email');
};

module.exports = mongoose.model('Moderator', moderatorSchema);