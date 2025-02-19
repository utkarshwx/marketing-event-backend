const mongoose = require('mongoose');
const { Schema } = mongoose;

const adminActivitySchema = new Schema({
    action: {
        type: String,
        required: true,
        enum: [
            'create_event', 
            'update_event', 
            'delete_event', 
            'modify_user', 
            'generate_report',
            'login',
            'permission_check',
            'deactivate_event',
            'create_moderator'
        ]
    },
    details: {
        type: Schema.Types.Mixed
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});

const adminDashboardPreferencesSchema = new Schema({
    defaultView: {
        type: String,
        enum: ['events', 'users', 'payments', 'reports'],
        default: 'events'
    },
    eventsPerPage: {
        type: Number,
        default: 10
    },
    usersPerPage: {
        type: Number,
        default: 20
    },
    favoriteReports: [{
        type: String
    }]
});

const adminPermissionsSchema = new Schema({
    canCreateEvents: {
        type: Boolean,
        default: true
    },
    canDeleteEvents: {
        type: Boolean,
        default: true
    },
    canModifyUsers: {
        type: Boolean,
        default: true
    },
    canGenerateReports: {
        type: Boolean,
        default: true
    },
    canManageModerators: {
        type: Boolean,
        default: true
    }
});

const adminSchema = new Schema({
    userId: {
        type: String,
        ref: 'User',
        required: true,
        unique: true
    },
    permissions: {
        type: adminPermissionsSchema,
        default: () => ({})
    },
    dashboardPreferences: {
        type: adminDashboardPreferencesSchema,
        default: () => ({})
    },
    lastLogin: {
        type: Date
    },
    activityLog: [adminActivitySchema],
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Methods for admin activity logging
adminSchema.methods.logActivity = async function(action, details) {
    this.activityLog.push({
        action,
        details,
        timestamp: new Date()
    });
    await this.save();
};

// Static method to get admin analytics
adminSchema.statics.getAdminAnalytics = async function(adminId, startDate, endDate) {
    const admin = await this.findOne({ userId: adminId });
    if (!admin) {
        throw new Error('Admin not found');
    }

    const activities = admin.activityLog.filter(log => 
        log.timestamp >= startDate && log.timestamp <= endDate
    );

    return {
        totalActivities: activities.length,
        activitiesByType: activities.reduce((acc, curr) => {
            acc[curr.action] = (acc[curr.action] || 0) + 1;
            return acc;
        }, {}),
        lastActive: admin.lastLogin,
        mostFrequentActivity: activities.length > 0 
            ? Object.entries(activities.reduce((acc, curr) => {
                acc[curr.action] = (acc[curr.action] || 0) + 1;
                return acc;
              }, {})).sort((a, b) => b[1] - a[1])[0][0]
            : null
    };
};

module.exports = mongoose.model('Admin', adminSchema);