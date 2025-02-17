const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Admin = require('../models/Admin');
const Moderator = require('../models/Moderator');
const config = require('../config');

// Base authentication middleware
const authenticate = (requiredRole) => {
    return async (request, reply) => {
        try {
            const token = request.headers.authorization?.split(' ')[1];
            if (!token) {
                reply.code(401).send({ error: 'No token provided' });
                return;
            }

            const decoded = jwt.verify(token, config.JWT_SECRET);
            
            // If a specific role is required, check it
            if (requiredRole && decoded.role !== requiredRole) {
                reply.code(403).send({ error: `${requiredRole} access required` });
                return;
            }

            // Set the user info in request
            request.user = decoded;
        } catch (error) {
            if (error.name === 'JsonWebTokenError') {
                reply.code(401).send({ error: 'Invalid token' });
            } else if (error.name === 'TokenExpiredError') {
                reply.code(401).send({ error: 'Token expired' });
            } else {
                reply.code(401).send({ error: 'Authentication failed' });
            }
            return;
        }
    };
};

// Role-specific authentication middlewares
const authenticateUser = authenticate('user');
const authenticateAdmin = authenticate('admin');
const authenticateModerator = authenticate('moderator');

// Optional authentication - allows routes to work with or without auth
const optionalAuthenticate = async (request, reply) => {
    try {
        const token = request.headers.authorization?.split(' ')[1];
        if (!token) {
            request.user = null;
            return;
        }

        const decoded = jwt.verify(token, config.JWT_SECRET);
        request.user = decoded;
    } catch (error) {
        request.user = null;
    }
};

// Check if user has valid payment
const checkPayment = async (request, reply) => {
    try {
        const { userId } = request.user;
        
        const user = await User.findOne({ userId });
        if (!user) {
            reply.code(404).send({ error: 'User not found' });
            return;
        }
        
        if (!user.hasValidPayment) {
            reply.code(403).send({ error: 'Payment required for this action' });
            return;
        }
    } catch (error) {
        console.error('Payment check error:', error);
        reply.code(500).send({ error: 'Internal server error' });
        return;
    }
};

// Verify moderator device
const verifyModeratorDevice = async (request, reply) => {
    try {
        const { userId } = request.user;
        const deviceId = request.headers['device-id'];
        
        if (!deviceId) {
            reply.code(400).send({ error: 'Device ID is required' });
            return;
        }

        const moderator = await Moderator.findOne({ userId });
        if (!moderator) {
            reply.code(404).send({ error: 'Moderator not found' });
            return;
        }

        if (moderator.deviceInfo.deviceId !== deviceId) {
            reply.code(401).send({ error: 'Unauthorized device' });
            return;
        }

        if (moderator.activeStatus !== 'active') {
            reply.code(403).send({ error: 'Moderator account is not active' });
            return;
        }

        // Update last active timestamp
        moderator.deviceInfo.lastUsed = new Date();
        await moderator.save();
    } catch (error) {
        console.error('Device verification error:', error);
        reply.code(500).send({ error: 'Device verification failed' });
        return;
    }
};

// Check admin permissions
const checkAdminPermission = (permission) => {
    return async (request, reply) => {
        try {
            const { userId } = request.user;
            
            const admin = await Admin.findOne({ userId });
            if (!admin) {
                reply.code(404).send({ error: 'Admin not found' });
                return;
            }

            if (!admin.permissions[permission]) {
                reply.code(403).send({ error: `Missing required permission: ${permission}` });
                return;
            }

            // Log admin activity
            await admin.logActivity('permission_check', {
                permission,
                timestamp: new Date()
            });
        } catch (error) {
            console.error('Permission check error:', error);
            reply.code(500).send({ error: 'Permission check failed' });
            return;
        }
    };
};

// Rate limiting middleware
const rateLimit = (limit, windowMs) => {
    const requests = new Map();
    
    return async (request, reply) => {
        const ip = request.ip;
        const now = Date.now();
        
        if (requests.has(ip)) {
            const data = requests.get(ip);
            
            // Clean old requests
            data.timestamps = data.timestamps.filter(time => now - time < windowMs);
            
            if (data.timestamps.length >= limit) {
                reply.code(429).send({ error: 'Too many requests' });
                return;
            }
            
            data.timestamps.push(now);
        } else {
            requests.set(ip, { timestamps: [now] });
        }
        
        // Clean up old entries
        for (const [key, data] of requests.entries()) {
            if (now - Math.max(...data.timestamps) > windowMs) {
                requests.delete(key);
            }
        }
    };
};

// Combine multiple middleware
const combineMiddleware = (...middlewares) => {
    return async (request, reply) => {
        for (const middleware of middlewares) {
            await middleware(request, reply);
            if (reply.sent) return;
        }
    };
};

module.exports = {
    authenticate,
    authenticateUser,
    authenticateAdmin,
    authenticateModerator,
    optionalAuthenticate,
    checkPayment,
    verifyModeratorDevice,
    checkAdminPermission,
    rateLimit,
    combineMiddleware
};