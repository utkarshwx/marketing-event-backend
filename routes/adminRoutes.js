const User = require('../models/User');
const Admin = require('../models/Admin');
const Event = require('../models/Event');
const Payment = require('../models/Payment');
const Moderator = require('../models/Moderator');
const { 
    authenticateAdmin, 
    checkAdminPermission 
} = require('../middleware/auth');
const bcrypt = require('bcrypt');
const config = require('../config/config');
const rateLimiters = require('../middleware/rateLimiter');
const jwt = require('jsonwebtoken');

async function adminRoutes(fastify) {
    // Admin Login
    fastify.post('/login', {
        preHandler: rateLimiters.loginStrict
    }, async (request, reply) => {
        try {
            const { username, password } = request.body;

            const admin = await Admin.findOne({ username });
            if (!admin) {
                // Log failed admin login attempt
                request.log.warn({
                    action: 'failed_admin_login',
                    username,
                    ip: request.ip,
                    userAgent: request.headers['user-agent']
                });
                
                return reply.code(401).send({ error: 'Invalid credentials' });
            }

            const isValidPassword = await bcrypt.compare(password, admin.password);
            if (!isValidPassword) {
                // Log failed admin login attempt
                request.log.warn({
                    action: 'failed_admin_login_invalid_password',
                    username,
                    ip: request.ip,
                    userAgent: request.headers['user-agent']
                });
                
                return reply.code(401).send({ error: 'Invalid credentials' });
            }

            const token = jwt.sign(
                { adminId: admin.adminId, role: admin.role },
                config.JWT_SECRET,
                { expiresIn: config.JWT_EXPIRES_IN }
            );

            // Update last login and log activity
            admin.lastLogin = new Date();
            await admin.save();
            await admin.logActivity('login', { 
                timestamp: new Date(),
                ip: request.ip,
                userAgent: request.headers['user-agent']
            });

            // Log successful admin login
            request.log.info({
                action: 'successful_admin_login',
                adminId: admin.adminId,
                ip: request.ip
            });

            reply.send({ 
                token,
                admin: {
                    adminId: admin.adminId,
                    username: admin.username,
                    role: admin.role,
                    permissions: admin.permissions
                }
            });
        } catch (error) {
            console.error('Admin login error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    fastify.get('/dashboard', { 
        preHandler: [
            authenticateAdmin,
            rateLimiters.custom(30, 60 * 1000) // 30 requests per minute
        ]
    }, async (request, reply) => {
        try {
            // Get various statistics
            const stats = {
                totalUsers: await User.countDocuments({ role: 'user' }),
                activeUsers: await User.countDocuments({ 
                    role: 'user',
                    hasValidPayment: true 
                }),
                totalEvents: await Event.countDocuments(),
                activeEvents: await Event.countDocuments({ 
                    isActive: true,
                    eventStatus: { $in: ['upcoming', 'ongoing'] }
                }),
                totalPayments: await Payment.countDocuments({ status: 'success' }),
                totalRevenue: (await Payment.aggregate([
                    { $match: { status: 'success' } },
                    { $group: { _id: null, total: { $sum: '$amount' } } }
                ]))[0]?.total || 0,
                moderatorStats: {
                    total: await User.countDocuments({ role: 'moderator' }),
                    active: await User.countDocuments({ 
                        role: 'moderator',
                        'moderator.activeStatus': 'active'
                    })
                }
            };

            // Get recent activities
            const recentActivities = await Admin.aggregate([
                { $unwind: '$activityLog' },
                { $sort: { 'activityLog.timestamp': -1 } },
                { $limit: 10 }
            ]);

            reply.send({
                stats,
                recentActivities
            });
        } catch (error) {
            console.error('Dashboard error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Event Management
    // Create Event
    fastify.post('/events', { 
        preHandler: [
            authenticateAdmin, 
            checkAdminPermission('canCreateEvents'),
            rateLimiters.adminOperations
        ]
    }, async (request, reply) => {
        try {
            const { eventName, description, eventDate, capacity, location, registrationDeadline } = request.body;
            const { adminId } = request.user;

            // Validate capacity
            if (capacity < config.MIN_EVENT_CAPACITY || capacity > config.MAX_EVENT_CAPACITY) {
                return reply.code(400).send({ 
                    error: `Capacity must be between ${config.MIN_EVENT_CAPACITY} and ${config.MAX_EVENT_CAPACITY}` 
                });
            }

            // Create event
            const event = new Event({
                eventName,
                description,
                eventDate: new Date(eventDate),
                capacity,
                location,
                registrationDeadline: new Date(registrationDeadline),
                createdBy: adminId
            });

            await event.save();

            // Log activity
            const admin = await Admin.findOne({ userId: adminId });
            await admin.logActivity('create_event', { 
                eventId: event.eventId,
                eventName: event.eventName 
            });

            reply.code(201).send(event);
        } catch (error) {
            console.error('Create event error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Update Event
    fastify.put('/events/:eventId', {
        preHandler: [authenticateAdmin, checkAdminPermission('canCreateEvents')]
    }, async (request, reply) => {
        try {
            const { eventId } = request.params;
            const updates = request.body;
            const { adminId } = request.user;

            const event = await Event.findOne({ eventId });
            if (!event) {
                return reply.code(404).send({ error: 'Event not found' });
            }

            // Don't allow capacity reduction below current registrations
            if (updates.capacity && updates.capacity < event.registeredCount) {
                return reply.code(400).send({ 
                    error: 'New capacity cannot be less than current registrations' 
                });
            }

            // Update event
            Object.assign(event, updates);
            event.updatedBy = adminId;
            await event.save();

            // Log activity
            const admin = await Admin.findOne({ userId: adminId });
            await admin.logActivity('update_event', { 
                eventId: event.eventId,
                updates: Object.keys(updates)
            });

            reply.send(event);
        } catch (error) {
            console.error('Update event error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Delete/Deactivate Event
    fastify.delete('/events/:eventId', {
        preHandler: [authenticateAdmin, checkAdminPermission('canDeleteEvents')]
    }, async (request, reply) => {
        try {
            const { eventId } = request.params;
            const { adminId } = request.user;
            const { deactivationReason } = request.body;

            const event = await Event.findOne({ eventId });
            if (!event) {
                return reply.code(404).send({ error: 'Event not found' });
            }

            // Check for active registrations
            const hasActiveRegistrations = event.registeredCount > 0;

            if (hasActiveRegistrations) {
                // Deactivate instead of delete
                event.isActive = false;
                event.deactivatedBy = adminId;
                event.deactivationReason = deactivationReason;
                event.deactivatedAt = new Date();
                await event.save();

                // Log activity
                const admin = await Admin.findOne({ userId: adminId });
                await admin.logActivity('deactivate_event', { 
                    eventId: event.eventId,
                    reason: deactivationReason 
                });

                return reply.send({ 
                    message: 'Event deactivated due to active registrations',
                    eventId: event.eventId
                });
            }

            // If no active registrations, delete the event
            await Event.deleteOne({ eventId });

            // Log activity
            const admin = await Admin.findOne({ userId: adminId });
            await admin.logActivity('delete_event', { eventId });

            reply.send({ 
                message: 'Event deleted successfully',
                eventId
            });
        } catch (error) {
            console.error('Delete event error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Get Event Statistics
    fastify.get('/events/stats', { preHandler: authenticateAdmin }, async (request, reply) => {
        try {
            const events = await Event.find().lean();

            const eventStats = await Promise.all(events.map(async (event) => {
                const registeredUsers = await User.find({ currentEvent: event.eventId })
                    .select('name email qrCode.isUsed')
                    .lean();

                return {
                    ...event,
                    registeredCount: registeredUsers.length,
                    scannedCount: registeredUsers.filter(u => u.qrCode.isUsed).length,
                    occupancyRate: (registeredUsers.length / event.capacity) * 100,
                    status: event.eventStatus
                };
            }));

            reply.send(eventStats);
        } catch (error) {
            console.error('Event stats error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Moderator Management
    // Create Moderator
    fastify.post('/moderators', {
        preHandler: [
            authenticateAdmin, 
            checkAdminPermission('canManageModerators'),
            rateLimiters.adminOperations
        ]
    }, async (request, reply) => {
        try {
            const { name, email, phoneNumber, password } = request.body;
            const { adminId } = request.user;

            // Check if email exists
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return reply.code(400).send({ error: 'Email already registered' });
            }

            // Create user with moderator role
            const hashedPassword = await bcrypt.hash(password, config.BCRYPT_SALT_ROUNDS);
            const user = new User({
                name,
                email,
                phoneNumber,
                password: hashedPassword,
                role: 'moderator',
                isEmailVerified: true // Moderators don't need email verification
            });

            await user.save();

            // Create moderator profile
            const moderator = new Moderator({
                userId: user.userId,
                activeStatus: 'active'
            });

            await moderator.save();

            // Log activity
            const admin = await Admin.findOne({ userId: adminId });
            await admin.logActivity('create_moderator', { 
                moderatorId: user.userId,
                moderatorName: name 
            });

            reply.code(201).send({
                message: 'Moderator created successfully',
                moderator: {
                    userId: user.userId,
                    name: user.name,
                    email: user.email
                }
            });
        } catch (error) {
            console.error('Create moderator error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });


    // Get Moderator Statistics
    fastify.get('/moderators/stats', { preHandler: authenticateAdmin }, async (request, reply) => {
        try {
            const moderators = await Moderator.find()
                .populate('userId', 'name email')
                .lean();

            const moderatorStats = moderators.map(moderator => ({
                ...moderator,
                dailyAverage: moderator.totalScans / 
                    Math.max(1, Math.ceil((Date.now() - moderator.createdAt) / (1000 * 60 * 60 * 24))),
                lastActive: moderator.lastActive,
                status: moderator.activeStatus
            }));

            reply.send(moderatorStats);
        } catch (error) {
            console.error('Moderator stats error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Get Payment Reports
    fastify.get('/payments/report', { preHandler: authenticateAdmin }, async (request, reply) => {
        try {
            const { startDate, endDate } = request.query;
            const query = {
                createdAt: {
                    $gte: new Date(startDate || Date.now() - 30 * 24 * 60 * 60 * 1000),
                    $lte: new Date(endDate || Date.now())
                }
            };

            const payments = await Payment.find(query)
                .populate('userId', 'name email')
                .lean();

            const report = {
                totalPayments: payments.length,
                successfulPayments: payments.filter(p => p.status === 'success').length,
                totalAmount: payments.reduce((sum, p) => sum + (p.status === 'success' ? p.amount : 0), 0),
                paymentsByDate: payments.reduce((acc, p) => {
                    const date = p.createdAt.toISOString().split('T')[0];
                    acc[date] = (acc[date] || 0) + (p.status === 'success' ? p.amount : 0);
                    return acc;
                }, {})
            };

            reply.send(report);
        } catch (error) {
            console.error('Payment report error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Get QR Code Usage Report
    fastify.get('/qr-usage/report', { preHandler: authenticateAdmin }, async (request, reply) => {
        try {
            const users = await User.find({
                'qrCode.code': { $exists: true }
            }).lean();

            const report = {
                totalQRCodes: users.length,
                usedQRCodes: users.filter(u => u.qrCode.isUsed).length,
                unusedQRCodes: users.filter(u => !u.qrCode.isUsed).length,
                scannedBy: await Moderator.aggregate([
                    { $unwind: '$scanHistory' },
                    {
                        $group: {
                            _id: '$userId',
                            scanCount: { $sum: 1 }
                        }
                    },
                    { $sort: { scanCount: -1 } }
                ])
            };

            reply.send(report);
        } catch (error) {
            console.error('QR usage report error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });
}

module.exports = adminRoutes;