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
    // Admin Login
    fastify.post('/login', {
        preHandler: rateLimiters.loginStrict
    }, async (request, reply) => {
        try {
            const { email, password } = request.body;

            // First find the user with admin role
            const adminUser = await User.findOne({
                email: email,
                role: 'admin'
            });

            if (!adminUser) {
                // Log failed admin login attempt
                request.log.warn({
                    action: 'failed_admin_login',
                    email,
                    ip: request.ip,
                    userAgent: request.headers['user-agent']
                });

                return reply.code(401).send({ error: 'Invalid credentials' });
            }

            // Verify password
            const isValidPassword = await bcrypt.compare(password, adminUser.password);
            if (!isValidPassword) {
                // Log failed admin login attempt
                request.log.warn({
                    action: 'failed_admin_login_invalid_password',
                    email,
                    ip: request.ip,
                    userAgent: request.headers['user-agent']
                });

                return reply.code(401).send({ error: 'Invalid credentials' });
            }

            // Now find the admin profile
            const admin = await Admin.findOne({ userId: adminUser.userId });
            if (!admin) {
                request.log.error({
                    action: 'admin_profile_missing',
                    userId: adminUser.userId,
                    ip: request.ip
                });

                return reply.code(500).send({ error: 'Admin profile not found' });
            }

            const token = jwt.sign(
                { userId: adminUser.userId, adminId: adminUser.userId, role: adminUser.role },
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
                userId: adminUser.userId,
                ip: request.ip
            });

            reply.send({
                token,
                admin: {
                    userId: adminUser.userId,
                    email: adminUser.email,
                    role: adminUser.role,
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

    fastify.get('/profile', {
        preHandler: authenticateAdmin
    }, async (request, reply) => {
        try {
            const admin = await Admin.findOne({ userId: request.user.adminId });
            reply.send(admin);
        } catch (error) {
            console.error('Admin profile error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    fastify.put('/profile', {
        preHandler: [
            authenticateAdmin,
            checkAdminPermission('canUpdateProfile'),
            rateLimiters.adminOperations
        ]
    }, async (request, reply) => {
        try {
            const { name, email } = request.body;
            const admin = await Admin.findOne({ userId: request.user.adminId });
            admin.name = name;
            admin.email = email;
            await admin.save();
            reply.send({ message: 'Profile updated successfully' });
        } catch (error) {    
            console.error('Admin profile update error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // User Management
    // Get all users
    fastify.get('/users', {
        preHandler: [
            authenticateAdmin,
            checkAdminPermission('canViewUsers'),
            rateLimiters.adminOperations
        ]
    }, async (request, reply) => {
        try {
            const users = await User.find({ role: 'user' });
            reply.send(users);
        } catch (error) {
            console.error('Get all users error:', error);
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
            const { userId } = request.user;  // Get userId from the JWT token

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
                activeStatus: 'active',
                createdBy: userId  // Add the createdBy field
            });

            await moderator.save();

            // Log activity
            const admin = await Admin.findOne({ userId });
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
            // Use lean() for better performance, and DON'T try to populate with ObjectId
            const moderators = await Moderator.find()
                .lean();

            // Fetch user details separately with proper string ID matching
            const moderatorUserIds = moderators.map(mod => mod.userId);
            const users = await User.find({ userId: { $in: moderatorUserIds } })
                .select('name email')
                .lean();

            // Create a lookup map for fast access
            const userMap = {};
            users.forEach(user => {
                userMap[user.userId] = user;
            });

            const moderatorStats = moderators.map(moderator => {
                const user = userMap[moderator.userId] || { name: 'Unknown', email: 'Unknown' };

                return {
                    ...moderator,
                    user: {
                        name: user.name,
                        email: user.email
                    },
                    dailyAverage: moderator.totalScans /
                        Math.max(1, Math.ceil((Date.now() - new Date(moderator.createdAt).getTime()) / (1000 * 60 * 60 * 24))),
                    lastActive: moderator.lastActive,
                    status: moderator.activeStatus
                };
            });

            reply.send(moderatorStats);
        } catch (error) {
            console.error('Moderator stats error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Get Payment Reports
    // Get Payment Reports with Razorpay details
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

            // Process payment data to include Razorpay specific information
            const processedPayments = payments.map(payment => {
                let razorpayDetails = {};

                if (payment.gatewayResponse) {
                    try {
                        const gatewayData = JSON.parse(payment.gatewayResponse);
                        razorpayDetails = {
                            paymentMethod: gatewayData.method || 'unknown',
                            bank: gatewayData.bank || 'N/A',
                            cardNetwork: gatewayData.card?.network || 'N/A',
                            upiId: gatewayData.vpa?.descriptor || 'N/A',
                            fee: gatewayData.fee || 0,
                            tax: gatewayData.tax || 0
                        };
                    } catch (e) {
                        // If JSON parsing fails, continue with empty details
                        console.error('Error parsing gateway response:', e);
                    }
                }

                return {
                    ...payment,
                    gateway: 'Razorpay',
                    razorpayDetails
                };
            });

            // Calculate reports
            const report = {
                totalPayments: processedPayments.length,
                successfulPayments: processedPayments.filter(p => p.status === 'success').length,
                failedPayments: processedPayments.filter(p => p.status === 'failed').length,
                pendingPayments: processedPayments.filter(p => p.status === 'pending').length,
                totalAmount: processedPayments.reduce((sum, p) => sum + (p.status === 'success' ? p.amount : 0), 0),

                // Payment method breakdown
                paymentMethods: processedPayments.reduce((acc, p) => {
                    if (p.status === 'success' && p.razorpayDetails.paymentMethod) {
                        const method = p.razorpayDetails.paymentMethod;
                        acc[method] = (acc[method] || 0) + 1;
                    }
                    return acc;
                }, {}),

                // Daily payments
                paymentsByDate: processedPayments.reduce((acc, p) => {
                    if (p.status === 'success') {
                        const date = p.createdAt.toISOString().split('T')[0];
                        acc[date] = (acc[date] || 0) + p.amount;
                    }
                    return acc;
                }, {}),

                // Refund statistics
                refunds: {
                    total: processedPayments.filter(p => p.refundStatus === 'completed').length,
                    pending: processedPayments.filter(p => ['requested', 'processing'].includes(p.refundStatus)).length,
                    amount: processedPayments.reduce((sum, p) => sum + (p.refundStatus === 'completed' ? (p.refundAmount || 0) : 0), 0)
                },

                // Gateway fees
                gatewayFees: processedPayments.reduce((sum, p) => {
                    if (p.status === 'success' && p.razorpayDetails.fee) {
                        return sum + p.razorpayDetails.fee;
                    }
                    return sum;
                }, 0),

                // Recent payments (last 10)
                recentPayments: processedPayments
                    .filter(p => p.status === 'success')
                    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
                    .slice(0, 10)
                    .map(p => ({
                        id: p.paymentId,
                        user: p.userId?.name || 'Unknown',
                        email: p.userId?.email || 'Unknown',
                        amount: p.amount,
                        date: p.paymentDate || p.createdAt,
                        method: p.razorpayDetails.paymentMethod || 'Unknown'
                    }))
            };

            reply.send(report);
        } catch (error) {
            console.error('Payment report error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Get detailed payment information
    fastify.get('/payments/:paymentId', { preHandler: authenticateAdmin }, async (request, reply) => {
        try {
            const { paymentId } = request.params;

            const payment = await Payment.findOne({ paymentId })
                .populate('userId', 'name email phoneNumber')
                .lean();

            if (!payment) {
                return reply.code(404).send({ error: 'Payment not found' });
            }

            // Parse gateway response if available
            let gatewayData = {};
            if (payment.gatewayResponse) {
                try {
                    gatewayData = JSON.parse(payment.gatewayResponse);
                } catch (e) {
                    console.error('Error parsing gateway response:', e);
                }
            }

            const paymentDetails = {
                ...payment,
                gatewayData,
                gateway: 'Razorpay'
            };

            reply.send(paymentDetails);
        } catch (error) {
            console.error('Payment detail error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Initiate refund for a payment
    fastify.post('/payments/:paymentId/refund', {
        preHandler: [authenticateAdmin, checkAdminPermission('canGenerateReports')]
    }, async (request, reply) => {
        try {
            const { paymentId } = request.params;
            const { amount, reason } = request.body;
            const { userId: adminId } = request.user;

            const payment = await Payment.findOne({ paymentId });
            if (!payment) {
                return reply.code(404).send({ error: 'Payment not found' });
            }

            if (payment.status !== 'success') {
                return reply.code(400).send({ error: 'Only successful payments can be refunded' });
            }

            if (payment.refundStatus !== 'none') {
                return reply.code(400).send({
                    error: `Refund already ${payment.refundStatus}`,
                    refundStatus: payment.refundStatus
                });
            }

            // Get Razorpay payment details
            const razorpayService = require('../services/razorpayService');
            const refundAmount = amount || payment.amount;

            // Initiate refund in Razorpay
            const refund = await razorpayService.initiateRefund(
                payment.transactionId,
                refundAmount * 100 // Convert to paisa
            );

            // Update payment record
            payment.refundStatus = 'processing';
            payment.refundId = refund.id;
            payment.refundAmount = refundAmount;
            payment.refundDate = new Date();
            await payment.save();

            // Log admin activity
            const admin = await Admin.findOne({ userId: adminId });
            await admin.logActivity('payment_refund', {
                paymentId,
                amount: refundAmount,
                reason,
                refundId: refund.id
            });

            // Log refund initiation
            request.log.info({
                action: 'payment_refund_initiated',
                adminId,
                paymentId,
                refundId: refund.id,
                amount: refundAmount
            });

            reply.send({
                success: true,
                message: 'Refund initiated successfully',
                refundId: refund.id,
                status: 'processing'
            });
        } catch (error) {
            console.error('Refund initiation error:', error);
            reply.code(500).send({ error: 'Failed to initiate refund' });
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