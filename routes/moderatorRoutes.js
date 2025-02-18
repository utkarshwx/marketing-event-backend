// routes/moderator.js
const User = require('../models/User');
const Moderator = require('../models/Moderator');
const { authenticateModerator, verifyModeratorDevice } = require('../middleware/auth');
const rateLimiters = require('../middleware/rateLimiter');

async function moderatorRoutes(fastify) {
    // Get moderator profile and stats
    fastify.get('/profile', { 
        preHandler: authenticateModerator 
    }, async (request, reply) => {
        try {
            const { userId } = request.user;
            const moderator = await Moderator.findOne({ userId })
                .populate('assignedEvents', 'eventName eventDate')
                .lean();

            if (!moderator) {
                return reply.code(404).send({ error: 'Moderator not found' });
            }

            // Reset daily scans if needed
            const modDoc = await Moderator.findOne({ userId });
            await modDoc.resetDailyScans();

            reply.send({
                ...moderator,
                scansToday: modDoc.scansToday,
                totalScans: modDoc.totalScans
            });
        } catch (error) {
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Scan QR code - apply rate limiting per device to prevent abuse
    fastify.post('/scan', { 
        preHandler: [
            authenticateModerator,
            verifyModeratorDevice,
            rateLimiters.qrScan
        ]
    }, async (request, reply) => {
        try {
            const { userId: moderatorId } = request.user;
            const { qrCode, location, deviceInfo } = request.body;

            // Validate QR code format
            if (!qrCode.startsWith('QR_')) {
                // Log invalid scan attempt
                request.log.info({
                    action: 'invalid_qr_scan_attempt',
                    moderatorId,
                    qrFormat: qrCode.substring(0, 5),
                    deviceId: deviceInfo?.deviceId
                });
                
                return reply.code(400).send({ error: 'Invalid QR code format' });
            }

            // Find user by QR code
            const user = await User.findOne({ 'qrCode.code': qrCode });
            if (!user) {
                // Log invalid QR code scan
                request.log.info({
                    action: 'nonexistent_qr_scan',
                    moderatorId,
                    qrCode,
                    deviceId: deviceInfo?.deviceId
                });
                
                return reply.code(404).send({ error: 'Invalid QR code' });
            }

            // Check if QR code has been used
            if (user.qrCode.isUsed) {
                // Log attempt to reuse QR code
                request.log.info({
                    action: 'used_qr_rescan_attempt',
                    moderatorId,
                    userId: user.userId,
                    qrCode,
                    originalScanTime: user.qrCode.usedAt
                });
                
                return reply.code(400).send({ 
                    error: 'QR code has already been used',
                    usedBy: user.qrCode.usedBy,
                    usedAt: user.qrCode.usedAt
                });
            }

            // Verify payment status
            if (!user.hasValidPayment) {
                return reply.code(403).send({ error: 'User payment not verified' });
            }

            // Check if user is registered for an event
            if (!user.currentEvent) {
                return reply.code(403).send({ error: 'User not registered for any event' });
            }

            // Use QR code
            await user.useQRCode(moderatorId);

            // Log scan in moderator's history
            const moderator = await Moderator.findOne({ userId: moderatorId });
            await moderator.logScan(qrCode, user.userId, user.currentEvent, location, deviceInfo);

            // Log successful scan
            request.log.info({
                action: 'successful_qr_scan',
                moderatorId,
                userId: user.userId,
                eventId: user.currentEvent,
                location
            });

            // Return user details
            reply.send({
                message: 'QR code validated successfully',
                user: {
                    name: user.name,
                    email: user.email,
                    event: user.currentEvent,
                    scannedAt: new Date()
                }
            });
        } catch (error) {
            console.error('Scan error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Get scan history - apply moderate rate limiting
    fastify.get('/scans', { 
        preHandler: [
            authenticateModerator,
            rateLimiters.custom(20, 60 * 1000) // 20 requests per minute
        ]
    }, async (request, reply) => {
        try {
            const { userId } = request.user;
            const { startDate, endDate } = request.query;

            const moderator = await Moderator.findOne({ userId });
            const stats = await moderator.getScanStats(
                new Date(startDate || Date.now() - 7 * 24 * 60 * 60 * 1000),
                new Date(endDate || Date.now())
            );

            reply.send(stats);
        } catch (error) {
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Register device for scanning - limit to prevent device hopping
    fastify.post('/register-device', { 
        preHandler: [
            authenticateModerator,
            rateLimiters.custom(3, 24 * 60 * 60 * 1000) // 3 device registrations per day
        ]
    }, async (request, reply) => {
        try {
            const { userId } = request.user;
            const { deviceId, deviceInfo } = request.body;

            // Check if device is already registered to another moderator
            const existingDeviceUser = await Moderator.findOne({ 
                'deviceInfo.deviceId': deviceId,
                userId: { $ne: userId }
            });

            if (existingDeviceUser) {
                // Log suspicious device registration attempt
                request.log.warn({
                    action: 'duplicate_device_registration_attempt',
                    userId,
                    deviceId,
                    existingUserId: existingDeviceUser.userId,
                    ip: request.ip
                });
                
                return reply.code(409).send({ error: 'Device already registered to another moderator' });
            }

            // Get moderator and previous device
            const moderator = await Moderator.findOne({ userId });
            const previousDeviceId = moderator.deviceInfo?.deviceId;
            
            // Update device information
            await moderator.registerDevice({
                deviceId,
                deviceModel: deviceInfo?.model || 'Unknown',
                deviceOS: deviceInfo?.os || 'Unknown',
                appVersion: deviceInfo?.appVersion || 'Unknown'
            });

            // Log device registration
            request.log.info({
                action: 'moderator_device_registered',
                userId,
                deviceId,
                previousDeviceId,
                ip: request.ip
            });

            reply.send({ 
                message: 'Device registered successfully',
                deviceId
            });
        } catch (error) {
            console.error('Device registration error:', error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });
}

module.exports = moderatorRoutes;