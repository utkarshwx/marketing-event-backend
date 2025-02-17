const User = require('../models/User');
const Moderator = require('../models/Moderator');
const { authenticateModerator } = require('../middleware/auth');

async function moderatorRoutes(fastify) {
    // Get moderator profile and stats
    fastify.get('/profile', { preHandler: authenticateModerator }, async (request, reply) => {
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

    // Scan QR code
    fastify.post('/scan', { preHandler: authenticateModerator }, async (request, reply) => {
        try {
            const { userId: moderatorId } = request.user;
            const { qrCode, location, deviceInfo } = request.body;

            // Validate QR code format
            if (!qrCode.startsWith('QR_')) {
                return reply.code(400).send({ error: 'Invalid QR code format' });
            }

            // Find user by QR code
            const user = await User.findOne({ 'qrCode.code': qrCode });
            if (!user) {
                return reply.code(404).send({ error: 'Invalid QR code' });
            }

            // Check if QR code has been used
            if (user.qrCode.isUsed) {
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
            await moderator.logScan(qrCode, user.userId, location, deviceInfo);

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

    // Get scan history
    fastify.get('/scans', { preHandler: authenticateModerator }, async (request, reply) => {
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

    // Register device for scanning
    fastify.post('/register-device', { preHandler: authenticateModerator }, async (request, reply) => {
        try {
            const { userId } = request.user;
            const { deviceId, deviceInfo } = request.body;

            const moderator = await Moderator.findOne({ userId });
            
            // Update device information
            moderator.deviceId = deviceId;
            moderator.lastActive = new Date();
            await moderator.save();

            reply.send({ 
                message: 'Device registered successfully',
                deviceId
            });
        } catch (error) {
            reply.code(500).send({ error: 'Internal server error' });
        }
    });
}

module.exports = moderatorRoutes;