const User = require('../models/User');
const Event = require('../models/Event');
const Payment = require('../models/Payment');
const { authenticateUser } = require('../middleware/auth');

async function userRoutes(fastify) {
    // Get user profile
    fastify.get('/profile', { preHandler: authenticateUser }, async (request, reply) => {
        try {
            const { userId } = request.user;
            const user = await User.findOne({ userId })
                .select('-password')
                .lean();

            if (!user) {
                return reply.code(404).send({ error: 'User not found' });
            }

            // Add QR code if payment is valid
            if (user.hasValidPayment && !user.qrCode.code) {
                const userDoc = await User.findOne({ userId });
                await userDoc.generateQRCode();
                user.qrCode = userDoc.qrCode;
            }

            reply.send(user);
        } catch (error) {
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Initiate payment
    fastify.post('/payments/initiate', { preHandler: authenticateUser }, async (request, reply) => {
        try {
            const { userId } = request.user;

            // Check if payment already exists
            const existingPayment = await Payment.findOne({
                userId,
                status: 'success'
            });

            if (existingPayment) {
                return reply.code(400).send({ error: 'Payment already completed' });
            }

            const payment = new Payment({
                userId,
                amount: 1000, // Example amount
                status: 'pending'
            });
            await payment.save();

            // Initialize payment gateway
            const paymentData = {
                merchantId: process.env.BILLDESK_MERCHANT_ID,
                paymentId: payment.paymentId,
                amount: payment.amount,
                callbackUrl: process.env.BILLDESK_CALLBACK_URL
            };

            reply.send({
                paymentUrl: 'your-payment-gateway-url',
                paymentId: payment.paymentId,
                paymentData
            });
        } catch (error) {
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Get available events
    fastify.get('/events', { preHandler: authenticateUser }, async (request, reply) => {
        try {
            const { userId } = request.user;
            const user = await User.findOne({ userId });

            if (!user.hasValidPayment) {
                return reply.code(403).send({ error: 'Payment required to view events' });
            }

            const events = await Event.find({ 
                isActive: true,
                eventStatus: { $in: ['upcoming', 'ongoing'] },
                registrationDeadline: { $gt: new Date() }
            }).lean();

            // Add registration status for each event
            const eventsWithStatus = events.map(event => ({
                ...event,
                isCurrentlyRegistered: event.eventId === user.currentEvent,
                availableSlots: event.capacity - event.registeredCount
            }));

            reply.send(eventsWithStatus);
        } catch (error) {
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Register for event
    fastify.post('/events/register', { preHandler: authenticateUser }, async (request, reply) => {
        try {
            const { userId } = request.user;
            const { eventId } = request.body;

            const user = await User.findOne({ userId });
            if (!user.hasValidPayment) {
                return reply.code(403).send({ error: 'Payment required for event registration' });
            }

            const event = await Event.findOne({ eventId });
            if (!event) {
                return reply.code(404).send({ error: 'Event not found' });
            }

            // Check event availability
            const availability = await Event.checkAvailability(eventId);
            if (!availability.available) {
                return reply.code(400).send({ error: 'Event is not available for registration' });
            }

            // If user is already registered for another event, handle the change
            if (user.currentEvent && user.currentEvent !== eventId) {
                const oldEvent = await Event.findOne({ eventId: user.currentEvent });
                if (oldEvent) {
                    await oldEvent.decrementRegistration();
                }
            }

            // Register for new event
            await event.incrementRegistration();
            user.currentEvent = eventId;
            await user.save();

            reply.send({ 
                message: 'Event registration successful',
                eventDetails: {
                    eventId: event.eventId,
                    eventName: event.eventName,
                    eventDate: event.eventDate
                }
            });
        } catch (error) {
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    // Change event registration
    fastify.post('/events/change', { preHandler: authenticateUser }, async (request, reply) => {
        try {
            const { userId } = request.user;
            const { newEventId } = request.body;

            const user = await User.findOne({ userId });
            if (!user.currentEvent) {
                return reply.code(400).send({ error: 'No current event registration found' });
            }

            // Process same as registration but with additional logging
            await userRoutes.generateRoute('POST', '/events/register').handler(request, reply);
        } catch (error) {
            reply.code(500).send({ error: 'Internal server error' });
        }
    });
}

module.exports = userRoutes;