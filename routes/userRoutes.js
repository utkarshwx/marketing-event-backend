const User = require('../models/User');
const Event = require('../models/Event');
const Payment = require('../models/Payment');
const { authenticateUser } = require('../middleware/auth');
const razorpayService = require('../utils/razorpayService');
const config = require('../config/config');
const generateId = require('../worker/generateId'); // Added this import

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

    // Initiate payment with Razorpay
    fastify.post('/payments/initiate', { preHandler: authenticateUser }, async (request, reply) => {
        try {
            const { userId } = request.user;
            const user = await User.findOne({ userId });

            // Check if payment already exists
            const existingPayment = await Payment.findOne({
                userId,
                status: 'success'
            });

            if (existingPayment) {
                return reply.code(400).send({ error: 'Payment already completed' });
            }

            // Create a new payment record with an ID generated before saving
            const payment = new Payment({
                userId,
                amount: 1000, // Example amount (₹1000)
                status: 'pending'
            });
            
            // Generate and set paymentId before saving
            payment.paymentId = await generateId('PAY');
            
            // Now save the payment with a guaranteed paymentId
            await payment.save();

            // Create Razorpay order
            const order = await razorpayService.createOrder({
                amount: payment.amount,
                receipt: payment.paymentId,
                userId
            });

            // Update the payment with the order ID
            payment.razorpayOrderId = order.id;
            await payment.save();

            // Log order creation
            request.log.info({
                action: 'razorpay_order_created',
                userId,
                paymentId: payment.paymentId,
                orderId: order.id
            });

            // Return order details for frontend
            reply.send({
                paymentId: payment.paymentId,
                orderId: order.id,
                amount: order.amount / 100, // Convert paisa to rupees
                currency: order.currency,
                key: config.RAZORPAY_KEY_ID,
                name: 'KIIT Event Registration',
                description: 'Event Registration Fee',
                prefillData: {
                    name: user.name,
                    email: user.email,
                    contact: user.phoneNumber
                },
                callbackUrl: config.RAZORPAY_CALLBACK_URL
            });
        } catch (error) {
            console.error('Payment initiation error:', error);
            reply.code(500).send({ error: 'Failed to initiate payment' });
        }
    });

    // Verify Razorpay payment
    fastify.post('/payments/verify', { preHandler: authenticateUser }, async (request, reply) => {
        try {
            const { orderId, paymentId, signature } = request.body;
            const { userId } = request.user;

            // Verify payment signature
            const isValidSignature = razorpayService.verifyPaymentSignature({
                orderId,
                paymentId,
                signature
            });

            if (!isValidSignature) {
                request.log.warn({
                    action: 'invalid_payment_signature',
                    userId,
                    paymentId,
                    ip: request.ip
                });
                return reply.code(400).send({ error: 'Invalid payment signature' });
            }

            // Get payment details from Razorpay
            const paymentDetails = await razorpayService.fetchPaymentDetails(paymentId);
            
            // Check if payment is successful
            if (paymentDetails.status !== 'captured') {
                return reply.code(400).send({ 
                    error: 'Payment not completed',
                    status: paymentDetails.status
                });
            }

            // Find and update the payment record
            const payment = await Payment.findOne({ 
                userId,
                status: 'pending'
            });

            if (!payment) {
                return reply.code(404).send({ error: 'Payment record not found' });
            }

            // Update payment status
            payment.status = 'success';
            payment.transactionId = paymentId;
            payment.gatewayResponse = JSON.stringify(paymentDetails);
            payment.paymentDate = new Date();
            await payment.save();

            // Update user payment status
            const user = await User.findOne({ userId });
            user.hasValidPayment = true;
            await user.save();

            // Generate QR code for the user
            await user.generateQRCode();

            // Log successful payment
            request.log.info({
                action: 'payment_successful',
                userId,
                paymentId,
                amount: payment.amount
            });

            reply.send({
                success: true,
                message: 'Payment verified successfully',
                qrCode: user.qrCode.code
            });
        } catch (error) {
            console.error('Payment verification error:', error);
            reply.code(500).send({ error: 'Payment verification failed' });
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