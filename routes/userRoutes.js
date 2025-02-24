const User = require('../models/User');
const Event = require('../models/Event');
const Payment = require('../models/Payment');
const { authenticateUser } = require('../middleware/auth');
const razorpayService = require('../utils/razorpayService');
const config = require('../config/config');
const generateId = require('../worker/generateId');

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

            try {
                // Try to create Razorpay order
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
                return reply.send({
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
                    callbackUrl: `${request.protocol}://${request.hostname}/api/user/payments/callback`
                });
            } catch (razorpayError) {
                console.error('Razorpay order creation error:', razorpayError);
                
                // If we're in development mode and there's a Razorpay error,
                // provide a mock payment flow for testing
                if (config.isDevelopment()) {
                    // Auto-approve the payment for development/testing
                    payment.status = 'success';
                    payment.transactionId = 'dev_' + Date.now();
                    payment.paymentDate = new Date();
                    await payment.save();
                    
                    // Update user payment status
                    user.hasValidPayment = true;
                    await user.save();
                    
                    // Generate QR code
                    await user.generateQRCode();
                    
                    request.log.info({
                        action: 'dev_payment_auto_approved',
                        userId,
                        paymentId: payment.paymentId
                    });
                    
                    return reply.send({
                        success: true,
                        message: 'Development mode: Payment auto-approved',
                        paymentId: payment.paymentId,
                        note: 'This is a development-only feature. Configure Razorpay for production.',
                        qrCode: user.qrCode.code
                    });
                }
                
                // In production, or if dev mode is not enabled, propagate the error
                throw razorpayError;
            }
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

    // Payment callback handler - this endpoint handles both success and failure
    fastify.post('/payments/callback', async (request, reply) => {
        try {
            const {
                razorpay_payment_id,
                razorpay_order_id,
                razorpay_signature,
                error_code,
                error_description
            } = request.body;
            
            // Log all incoming payment callbacks
            request.log.info({
                action: 'payment_callback_received',
                orderId: razorpay_order_id,
                paymentId: razorpay_payment_id,
                hasSignature: !!razorpay_signature,
                hasError: !!error_code,
                ip: request.ip
            });

            // Get the original payment from our database using the order ID
            // Strip the 'order_' prefix if present
            const orderIdForLookup = razorpay_order_id.startsWith('order_') 
                ? razorpay_order_id 
                : `order_${razorpay_order_id}`;
                
            const payment = await Payment.findOne({ razorpayOrderId: orderIdForLookup });
            
            if (!payment) {
                request.log.error({
                    action: 'payment_callback_order_not_found',
                    orderId: razorpay_order_id,
                    ip: request.ip
                });
                
                return reply.code(404).send({ 
                    success: false,
                    message: 'Payment record not found',
                    redirect: '/payment-error?code=not_found'
                });
            }
            
            // Fetch the user
            const user = await User.findOne({ userId: payment.userId });
            if (!user) {
                request.log.error({
                    action: 'payment_callback_user_not_found',
                    userId: payment.userId,
                    orderId: razorpay_order_id
                });
                
                return reply.code(404).send({ 
                    success: false,
                    message: 'User not found',
                    redirect: '/payment-error?code=user_not_found'
                });
            }

            // Handle payment failure case
            if (error_code) {
                // Update payment status
                payment.status = 'failed';
                payment.gatewayResponse = JSON.stringify({
                    error_code,
                    error_description,
                    timestamp: new Date()
                });
                await payment.save();
                
                request.log.info({
                    action: 'payment_failed',
                    userId: payment.userId,
                    paymentId: payment.paymentId,
                    errorCode: error_code,
                    errorDescription: error_description
                });
                
                return reply.send({
                    success: false,
                    message: 'Payment failed',
                    error: error_description || 'Unknown payment error',
                    redirect: `/payment-failed?code=${error_code}`
                });
            }
            
            // Handle payment success case
            if (razorpay_payment_id && razorpay_signature) {
                // Verify signature
                const isValidSignature = razorpayService.verifyPaymentSignature({
                    orderId: razorpay_order_id,
                    paymentId: razorpay_payment_id,
                    signature: razorpay_signature
                });
                
                if (!isValidSignature) {
                    request.log.warn({
                        action: 'invalid_payment_signature',
                        userId: payment.userId,
                        orderId: razorpay_order_id,
                        paymentId: razorpay_payment_id,
                        ip: request.ip
                    });
                    
                    payment.status = 'failed';
                    payment.gatewayResponse = JSON.stringify({
                        error: 'Invalid signature',
                        timestamp: new Date()
                    });
                    await payment.save();
                    
                    return reply.code(400).send({ 
                        success: false,
                        message: 'Invalid payment signature',
                        redirect: '/payment-error?code=invalid_signature'
                    });
                }
                
                // Get payment details from Razorpay
                const paymentDetails = await razorpayService.fetchPaymentDetails(razorpay_payment_id);
                
                // Check if payment is successful
                if (paymentDetails.status !== 'captured') {
                    payment.status = 'failed';
                    payment.transactionId = razorpay_payment_id;
                    payment.gatewayResponse = JSON.stringify(paymentDetails);
                    await payment.save();
                    
                    return reply.send({ 
                        success: false,
                        message: 'Payment not completed',
                        status: paymentDetails.status,
                        redirect: `/payment-failed?status=${paymentDetails.status}`
                    });
                }
                
                // Payment is successful - update payment status
                payment.status = 'success';
                payment.transactionId = razorpay_payment_id;
                payment.gatewayResponse = JSON.stringify(paymentDetails);
                payment.paymentDate = new Date();
                await payment.save();
                
                // Update user payment status
                user.hasValidPayment = true;
                await user.save();
                
                // Generate QR code for the user
                await user.generateQRCode();
                
                // Log successful payment
                request.log.info({
                    action: 'payment_successful',
                    userId: user.userId,
                    paymentId: razorpay_payment_id,
                    orderId: razorpay_order_id,
                    amount: payment.amount
                });
                
                return reply.send({
                    success: true,
                    message: 'Payment verified successfully',
                    qrCode: user.qrCode.code,
                    redirect: '/payment-success'
                });
            }
            
            // If we reach here, the callback didn't include payment details or error
            return reply.code(400).send({
                success: false,
                message: 'Invalid callback data',
                redirect: '/payment-error?code=invalid_data'
            });
            
        } catch (error) {
            request.log.error({
                action: 'payment_callback_error',
                error: error.message,
                stack: error.stack
            });
            
            reply.code(500).send({ 
                success: false,
                message: 'Payment processing error',
                redirect: '/payment-error?code=server_error'
            });
        }
    });

    

    // Handle payment success page redirect
    fastify.get('/payment-success', async (request, reply) => {
        // This can serve an HTML success page or redirect to your frontend
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
            <title>Payment Successful</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {
                font-family: 'Roboto', sans-serif;
                text-align: center;
                padding: 40px 20px;
                background-color: #f8f9fa;
                color: #333;
                }
                .container {
                max-width: 600px;
                margin: 0 auto;
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                }
                .success-icon {
                color: #05a000;
                font-size: 64px;
                margin-bottom: 20px;
                }
                h1 {
                color: #05a000;
                margin-bottom: 20px;
                }
                .btn {
                display: inline-block;
                padding: 12px 24px;
                background-color: #05a000;
                color: white;
                border-radius: 4px;
                text-decoration: none;
                margin-top: 20px;
                font-weight: 500;
                }
            </style>
            </head>
            <body>
            <div class="container">
                <div class="success-icon">✓</div>
                <h1>Payment Successful!</h1>
                <p>Your payment has been processed successfully. You can now proceed to register for events.</p>
                <p>Your QR code has been generated and is available in your profile.</p>
                <a href="/events" class="btn">Browse Events</a>
            </div>
            </body>
            </html>
        `;
        
        reply.type('text/html').send(html);
    });

    // Handle payment failure page redirect
    fastify.get('/payment-failed', async (request, reply) => {
        const { code, status } = request.query;
        
        // This can serve an HTML failure page or redirect to your frontend
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
            <title>Payment Failed</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {
                font-family: 'Roboto', sans-serif;
                text-align: center;
                padding: 40px 20px;
                background-color: #f8f9fa;
                color: #333;
                }
                .container {
                max-width: 600px;
                margin: 0 auto;
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                }
                .error-icon {
                color: #dc3545;
                font-size: 64px;
                margin-bottom: 20px;
                }
                h1 {
                color: #dc3545;
                margin-bottom: 20px;
                }
                .error-details {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 4px;
                margin: 20px 0;
                text-align: left;
                }
                .btn {
                display: inline-block;
                padding: 12px 24px;
                background-color: #05a000;
                color: white;
                border-radius: 4px;
                text-decoration: none;
                margin-top: 20px;
                font-weight: 500;
                }
            </style>
            </head>
            <body>
            <div class="container">
                <div class="error-icon">✗</div>
                <h1>Payment Failed</h1>
                <p>We couldn't process your payment at this time.</p>
                
                <div class="error-details">
                <p><strong>Error code:</strong> ${code || status || 'Unknown'}</p>
                <p>Please try again or contact support if the problem persists.</p>
                </div>
                
                <a href="/payments/initiate" class="btn">Try Again</a>
            </div>
            </body>
            </html>
        `;
        
        reply.type('text/html').send(html);
    });

    // Generic payment error handler
    fastify.get('/payment-error', async (request, reply) => {
        const { code } = request.query;
        
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
            <title>Payment Error</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {
                font-family: 'Roboto', sans-serif;
                text-align: center;
                padding: 40px 20px;
                background-color: #f8f9fa;
                color: #333;
                }
                .container {
                max-width: 600px;
                margin: 0 auto;
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                }
                .error-icon {
                color: #dc3545;
                font-size: 64px;
                margin-bottom: 20px;
                }
                h1 {
                color: #dc3545;
                margin-bottom: 20px;
                }
                .error-details {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 4px;
                margin: 20px 0;
                text-align: left;
                }
                .btn {
                display: inline-block;
                padding: 12px 24px;
                background-color: #05a000;
                color: white;
                border-radius: 4px;
                text-decoration: none;
                margin-top: 20px;
                font-weight: 500;
                }
            </style>
            </head>
            <body>
            <div class="container">
                <div class="error-icon">⚠️</div>
                <h1>Payment Error</h1>
                <p>There was a problem processing your payment request.</p>
                
                <div class="error-details">
                <p><strong>Error type:</strong> ${getErrorMessage(code)}</p>
                <p>If this problem persists, please contact support.</p>
                </div>
                
                <a href="/payments/initiate" class="btn">Try Again</a>
            </div>
            </body>
            </html>
        `;
        
        function getErrorMessage(code) {
            const errorMessages = {
            'not_found': 'Payment record not found',
            'user_not_found': 'User account not found',
            'invalid_signature': 'Invalid payment verification',
            'invalid_data': 'Invalid payment data received',
            'server_error': 'Server error processing payment',
            };
            
            return errorMessages[code] || 'Unknown error';
        }
        
        reply.type('text/html').send(html);
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