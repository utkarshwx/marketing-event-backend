// index.js
const fastify = require('fastify')({ 
  logger: {
      level: 'info',
      serializers: {
          req(request) {
              return {
                  method: request.method,
                  url: request.url,
                  headers: request.headers,
                  hostname: request.hostname,
                  remoteAddress: request.ip,
                  remotePort: request.socket ? request.socket.remotePort : undefined
              };
          }
      }
  }
});
const mongoose = require('mongoose');
const path = require('path');
const config = require('./config/config');

// Import routes
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const moderatorRoutes = require('./routes/moderatorRoutes');
const adminRoutes = require('./routes/adminRoutes');

// Import middleware
const {
  authenticateUser,
  authenticateAdmin,
  authenticateModerator,
  checkPayment
} = require('./middleware/auth');
const rateLimiters = require('./middleware/rateLimiter');

// Register Fastify plugins
fastify.register(require('@fastify/cors'), {
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
      'Origin',
      'X-Requested-With',
      'Accept',
      'Content-Type',
      'Authorization',
      'Device-ID'
  ],
  credentials: true,
  preflight: true
});

// Global rate limiting
fastify.addHook('onRequest', rateLimiters.global);

// Add error handler
fastify.setErrorHandler(function (error, request, reply) {
  // Log error
  request.log.error(error);
  
  // Handle validation errors
  if (error.validation) {
      reply.status(400).send({
          error: 'Validation failed',
          details: error.validation
      });
      return;
  }

  // Handle JWT errors
  if (error.name === 'JsonWebTokenError') {
      reply.status(401).send({ error: 'Invalid token' });
      return;
  }

  if (error.name === 'TokenExpiredError') {
      reply.status(401).send({ error: 'Token expired' });
      return;
  }

  // Handle not found errors
  if (error.statusCode === 404) {
      reply.status(404).send({ error: 'Resource not found' });
      return;
  }

  // Default error
  reply.status(error.statusCode || 500).send({
      error: error.message || 'Internal Server Error'
  });
});

// Connect to MongoDB
// MongoDB Connection Options
const mongoOptions = {
  retryWrites: true,
  w: 'majority',
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  family: 4 // Force IPv4
};

// MongoDB Connection with detailed error handling
mongoose.connect(config.MONGODB_URI, mongoOptions)
  .then(() => {
      fastify.log.info({
          message: 'Connected to MongoDB',
          database: mongoose.connection.name,
          host: mongoose.connection.host
      });
  })
  .catch((err) => {
      fastify.log.error({
          message: 'MongoDB connection error',
          error: err.message,
          code: err.code,
          name: err.name
      });

      // More specific error messages based on error type
      if (err.name === 'MongoServerSelectionError') {
          fastify.log.error('Could not connect to any MongoDB server');
      } else if (err.name === 'MongoNetworkError') {
          fastify.log.error('Network error while connecting to MongoDB');
      }

      process.exit(1);
  });

// Add MongoDB connection event listeners
mongoose.connection.on('connected', () => {
  fastify.log.info('Mongoose connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  fastify.log.error({
      message: 'Mongoose connection error',
      error: err.message
  });
});

mongoose.connection.on('disconnected', () => {
  fastify.log.warn('Mongoose disconnected from MongoDB');
});

// Handle process termination
process.on('SIGINT', async () => {
  try {
      await mongoose.connection.close();
      fastify.log.info('MongoDB connection closed through app termination');
      process.exit(0);
  } catch (err) {
      fastify.log.error({
          message: 'Error closing MongoDB connection',
          error: err.message
      });
      process.exit(1);
  }
});

// Register routes with their respective authentication
// Auth routes (public)
fastify.register(authRoutes, { prefix: '/api/auth' });

// User routes (requires user authentication)
fastify.register(userRoutes, { 
  prefix: '/api/user',
  preHandler: authenticateUser
});

// Moderator routes (requires moderator authentication)
fastify.register(moderatorRoutes, {
  prefix: '/api/moderator',
  preHandler: authenticateModerator
});

// Admin routes (requires admin authentication)
fastify.register(adminRoutes, {
  prefix: '/api/admin',
  preHandler: authenticateAdmin
});

// Handle payment webhook (public route but rate limited)
fastify.post('/api/payments/webhook', {
  preHandler: rateLimiters.custom(100, 60 * 1000) // 100 requests per minute for webhook
}, async (request, reply) => {
  try {
      // Validate webhook signature if using a payment gateway that supports it
      // This adds another layer of security beyond rate limiting
      
      const { paymentId, status, transactionId, gatewayResponse } = request.body;

      const payment = await Payment.findOne({ paymentId });
      if (!payment) {
          return reply.code(404).send({ error: 'Payment not found' });
      }

      // Log payment update from webhook
      request.log.info({
          action: 'payment_webhook_received',
          paymentId,
          status,
          transactionId,
          ip: request.ip
      });

      payment.status = status;
      payment.transactionId = transactionId;
      payment.gatewayResponse = gatewayResponse;
      payment.paymentDate = new Date();
      await payment.save();

      if (status === 'success') {
          // Update user payment status
          const user = await User.findOne({ userId: payment.userId });
          user.hasValidPayment = true;
          await user.save();

          // Generate QR code
          await user.generateQRCode();
          
          // Log successful payment
          request.log.info({
              action: 'payment_successful',
              paymentId,
              userId: payment.userId,
              amount: payment.amount
          });
      }

      reply.send({ message: 'Payment status updated' });
  } catch (error) {
      request.log.error('Payment webhook error:', error);
      reply.code(500).send({ error: 'Internal server error' });
  }
});

// Graceful shutdown handler
const gracefulShutdown = async (signal) => {
  fastify.log.info(`Received ${signal}. Starting graceful shutdown...`);
  
  try {
      // Close fastify server
      await fastify.close();
      fastify.log.info('Fastify server closed');
      
      // Close MongoDB connection
      await mongoose.connection.close();
      fastify.log.info('MongoDB connection closed');
      
      process.exit(0);
  } catch (err) {
      fastify.log.error('Error during shutdown:', err);
      process.exit(1);
  }
};

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions and rejections
process.on('uncaughtException', (err) => {
  fastify.log.error('Uncaught Exception:', err);
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  fastify.log.error('Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown('unhandledRejection');
});

// Start server
const start = async () => {
  try {
      // Log server configuration (excluding sensitive data)
      fastify.log.info({
          environment: config.NODE_ENV,
          port: config.PORT,
          mongoDbConnected: mongoose.connection.readyState === 1,
          rateLimitWindow: `${config.RATE_LIMIT_WINDOW_MS/60000} minutes`,
          maxRequestsPerWindow: config.RATE_LIMIT_MAX_REQUESTS
      }, 'Server configuration');

      await fastify.listen({ 
          port: config.PORT,
          host: '0.0.0.0'
      });
      
      fastify.log.info(`Server listening on ${fastify.server.address().port}`);
  } catch (err) {
      fastify.log.error(err);
      process.exit(1);
  }
};

start();