const fastify = require('fastify')({ logger: true });
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Import models
const User = require('./models/User');
const OTPVerification = require('./models/Otp');
const Payment = require('./models/Payment');
const IDCard = require('./models/IdCard');
const EventRegistration = require('./models/EventRegistration');
const Event = require('./models/Event');
const Admin = require('./models/Admin');
const { default: mongoose } = require('mongoose');
const { sendOtpMail } = require('./utils/mailer');

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

fastify.register(require('fastify-cors'), {
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE']
});

// Authentication & Registration Routes
const userRoutes = async (fastify) => {
  // Register user
  fastify.post('/register', async (request, reply) => {
    try {
      const { name, email, phoneNumber, password } = request.body;

      // Check if user exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        console.log('Duplicate email attempt:', existingUser.email);
        return reply.status(400).send({ error: 'Email already registered' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_SALT_ROUNDS));

      // Create user
      const user = new User({
        name,
        email,
        phoneNumber,
        password: hashedPassword
      });

      await user.save();

      // Generate OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpVerification = new OTPVerification({
        userId: user.userId,
        otp,
        expiresAt: new Date(Date.now() + parseInt(process.env.OTP_EXPIRY_MINUTES) * 60000)
      });

      await otpVerification.save();

      await sendOtpMail(user.email, otp, user.name);

      reply.code(201).send({
        message: 'Registration successful. Please verify your email.',
        userId: user.userId
      });

    } catch (error) {
      console.error("Error:", error);
      if (error.name === 'ValidationError') {
        return reply.code(400).send({ error: error.message });
      }
      reply.code(500).send({ error: 'Internal server error' });
    }
  });

  // Verify email
  fastify.post('/verify-email', async (request, reply) => {
    try {
      const { userId, otp } = request.body;

      const verification = await OTPVerification.findOne({
        userId,
        isVerified: false,
        expiresAt: { $gt: new Date() }
      });

      if (!verification || verification.otp !== otp) {
        return reply.code(400).send({ error: 'Invalid or expired OTP' });
      }

      // Update verification status
      verification.isVerified = true;
      await verification.save();

      // Update user email verification status
      await User.findOneAndUpdate(
        { userId },
        { isEmailVerified: true }
      );

      reply.send({ message: 'Email verified successfully' });
    } catch (error) {
      reply.code(500).send({ error: 'Internal server error' });
    }
  });

  // Login
  fastify.post('/login', async (request, reply) => {
    try {
      const { email, password } = request.body;

      const user = await User.findOne({ email });
      if (!user) {
        return reply.code(401).send({ error: 'Invalid credentials' });
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        return reply.code(401).send({ error: 'Invalid credentials' });
      }

      if (!user.isEmailVerified) {
        return reply.code(403).send({ error: 'Please verify your email first' });
      }

      const token = jwt.sign(
        { userId: user.userId },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
      );

      const payment = await Payment.findOne({
        userId: user.userId,
        status: 'success'
      });

      reply.send({
        token,
        user: {
          userId: user.userId,
          name: user.name,
          email: user.email,
          hasFullAccess: !!payment
        }
      });
    } catch (error) {
      reply.code(500).send({ error: 'Internal server error' });
    }
  });
};

// Protected User Routes
const protectedUserRoutes = async (fastify) => {
  // Initiate payment
  fastify.post('/payments/initiate', async (request, reply) => {
    try {
      const { userId } = request.user;

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

  // Event registration
  fastify.post('/events/register', async (request, reply) => {
    try {
      const { userId } = request.user;
      const { eventId } = request.body;

      // Check payment status
      const payment = await Payment.findOne({
        userId,
        status: 'success'
      });
      if (!payment) {
        return reply.code(403).send({ error: 'Payment required for event registration' });
      }

      // Check existing registration
      const existingRegistration = await EventRegistration.findOne({
        userId,
        eventId,
        isActive: true
      });
      if (existingRegistration) {
        return reply.code(400).send({ error: 'Already registered for this event' });
      }

      // Check event capacity
      const event = await Event.findOne({ eventId });
      const registrationCount = await EventRegistration.countDocuments({
        eventId,
        isActive: true
      });
      if (registrationCount >= event.capacity) {
        return reply.code(400).send({ error: 'Event is full' });
      }

      // Create registration
      const registration = new EventRegistration({
        userId,
        eventId,
        isActive: true
      });
      await registration.save();

      reply.send({ message: 'Event registration successful' });
    } catch (error) {
      reply.code(500).send({ error: 'Internal server error' });
    }
  });

  // Get events
  fastify.get('/events', async (request, reply) => {
    try {
      const events = await Event.find({ isActive: true })
        .sort({ eventDate: 1 });
      reply.send(events);
    } catch (error) {
      reply.code(500).send({ error: 'Internal server error' });
    }
  });
};

// Admin Routes
const adminRoutes = async (fastify) => {
  // Existing login route
  fastify.post('/login', async (request, reply) => {
    try {
      const { username, password } = request.body;

      const admin = await Admin.findOne({ username });
      if (!admin) {
        return reply.code(401).send({ error: 'Invalid credentials' });
      }

      const isValidPassword = await bcrypt.compare(password, admin.password);
      if (!isValidPassword) {
        return reply.code(401).send({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { adminId: admin.adminId, role: admin.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
      );

      reply.send({ token });
    } catch (error) {
      reply.code(500).send({ error: 'Internal server error' });
    }
  });

  // Create event endpoint
  fastify.post('/create-event', async (request, reply) => {
    try {
      const { eventName, description, eventDate, capacity } = request.body;
      // const { adminId } = request.user;

      const eventDateTime = new Date(eventDate);
      if (eventDateTime < new Date()) {
        return reply.code(400).send({ error: 'Event date cannot be in the past' });
      }

      if (capacity <= 0) {
        return reply.code(400).send({ error: 'Capacity must be greater than 0' });
      }

      const event = new Event({
        eventName,
        description,
        eventDate: eventDateTime,
        capacity
      });

      await event.save();

      reply.code(201).send({
        message: 'Event created successfully',
        event: {
          eventId: event.eventId,
          eventName: event.eventName,
          description: event.description,
          eventDate: event.eventDate,
          capacity: event.capacity,
          isActive: event.isActive
        }
      });
    } catch (error) {

      console.error('Error creating event:', error);

      if (error.name === 'ValidationError') {
        return reply.code(400).send({ error: error.message });
      }
      reply.code(500).send({ error: 'Internal server error' });
    }
  });

  fastify.delete('/events/:eventId', async (request, reply) => {
    try {
      const { eventId } = request.params;
      const { adminId } = request.user;

      const event = await Event.findOne({ eventId });
      if (!event) {
        return reply.code(404).send({ error: 'Event not found' });
      }

      const activeRegistrations = await EventRegistration.exists({
        eventId,
        isActive: true
      });

      if (activeRegistrations) {
        event.isActive = false;
        event.deactivatedBy = adminId;
        event.deactivatedAt = new Date();
        await event.save();

        return reply.send({
          message: 'Event deactivated successfully. Active registrations exist.'
        });
      }

      await Event.deleteOne({ eventId });

      reply.send({
        message: 'Event deleted successfully'
      });
    } catch (error) {
      console.error('Error deleting event:', error);
      reply.code(500).send({ error: 'Internal server error' });
    }
  });

  // Get all events endpoint
  fastify.get('/events', async (request, reply) => {
    try {
      const events = await Event.find()
        .select('-__v')
        .lean();

      // Enhance events with registration count
      const enhancedEvents = await Promise.all(events.map(async (event) => {
        const registrationCount = await EventRegistration.countDocuments({
          eventId: event.eventId,
          isActive: true
        });

        return {
          ...event,
          registrationCount,
          availableSpots: event.capacity - registrationCount
        };
      }));

      reply.send(enhancedEvents);
    } catch (error) {
      console.error('Error fetching events:', error);
      reply.code(500).send({ error: 'Internal server error' });
    }
  });

  // Existing users route
  fastify.get('/users', async (request, reply) => {
    try {
      const users = await User.find()
        .select('-password')
        .lean();

      const enhancedUsers = await Promise.all(users.map(async (user) => {
        const payment = await Payment.findOne({ userId: user.userId, status: 'success' });
        const idCard = await IDCard.findOne({ userId: user.userId });
        const registrations = await EventRegistration.find({
          userId: user.userId,
          isActive: true
        });

        return {
          ...user,
          hasPaid: !!payment,
          idCardStatus: idCard ? idCard.isIssued : 'not_created',
          registeredEvents: registrations.length
        };
      }));

      reply.send(enhancedUsers);
    } catch (error) {
      reply.code(500).send({ error: 'Internal server error' });
    }
  });

  // Existing ID cards route
  fastify.patch('/id-cards/:userId', async (request, reply) => {
    try {
      const { userId } = request.params;
      const { isIssued } = request.body;
      const { adminId } = request.user;

      const idCard = await IDCard.findOneAndUpdate(
        { userId },
        {
          isIssued,
          issuedBy: adminId,
          issuedAt: isIssued ? new Date() : null
        },
        { new: true }
      );

      if (!idCard) {
        return reply.code(404).send({ error: 'ID card not found' });
      }

      reply.send({ message: 'ID card status updated', idCard });
    } catch (error) {
      reply.code(500).send({ error: 'Internal server error' });
    }
  });
};
// Middleware
async function authenticateUser(request, reply) {
  try {
    const token = request.headers.authorization?.split(' ')[1];
    if (!token) {
      throw new Error('No token provided');
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    request.user = decoded;
  } catch (error) {
    reply.code(401).send({ error: 'Invalid token' });
  }
}

async function authenticateAdmin(request, reply) {
  try {
    const token = request.headers.authorization?.split(' ')[1];
    if (!token) {
      throw new Error('No token provided');
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.adminId) {
      throw new Error('Admin access required');
    }
    request.user = decoded;
  } catch (error) {
    reply.code(401).send({ error: 'Invalid token' });
  }
}

// Register routes
fastify.register(userRoutes, { prefix: '/api' });
fastify.register(protectedUserRoutes, {
  prefix: '/api',
  preHandler: authenticateUser
});
fastify.register(adminRoutes, {
  prefix: '/api/admin',
  preHandler: authenticateAdmin
});

// Payment callback (public route)
fastify.post('/api/payments/callback', async (request, reply) => {
  try {
    const { paymentId, status, transactionId, gatewayResponse } = request.body;

    const payment = await Payment.findOne({ paymentId });
    if (!payment) {
      return reply.code(404).send({ error: 'Payment not found' });
    }

    payment.status = status;
    payment.transactionId = transactionId;
    payment.gatewayResponse = gatewayResponse;
    payment.paymentDate = new Date();
    await payment.save();

    if (status === 'success') {
      const idCard = new IDCard({
        userId: payment.userId,
        isIssued: false
      });
      await idCard.save();
    }

    reply.send({ message: 'Payment status updated' });
  } catch (error) {
    reply.code(500).send({ error: 'Internal server error' });
  }
});

// Start server
const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 3000 });
    console.log(`Server listening on ${fastify.server.address().port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();