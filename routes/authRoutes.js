// routes/auth.js
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const OTPVerification = require('../models/Otp');
const config = require('../config/config');
const { sendOtpMail, sendloginMail } = require('../utils/mailer');
const rateLimiters = require('../middleware/rateLimiter');

async function authRoutes(fastify) {
    // Register user - limit to prevent spam account creation
    fastify.route({
        method: 'POST',
        url: '/register',
        preHandler: rateLimiters.registration,
        handler: async (request, reply) => {
            try {
                const { name, email, phoneno, password } = request.body;

                // Check if user exists
                const existingUser = await User.findOne({ email });
                if (existingUser) {
                    return reply.code(400).send({ error: 'Email already registered' });
                }

                // Hash password
                const hashedPassword = await bcrypt.hash(password, config.BCRYPT_SALT_ROUNDS);

                // Create user
                const user = new User({
                    name,
                    email,
                    phoneNumber: phoneno,
                    password: hashedPassword,
                    role: 'user'
                });

                await user.save();

                // Generate OTP
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                const otpVerification = new OTPVerification({
                    userId: user.userId,
                    otp,
                    expiresAt: new Date(Date.now() + config.OTP_EXPIRY_MINUTES * 60000)
                });

                await otpVerification.save();
                await sendOtpMail(user.email, otp, user.name);

                reply.code(201).send({
                    message: 'Registration successful. Please verify your email.',
                    userId: user.userId
                });
            } catch (error) {
                console.error("Registration error:", error);
                reply.code(500).send({ error: 'Internal server error' });
            }
        }
    });

    // Verify email - limit to prevent OTP brute force
    fastify.route({
        method: 'POST',
        url: '/verify-email',
        preHandler: rateLimiters.otpVerification,
        handler: async (request, reply) => {
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
                console.error("Email verification error:", error);
                reply.code(500).send({ error: 'Internal server error' });
            }
        }
    });

    // Login - strict rate limiting to prevent brute force
    fastify.route({
        method: 'POST',
        url: '/login',
        preHandler: rateLimiters.loginStrict,
        handler: async (request, reply) => {
            try {
                const { email, password } = request.body;

                const user = await User.findOne({ email });
                if (!user) {
                    return reply.code(401).send({ error: 'Invalid credentials' });
                }

                const isValidPassword = await bcrypt.compare(password, user.password);
                if (!isValidPassword) {
                    // Log failed login attempt
                    request.log.info({
                        action: 'failed_login',
                        email,
                        ip: request.ip,
                        userAgent: request.headers['user-agent']
                    });
                    return reply.code(401).send({ error: 'Invalid credentials' });
                }

                if (user.role === 'user' && !user.isEmailVerified) {
                    return reply.code(403).send({ error: 'Please verify your email first' });
                }

                const token = jwt.sign(
                    { 
                        userId: user.userId,
                        role: user.role
                    },
                    config.JWT_SECRET,
                    { expiresIn: config.JWT_EXPIRES_IN }
                );

                // Send login alert for user role
                if (user.role === 'user') {
                    await sendloginMail(user.email, user.name);
                }

                // Log successful login
                request.log.info({
                    action: 'successful_login',
                    userId: user.userId,
                    role: user.role,
                    ip: request.ip
                });

                // Prepare response based on role
                const response = {
                    token,
                    user: {
                        userId: user.userId,
                        name: user.name,
                        email: user.email,
                        role: user.role
                    }
                };

                // Add role-specific data
                if (user.role === 'user') {
                    response.user.hasValidPayment = user.hasValidPayment;
                    response.user.currentEvent = user.currentEvent;
                }

                reply.send(response);
            } catch (error) {
                console.error("Login error:", error);
                reply.code(500).send({ error: 'Internal server error' });
            }
        }
    });

    // Resend OTP - limit to prevent abuse
    fastify.route({
        method: 'POST',
        url: '/resend-otp',
        preHandler: rateLimiters.otpVerification,
        handler: async (request, reply) => {
            try {
                const { userId } = request.body;

                const user = await User.findOne({ userId });
                if (!user) {
                    return reply.code(404).send({ error: 'User not found' });
                }

                if (user.isEmailVerified) {
                    return reply.code(400).send({ error: 'Email already verified' });
                }

                // Generate new OTP
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                const otpVerification = new OTPVerification({
                    userId: user.userId,
                    otp,
                    expiresAt: new Date(Date.now() + config.OTP_EXPIRY_MINUTES * 60000)
                });

                await otpVerification.save();
                await sendOtpMail(user.email, otp, user.name);

                reply.send({ message: 'New OTP sent successfully' });
            } catch (error) {
                console.error("Resend OTP error:", error);
                reply.code(500).send({ error: 'Internal server error' });
            }
        }
    });

    // Forgot Password - limit to prevent account enumeration abuse
    fastify.route({
        method: 'POST',
        url: '/forgot-password',
        preHandler: rateLimiters.accountRecovery,
        handler: async (request, reply) => {
            try {
                const { email } = request.body;

                const user = await User.findOne({ email });
                if (!user) {
                    // Return same response to prevent user enumeration
                    // But add delay to prevent timing attacks
                    await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 500));
                    return reply.send({ 
                        message: 'If your email is registered, you will receive a password reset OTP'
                    });
                }

                // Generate OTP for password reset
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                const otpVerification = new OTPVerification({
                    userId: user.userId,
                    otp,
                    expiresAt: new Date(Date.now() + config.OTP_EXPIRY_MINUTES * 60000)
                });

                await otpVerification.save();
                await sendOtpMail(user.email, otp, user.name);

                // Log password reset request
                request.log.info({
                    action: 'password_reset_requested',
                    userId: user.userId,
                    ip: request.ip
                });

                reply.send({ 
                    message: 'If your email is registered, you will receive a password reset OTP',
                    userId: user.userId
                });
            } catch (error) {
                console.error("Forgot password error:", error);
                reply.code(500).send({ error: 'Internal server error' });
            }
        }
    });

    // Reset Password - limit to prevent brute force
    fastify.route({
        method: 'POST',
        url: '/reset-password',
        preHandler: rateLimiters.otpVerification,
        handler: async (request, reply) => {
            try {
                const { userId, otp, newPassword } = request.body;

                const verification = await OTPVerification.findOne({
                    userId,
                    otp,
                    isVerified: false,
                    expiresAt: { $gt: new Date() }
                });

                if (!verification) {
                    return reply.code(400).send({ error: 'Invalid or expired OTP' });
                }

                // Hash new password
                const hashedPassword = await bcrypt.hash(newPassword, config.BCRYPT_SALT_ROUNDS);

                // Update password
                await User.findOneAndUpdate(
                    { userId },
                    { password: hashedPassword }
                );

                // Mark OTP as verified
                verification.isVerified = true;
                await verification.save();

                // Log successful password reset
                request.log.info({
                    action: 'password_reset_completed',
                    userId,
                    ip: request.ip
                });

                reply.send({ message: 'Password reset successful' });
            } catch (error) {
                console.error("Reset password error:", error);
                reply.code(500).send({ error: 'Internal server error' });
            }
        }
    });
}

module.exports = authRoutes;