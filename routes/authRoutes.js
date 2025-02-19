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
    // Register user with optimizations
    fastify.route({
        method: 'POST',
        url: '/register',
        preHandler: rateLimiters.registration,
        handler: async (request, reply) => {
            try {
                const { name, email, phoneno, password } = request.body;

                // Validate inputs
                if (!name || !email || !phoneno || !password) {
                    return reply.code(400).send({ 
                        error: 'Missing required fields',
                        requiredFields: ['name', 'email', 'phoneno', 'password']
                    });
                }

                // Check if user exists - using lean() for faster query
                const existingUser = await User.findOne({
                    $or: [
                        { email },
                        { phoneNumber: phoneno }
                    ]
                }).lean();

                // Provide specific feedback about which field is duplicate
                if (existingUser) {
                    if (existingUser.email === email) {
                        return reply.code(409).send({ 
                            error: 'Email already registered',
                            field: 'email'
                        });
                    } else if (existingUser.phoneNumber === phoneno) {
                        return reply.code(409).send({ 
                            error: 'Phone number already registered',
                            field: 'phoneno'
                        });
                    } else {
                        return reply.code(409).send({ error: 'User already exists' });
                    }
                }

                // Start password hashing (CPU-intensive operation) early
                const hashedPasswordPromise = bcrypt.hash(password, config.BCRYPT_SALT_ROUNDS);

                // Generate OTP in parallel
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                
                // Wait for password hashing to complete
                const hashedPassword = await hashedPasswordPromise;

                // Create user
                const user = new User({
                    name,
                    email,
                    phoneNumber: phoneno,
                    password: hashedPassword,
                    role: 'user'
                });

                // Save user first and get the ID
                await user.save();

                // Create OTP verification record
                const otpVerification = new OTPVerification({
                    userId: user.userId,
                    otp,
                    expiresAt: new Date(Date.now() + config.OTP_EXPIRY_MINUTES * 60000)
                });

                // Send OTP email asynchronously (don't wait for it)
                const emailPromise = sendOtpMail(user.email, otp, user.name)
                    .catch(err => {
                        // Log email failure but don't fail the registration
                        console.error(`Failed to send OTP email to ${user.email}:`, err);
                        request.log.error({
                            action: 'otp_email_failed',
                            userId: user.userId,
                            email: user.email,
                            error: err.message
                        });
                    });

                // Save OTP verification in parallel with email sending
                await otpVerification.save();

                // Log successful registration
                request.log.info({
                    action: 'user_registered',
                    userId: user.userId,
                    email: user.email,
                    ip: request.ip
                });

                // Return response without waiting for email to be sent
                reply.code(201).send({
                    message: 'Registration successful. Please verify your email.',
                    userId: user.userId
                });
                
                // No need to await emailPromise - let it complete in the background
            } catch (error) {
                // Handle duplicate key errors more gracefully
                if (error.code === 11000) {
                    const field = Object.keys(error.keyValue)[0];
                    const value = error.keyValue[field];
                    
                    // Log duplicate registration attempt
                    request.log.warn({
                        action: 'duplicate_registration_attempt',
                        field,
                        value: field === 'email' ? value : '[REDACTED]', // Don't log phone numbers
                        ip: request.ip
                    });
                    
                    return reply.code(409).send({ 
                        error: `This ${field} is already registered`,
                        field
                    });
                }
                
                console.error("Registration error:", error);
                reply.code(500).send({ error: 'Internal server error' });
            }
        }
    });

    fastify.route({
        method: 'POST',
        url: '/verify-email',
        preHandler: rateLimiters.otpVerification,
        handler: async (request, reply) => {
            try {
                const { userId, otp } = request.body;
    
                // Find the most recent valid OTP for this user
                const verification = await OTPVerification.findOne({
                    userId,
                    otp, // Match the exact OTP
                    isVerified: false,
                    expiresAt: { $gt: new Date() }
                }).sort({ createdAt: -1 }); // Get the most recently created OTP
                
                if (!verification) {
                    return reply.code(400).send({ error: 'Invalid or expired OTP' });
                }
    
                // Update verification status
                verification.isVerified = true;
                await verification.save();
    
                // Expire all other OTPs for this user (for cleanup)
                await OTPVerification.updateMany(
                    { 
                        userId,
                        _id: { $ne: verification._id }, // Exclude the one we just verified
                        isVerified: false 
                    },
                    { 
                        $set: { 
                            expiresAt: new Date()  // Expire all other OTPs
                        } 
                    }
                );
    
                // Update user email verification status
                await User.findOneAndUpdate(
                    { userId },
                    { isEmailVerified: true }
                );
    
                // Log verification success
                request.log.info({
                    action: 'email_verified',
                    userId: userId,
                    ip: request.ip
                });
    
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

                // First, invalidate all existing OTPs for this user
                await OTPVerification.updateMany(
                    { 
                        userId,
                        isVerified: false,
                        expiresAt: { $gt: new Date() } 
                    },
                    { 
                        $set: { 
                            expiresAt: new Date() // Expire all existing OTPs
                        } 
                    }
                );

                // Generate new OTP
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                const otpVerification = new OTPVerification({
                    userId: user.userId,
                    otp,
                    expiresAt: new Date(Date.now() + config.OTP_EXPIRY_MINUTES * 60000)
                });

                await otpVerification.save();
                await sendOtpMail(user.email, otp, user.name);

                // Log OTP resend activity
                request.log.info({
                    action: 'otp_resent',
                    userId: user.userId,
                    ip: request.ip
                });

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

                // Find the most recent valid OTP for this user
                const verification = await OTPVerification.findOne({
                    userId,
                    otp,
                    isVerified: false,
                    expiresAt: { $gt: new Date() }
                }).sort({ createdAt: -1 }); // Get the most recently created OTP

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
                
                // Expire all other OTPs for this user
                await OTPVerification.updateMany(
                    { 
                        userId,
                        _id: { $ne: verification._id }, // Exclude the one we just verified
                        isVerified: false 
                    },
                    { 
                        $set: { 
                            expiresAt: new Date()  // Expire all other OTPs
                        } 
                    }
                );

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