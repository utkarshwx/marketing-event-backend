const crypto = require('crypto');
require('dotenv').config();

// Generate a random JWT secret
const generateJWTSecret = () => {
    return crypto.randomBytes(64).toString('hex');
};

// Store the generated JWT secret
let JWT_SECRET = null;

const config = {
    // Server Configuration
    PORT: parseInt(process.env.PORT || '3000', 10),
    NODE_ENV: process.env.NODE_ENV || 'development',
    
    // MongoDB Configuration
    MONGODB_URI: process.env.MONGODB_URI,

    // JWT Configuration
    get JWT_SECRET() {
        if (!JWT_SECRET) {
            JWT_SECRET = generateJWTSecret();
            console.log('New JWT secret generated');
        }
        return JWT_SECRET;
    },
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '24h',
    
    // SMTP Configuration
    SMTP_HOST: process.env.SMTP_HOST,
    SMTP_PORT: parseInt(process.env.SMTP_PORT || '465', 10),
    SMTP_USER: process.env.SMTP_USER,
    SMTP_PASS: process.env.SMTP_PASS,
    SMTP_SENDER_NAME: process.env.SMTP_SENDER_NAME,
    
    // QR Code Configuration
    QR_CODE_PREFIX: process.env.QR_CODE_PREFIX || 'QR',
    QR_CODE_EXPIRY_HOURS: parseInt(process.env.QR_CODE_EXPIRY_HOURS || '24', 10),
    
    // OTP Configuration
    OTP_EXPIRY_MINUTES: parseInt(process.env.OTP_EXPIRY_MINUTES || '15', 10),
    OTP_LENGTH: parseInt(process.env.OTP_LENGTH || '6', 10),
    
    // Payment Gateway Configuration (Changed from BillDesk to Razorpay)
    RAZORPAY_KEY_ID: process.env.RAZORPAY_KEY_ID,
    RAZORPAY_KEY_SECRET: process.env.RAZORPAY_KEY_SECRET,
    RAZORPAY_WEBHOOK_SECRET: process.env.RAZORPAY_WEBHOOK_SECRET,
    RAZORPAY_CALLBACK_URL: process.env.RAZORPAY_CALLBACK_URL,

    // Event Configuration
    MAX_EVENT_CAPACITY: parseInt(process.env.MAX_EVENT_CAPACITY || '1000', 10),
    MIN_EVENT_CAPACITY: parseInt(process.env.MIN_EVENT_CAPACITY || '1', 10),
    
    // Security Configuration
    BCRYPT_SALT_ROUNDS: parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10),
    RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
    RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
    
    // Admin Configuration
    ADMIN_DEFAULT_USERNAME: process.env.ADMIN_DEFAULT_USERNAME || 'admin',
    ADMIN_DEFAULT_PASSWORD: process.env.ADMIN_DEFAULT_PASSWORD,

    // Moderator Configuration
    MAX_DAILY_SCANS: parseInt(process.env.MAX_DAILY_SCANS || '500', 10),
    DEVICE_TOKEN_EXPIRY_DAYS: parseInt(process.env.DEVICE_TOKEN_EXPIRY_DAYS || '30', 10),

    // Helper Methods
    isProduction() {
        return this.NODE_ENV === 'production';
    },

    isDevelopment() {
        return this.NODE_ENV === 'development';
    }
};

// Validate required configuration in production
if (config.isProduction()) {
    const requiredFields = [
        { key: 'MONGODB_URI', message: 'MongoDB URI is required' },
        { key: 'SMTP_HOST', message: 'SMTP host is required' },
        { key: 'SMTP_USER', message: 'SMTP user is required' },
        { key: 'SMTP_PASS', message: 'SMTP password is required' },
        { key: 'SMTP_SENDER_NAME', message: 'SMTP sender name is required' },
        { key: 'RAZORPAY_KEY_ID', message: 'Razorpay key ID is required' },
        { key: 'RAZORPAY_KEY_SECRET', message: 'Razorpay key secret is required' },
        { key: 'RAZORPAY_WEBHOOK_SECRET', message: 'Razorpay webhook secret is required' },
        { key: 'RAZORPAY_CALLBACK_URL', message: 'Razorpay callback URL is required' },
        { key: 'ADMIN_DEFAULT_PASSWORD', message: 'Admin default password is required' }
    ];

    for (const field of requiredFields) {
        if (!config[field.key]) {
            throw new Error(`Production Error: ${field.message}`);
        }
    }
}

// Validate port number
if (isNaN(config.PORT) || config.PORT <= 0 || config.PORT > 65535) {
    throw new Error('Invalid port number specified');
}

// Validate SMTP configuration
if (config.SMTP_PORT && (isNaN(config.SMTP_PORT) || config.SMTP_PORT <= 0 || config.SMTP_PORT > 65535)) {
    throw new Error('Invalid SMTP port number specified');
}

// Validate rate limiting configuration
if (config.RATE_LIMIT_WINDOW_MS <= 0 || config.RATE_LIMIT_MAX_REQUESTS <= 0) {
    throw new Error('Invalid rate limiting configuration');
}

// Validate event capacity configuration
if (config.MAX_EVENT_CAPACITY < config.MIN_EVENT_CAPACITY) {
    throw new Error('Maximum event capacity cannot be less than minimum capacity');
}

module.exports = config;