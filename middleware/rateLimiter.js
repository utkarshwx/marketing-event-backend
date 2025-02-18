// middleware/rateLimiter.js
const config = require('../config/config');

/**
 * Creates a rate limiter with configurable limits and window
 * @param {number} limit - Maximum requests allowed in time window
 * @param {number} windowMs - Time window in milliseconds
 * @param {string} [keyGenerator] - Function to generate unique key (default: IP)
 * @returns {Function} Rate limiting middleware
 */
const createRateLimiter = (limit, windowMs, keyGenerator = req => req.ip) => {
    const requests = new Map();
    
    return async (request, reply) => {
        const key = keyGenerator(request);
        const now = Date.now();
        
        if (requests.has(key)) {
            const data = requests.get(key);
            
            // Clean old requests outside window
            data.timestamps = data.timestamps.filter(time => now - time < windowMs);
            
            if (data.timestamps.length >= limit) {
                // Log excessive requests
                request.log.warn({
                    action: 'rate_limit_exceeded',
                    ip: request.ip,
                    endpoint: request.url,
                    method: request.method,
                    count: data.timestamps.length
                });
                
                reply.code(429).send({ 
                    error: 'Too many requests',
                    retryAfter: Math.ceil((data.timestamps[0] + windowMs - now) / 1000)
                });
                return;
            }
            
            data.timestamps.push(now);
        } else {
            requests.set(key, { timestamps: [now] });
        }
        
        // Clean up old entries periodically
        if (Math.random() < 0.01) { // 1% chance to clean on each request
            for (const [key, data] of requests.entries()) {
                if (now - Math.max(...data.timestamps) > windowMs) {
                    requests.delete(key);
                }
            }
        }
    };
};

// Predefined rate limiters for different scenarios
const rateLimiters = {
    // Login attempts - strict limits to prevent brute force
    login: createRateLimiter(5, 5 * 60 * 1000), // 5 attempts per 5 minutes per IP
    
    // Login with additional fingerprinting for better security
    loginStrict: createRateLimiter(5, 5 * 60 * 1000, 
        req => `${req.ip}-${req.headers['user-agent'] || 'unknown'}`),
    
    // Account recovery operations 
    accountRecovery: createRateLimiter(3, 15 * 60 * 1000), // 3 attempts per 15 minutes
    
    // OTP verification attempts
    otpVerification: createRateLimiter(5, 10 * 60 * 1000), // 5 attempts per 10 minutes
    
    // New account registrations
    registration: createRateLimiter(3, 60 * 60 * 1000), // 3 new accounts per hour per IP
    
    // QR code scan attempts by moderators
    qrScan: createRateLimiter(60, 60 * 60 * 1000), // 60 scans per hour
    
    // Admin operations
    adminOperations: createRateLimiter(30, 60 * 60 * 1000), // 30 operations per hour
    
    // Global limiter for all API requests
    global: createRateLimiter(
        config.RATE_LIMIT_MAX_REQUESTS || 100,
        config.RATE_LIMIT_WINDOW_MS || 900000
    ),
    
    // Create a custom rate limiter with config
    custom: (limit, windowMs, keyGen) => createRateLimiter(limit, windowMs, keyGen)
};

module.exports = rateLimiters;