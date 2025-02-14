const dotenv = require('dotenv');
dotenv.config();

const config = {
    SMTP_HOST: process.env.SMTP_HOST,
    SMTP_USER: process.env.SMTP_USER,
    SMTP_PASS: process.env.SMTP_PASS,
    SMTP_PORT: parseInt(process.env.SMTP_PORT || '587', 10), // Default to 587 if not provided
    SMTP_SENDER_NAME: process.env.SMTP_SENDER_NAME,
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
};

module.exports = config;