const nodemailer = require('nodemailer');
const { readFileSync } = require('fs');
const { resolve } = require('path');
const { compile } = require('handlebars');
const config = require('../config/index.js');

const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_SENDER_NAME } = config;

const transporter = nodemailer.createTransport({

    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: true,
    auth: {
        user: SMTP_USER,
        pass: SMTP_PASS,
    },
});

const sendMail = async (to, subject, template, data) => {

    try {

        const html = compile(
            readFileSync(resolve(__dirname, `../template/${template}.hbs`), 'utf8')
        )(data);

        await transporter.sendMail({
            from: `${SMTP_SENDER_NAME} <${SMTP_USER}>`,
            to,
            subject,
            html,
        });


    } catch (error) {

        console.error(`Attempt failed to send email to ${to}: ${error.message}`);

    }
};

const sendOtpMail = async (to, otp, userName) => {
    try {
        await sendMail(to, 'OTP for your account', 'otp', { 
            otp, 
            userName: userName 
        });
    } catch (error) {
        console.error(`Failed to send OTP email to ${to}: ${error.message}`);
        throw error;
    }
};

const sendloginMail = async (to, userName) => {
    try {
        
        await sendMail(to, 'Login Alert!!', 'login', {
            userName: userName,
            loginTime: new Date().toLocaleString(),
        });
    } catch (error) {
        console.error(`Failed to send login alert email to ${to}: ${error.message}`);
        throw error;
    }
};

module.exports = {
    sendOtpMail,
    sendloginMail
};
