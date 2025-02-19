    // services/razorpayService.js
const Razorpay = require('razorpay');
const crypto = require('crypto');
const config = require('../config/config');

// Initialize Razorpay with your key credentials
const razorpayInstance = new Razorpay({
  key_id: config.RAZORPAY_KEY_ID,
  key_secret: config.RAZORPAY_KEY_SECRET
});

/**
 * Creates a Razorpay order
 * @param {Object} orderData - Order data including amount, currency, receipt, etc.
 * @returns {Promise<Object>} - Razorpay order object
 */
const createOrder = async (orderData) => {
  try {
    const options = {
      amount: orderData.amount * 100, // amount in paisa (Razorpay uses smallest currency unit)
      currency: 'INR',
      receipt: orderData.receipt,
      notes: {
        userId: orderData.userId,
        purpose: 'Event Registration'
      }
    };

    return await razorpayInstance.orders.create(options);
  } catch (error) {
    console.error('Razorpay order creation error:', error);
    throw new Error('Failed to create payment order');
  }
};

/**
 * Verify Razorpay payment signature
 * @param {Object} paymentData - Payment verification data
 * @returns {Boolean} - Whether signature is valid
 */
const verifyPaymentSignature = (paymentData) => {
  try {
    // Signature verification
    const expectedSignature = crypto.createHmac('sha256', config.RAZORPAY_WEBHOOK_SECRET)
      .update(`${paymentData.orderId}|${paymentData.paymentId}`)
      .digest('hex');
    
    return expectedSignature === paymentData.signature;
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
};

/**
 * Fetch payment details from Razorpay
 * @param {String} paymentId - Razorpay payment ID
 * @returns {Promise<Object>} - Payment details
 */
const fetchPaymentDetails = async (paymentId) => {
  try {
    return await razorpayInstance.payments.fetch(paymentId);
  } catch (error) {
    console.error('Error fetching payment details:', error);
    throw new Error('Failed to fetch payment details');
  }
};

/**
 * Initiate refund for a payment
 * @param {String} paymentId - Razorpay payment ID
 * @param {Number} amount - Amount to refund (in paisa)
 * @returns {Promise<Object>} - Refund details
 */
const initiateRefund = async (paymentId, amount) => {
  try {
    return await razorpayInstance.payments.refund(paymentId, {
      amount,
      speed: 'normal',
      notes: {
        reason: 'Customer requested refund'
      }
    });
  } catch (error) {
    console.error('Refund initiation error:', error);
    throw new Error('Failed to initiate refund');
  }
};

module.exports = {
  createOrder,
  verifyPaymentSignature,
  fetchPaymentDetails,
  initiateRefund
};