const mongoose = require('mongoose');
const { Schema } = mongoose;

const otp_link_verify = new Schema({
    Id: {
        type: String,
        required: true,
        unique: true
    },
    Email:{
        type:String,
        required: true,
    },
    expiresAt:{
        type: Date,
        required: true
    }
});



module.exports = mongoose.model('Otp-verify', otp_link_verify);
