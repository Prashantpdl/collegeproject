const crypto = require('crypto');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');
const { Schema } = mongoose;

const userSchema = new Schema({
    name: {
        type: String,
        required: [true, 'Please tell us your name'],
        trim: true,
        maxlength: [100, 'Name must be less or equal to 100 characters'],
        minlength: [2, 'Name must be more or equal to 2 characters']
    },
    email: {
        type: String,
        required: [true, 'Please provide your email'],
        unique: [true, 'Email is already taken'],
        trim: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    role: {
        type: String,
        enum: ["user", "guide", "admin", "system-admin"],
        default: "user"
    },
    password: {
        type: String,
        required: [true, 'Please provide a password'],
        minlength: [8, 'Password must be at least 8 characters'],
        select: false
    },
    passwordConfirm: {
        type: String,
    },
    addedBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
    active: {
        type: Boolean,
        default: true,
        select: false
    },
    number: {
        type: String,
        select: false
    },
    otpExpiresAt: Date,
    verified: {
        type: Boolean,
        default: false
    }
});

// Pre middleware to hash password before saving
userSchema.pre('save', async function(next) {
    // Only run this function if password was actually modified
    if (!this.isModified('password')) return next();

    // Hash password
    this.password = await bcrypt.hash(this.password, 12);

    // Delete passwordConfirm
    this.passwordConfirm = undefined;
    next();
});

// Method to generate OTP and set expiration time
// userSchema.methods.generateOTP = function() {
//     const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generates a 6-digit OTP
//     this.otp = otp;
//     this.otpExpiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes in milliseconds
//     return otp;
// };

const User = mongoose.model('User', userSchema);

module.exports = User;
