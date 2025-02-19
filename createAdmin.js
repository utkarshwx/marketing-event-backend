const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./models/User');
const Admin = require('./models/Admin');
const config = require('./config/config');
const crypto = require('crypto');

/**
 * Generates a random phone number for admin accounts
 * Format: 9XXXXXXXXX (10 digits starting with 9)
 */
function generateUniquePhoneNumber() {
    return '9' + crypto.randomBytes(5).toString('hex').substring(0, 9);
}

/**
 * Checks if a phone number already exists in the database
 */
async function isPhoneNumberTaken(phoneNumber) {
    const existingUser = await User.findOne({ phoneNumber });
    return !!existingUser;
}

async function createAdmin() {
    let connection = null;
    
    try {
        // Connect to MongoDB
        connection = await mongoose.connect(config.MONGODB_URI);
        console.log('Connected to MongoDB');

        // Check if admin already exists
        const existingAdmin = await User.findOne({ role: 'admin' });
        if (existingAdmin) {
            console.log('Admin account already exists:');
            console.log('Email:', existingAdmin.email);
            console.log('UserId:', existingAdmin.userId);
            process.exit(0);
        }

        // Generate unique phone number
        let phoneNumber = '1234567890'; // Default value
        let isUnique = !(await isPhoneNumberTaken(phoneNumber));
        
        // If default number is taken, generate a unique one
        if (!isUnique) {
            console.log('Default phone number is already taken, generating a unique one...');
            let attempts = 0;
            const maxAttempts = 5;
            
            while (!isUnique && attempts < maxAttempts) {
                phoneNumber = generateUniquePhoneNumber();
                isUnique = !(await isPhoneNumberTaken(phoneNumber));
                attempts++;
            }
            
            if (!isUnique) {
                throw new Error(`Failed to generate a unique phone number after ${maxAttempts} attempts`);
            }
        }

        // Create admin user
        const hashedPassword = await bcrypt.hash(config.ADMIN_DEFAULT_PASSWORD, config.BCRYPT_SALT_ROUNDS);
        
        const adminUser = new User({
            name: 'Admin',
            email: 'admin@kiit.ac.in',
            phoneNumber: phoneNumber,
            password: hashedPassword,
            role: 'admin',
            isEmailVerified: true
        });

        await adminUser.save();
        console.log('Admin user created successfully');

        // Create admin profile
        const admin = new Admin({
            userId: adminUser.userId,
            permissions: {
                canCreateEvents: true,
                canDeleteEvents: true,
                canModifyUsers: true,
                canGenerateReports: true,
                canManageModerators: true
            },
            dashboardPreferences: {
                defaultView: 'events',
                eventsPerPage: 10,
                usersPerPage: 20
            }
        });

        await admin.save();
        console.log('Admin profile created successfully');

        console.log('Admin account created successfully');
        console.log('Email:', adminUser.email);
        console.log('Phone:', adminUser.phoneNumber);
        console.log('UserId:', adminUser.userId);
        console.log('Password:', config.ADMIN_DEFAULT_PASSWORD);

    } catch (error) {
        console.error('Error creating admin:', error);
        
        // Handle duplicate key errors more gracefully
        if (error.code === 11000) {
            const field = Object.keys(error.keyValue)[0];
            console.error(`Duplicate ${field} detected: ${error.keyValue[field]}`);
            console.error('Please try again or use a different value.');
        }
        
    } finally {
        if (connection) {
            await mongoose.connection.close();
            console.log('MongoDB connection closed');
        }
        process.exit(0);
    }
}

createAdmin();