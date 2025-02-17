const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./models/User');
const Admin = require('./models/Admin');
const config = require('./config');

async function createAdmin() {
    try {
        // Connect to MongoDB
        await mongoose.connect(config.MONGODB_URI);
        console.log('Connected to MongoDB');

        // Check if admin already exists
        const existingAdmin = await User.findOne({ role: 'admin' });
        if (existingAdmin) {
            console.log('Admin account already exists');
            process.exit(0);
        }

        // Create admin user
        const hashedPassword = await bcrypt.hash(config.ADMIN_DEFAULT_PASSWORD, config.BCRYPT_SALT_ROUNDS);
        
        const adminUser = new User({
            name: 'Admin',
            email: 'admin@kiit.ac.in',
            phoneNumber: '1234567890',
            password: hashedPassword,
            role: 'admin',
            isEmailVerified: true
        });

        await adminUser.save();

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

        console.log('Admin account created successfully');
        console.log('Email:', adminUser.email);
        console.log('Password:', config.ADMIN_DEFAULT_PASSWORD);

    } catch (error) {
        console.error('Error creating admin:', error);
    } finally {
        await mongoose.connection.close();
        process.exit(0);
    }
}

createAdmin();