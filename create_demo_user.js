const { db } = require('./firebase');
const bcrypt = require('bcryptjs');

async function createDemoUser() {
    const email = 'admin@example.com';
    const password = 'password123';
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const usersRef = db.collection('users');
        const snapshot = await usersRef.where('email', '==', email).get();

        if (!snapshot.empty) {
            console.log('User already exists');
            process.exit(0);
        }

        await usersRef.add({
            email,
            username: 'Admin User',
            password: hashedPassword,
            role: 'admin',
            created_at: new Date().toISOString()
        });
        console.log('Demo admin user created');
        process.exit(0);
    } catch (error) {
        console.error('Error creating user:', error);
        process.exit(1);
    }
}

createDemoUser();
