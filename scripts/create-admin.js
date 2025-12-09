const { db } = require('../firebase');
const bcrypt = require('bcryptjs');

const createAdmin = async () => {
    const args = process.argv.slice(2);
    if (args.length < 2) {
        console.log('Uso: node create-admin.js <email> <password> [username]');
        process.exit(1);
    }

    const email = args[0];
    const password = args[1];
    const username = args[2] || 'SuperAdmin';

    try {
        console.log(`Creating admin user: ${email}...`);
        
        // Check text
        const snapshot = await db.collection('users').where('email', '==', email).get();
        if (!snapshot.empty) {
            console.log('❌ Error: El usuario ya existe.');
            process.exit(1);
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        await db.collection('users').add({
            email,
            password: hashedPassword,
            username,
            role: 'admin',
            avatar_url: '',
            created_at: new Date().toISOString()
        });

        console.log('✅ Admin user created successfully!');
        console.log('Puedes iniciar sesión ahora y crear más usuarios desde el panel.');
        process.exit(0);

    } catch (error) {
        console.error('Error:', error);
        process.exit(1);
    }
};

createAdmin();
