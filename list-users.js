const { db } = require('./firebase');

async function listUsers() {
    try {
        const snapshot = await db.collection('users').get();

        if (snapshot.empty) {
            console.log('No users found');
            process.exit(0);
        }

        console.log('\n=== USERS ===\n');

        snapshot.forEach(doc => {
            const data = doc.data();
            console.log('ID:', doc.id);
            console.log('Email:', data.email);
            console.log('Username:', data.username);
            console.log('Role:', data.role || 'NOT SET');
            console.log('Google ID:', data.google_id || 'None');
            console.log('---');
        });

        process.exit(0);
    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

listUsers();
