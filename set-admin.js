const { db } = require('./firebase');

async function setAdminRole() {
    try {
        const userId = process.argv[2];

        if (!userId) {
            console.log('❌ Usage: node set-admin.js <user-id>');
            console.log('\n💡 Run "node check-users.js" to see all user IDs\n');
            process.exit(1);
        }

        console.log(`🔧 Setting admin role for user: ${userId}\n`);

        const userRef = db.collection('users').doc(userId);
        const doc = await userRef.get();

        if (!doc.exists) {
            console.log('❌ User not found!\n');
            process.exit(1);
        }

        await userRef.update({ role: 'admin' });

        const updatedDoc = await userRef.get();
        const data = updatedDoc.data();

        console.log('✅ User updated successfully!\n');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('📋 USER DETAILS:');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log(`📧 Email:    ${data.email}`);
        console.log(`👤 Username: ${data.username}`);
        console.log(`🛡️  Role:     ${data.role}`);
        console.log(`🔗 Google:   ${data.google_id ? 'Linked ✓' : 'Not linked'}`);
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
        console.log('⚠️  IMPORTANT: User must log out and log in again to see changes!\n');

        process.exit(0);
    } catch (error) {
        console.error('❌ Error:', error);
        process.exit(1);
    }
}

setAdminRole();
