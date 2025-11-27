const { db } = require('./firebase');

async function testThreads() {
    try {
        console.log('Testing threads query...');
        // Use a fake user ID or one that exists if known. 
        // If auth worked, we might have a user.
        // But for the query error (Index), the user ID doesn't need to match a real user, just the query structure matters.
        const userId = 'test_user_id';

        const snapshot = await db.collection('threads')
            .where('user_id', '==', userId)
            .orderBy('created_at', 'desc')
            .get();

        console.log('Query successful. Docs found:', snapshot.size);
    } catch (error) {
        console.error('Query Failed!');
        console.error(error);
    }
}

testThreads();
