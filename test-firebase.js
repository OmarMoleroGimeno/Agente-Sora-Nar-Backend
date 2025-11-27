const admin = require('firebase-admin');
require('dotenv').config();

console.log('Testing Firebase Connection...');
console.log('Creds path:', process.env.GOOGLE_APPLICATION_CREDENTIALS);

try {
    if (!admin.apps.length) {
        admin.initializeApp({
            credential: admin.credential.applicationDefault()
        });
    }

    const db = admin.firestore();

    const testRef = db.collection('test_connection').doc('ping');

    testRef.set({
        message: 'Hello Firebase!',
        timestamp: new Date().toISOString()
    }).then(() => {
        console.log('SUCCESS: Wrote to Firestore collection "test_connection". Check your console!');
    }).catch(err => {
        console.error('ERROR Writing to Firestore:', err);
    });

} catch (error) {
    console.error('INITIALIZATION ERROR:', error);
}
