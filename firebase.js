const admin = require('firebase-admin');
require('dotenv').config();

let db;

if (!admin.apps.length) {
    try {
        // Check if GOOGLE_APPLICATION_CREDENTIALS is set or if we are in an environment with default credentials
        if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
            admin.initializeApp({
                credential: admin.credential.applicationDefault()
            });
            console.log('Firebase Admin Initialized with Application Default Credentials');
        } else {
            // Fallback for development without credentials - this will likely fail on DB operations
            // but prevents immediate crash if we just want to start the server to show UI
            console.warn('WARNING: GOOGLE_APPLICATION_CREDENTIALS not set. Firebase operations will fail.');
            // We can try to initialize with no arguments (works in some GCP environments)
            // or just not initialize and let db be undefined/mock
            admin.initializeApp();
        }
    } catch (error) {
        console.error('Firebase Admin Initialization Error:', error);
    }
}

try {
    db = admin.firestore();
} catch (e) {
    console.error('Failed to initialize Firestore:', e.message);
    // Mock DB to prevent server crash on startup, but requests will fail
    db = {
        collection: () => ({
            where: () => ({ get: async () => ({ empty: true, docs: [] }) }),
            doc: () => ({ get: async () => ({ exists: false }), set: async () => { }, delete: async () => { } }),
            get: async () => ({ docs: [] }),
            add: async () => ({ id: 'mock_id' })
        })
    };
}

module.exports = { db, admin };
