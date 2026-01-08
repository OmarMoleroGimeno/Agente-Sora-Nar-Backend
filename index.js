const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db } = require('./firebase');
const OpenAI = require('openai');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const multer = require('multer');
const ragService = require('./rag');
require('dotenv').config();

// Multer config for memory storage
const upload = multer({ storage: multer.memoryStorage() });

const app = express();
app.use(cors());
app.use(express.json());

// Initialize OpenAI
let openai;
if (process.env.OPENAI_API_KEY) {
    openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
}

// Initialize RAG Service
ragService.init();

app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

app.get('/ping', (req, res) => res.send('pong'));

// Session config for Passport
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Middleware to check admin role
const isAdmin = async (req, res, next) => {
    try {
        const userDoc = await db.collection('users').doc(req.user.id).get();
        if (!userDoc.exists || userDoc.data().role !== 'admin') {
            return res.status(403).send('Admin access required');
        }
        next();
    } catch (e) {
        res.status(500).send('Error checking permissions');
    }
};

// Passport Config
passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

// Passport Config (Only if Google OAuth is configured)
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    const callbackURL = process.env.GOOGLE_CALLBACK || 'http://localhost:3000/api/auth/google/callback';
    console.log('Google OAuth Callback URL:', callbackURL);

    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: callbackURL
    },
        async function (accessToken, refreshToken, profile, cb) {
            try {
                console.log('Google Auth Callback Started');
                const email = profile.emails?.[0]?.value;
                console.log('Google Profile Email:', email);

                if (!email) {
                    console.error('No email found in Google profile');
                    return cb(new Error('No email found in Google profile'));
                }

                const usersRef = db.collection('users');
                // Check if user exists by email (created by admin)
                console.log('Querying Firestore for email:', email);
                const snapshot = await usersRef.where('email', '==', email).get();

                console.log('Firestore Query Result Empty?:', snapshot.empty);

                if (snapshot.empty) {
                    console.warn('User not found in DB for email:', email);
                    // User not found in DB -> Deny Access
                    return cb(null, false, { message: 'Access denied. You must be registered by an admin.' });
                }

                // User exists -> Update google_id and avatar if needed
                const doc = snapshot.docs[0];
                const userData = doc.data();
                console.log('User found in DB:', userData.username);

                if (!userData.google_id || !userData.avatar_url) {
                    console.log('Updating user with Google info...');
                    await doc.ref.update({
                        google_id: profile.id,
                        avatar_url: profile.photos?.[0]?.value
                    });
                }

                const user = { id: doc.id, ...userData, google_id: profile.id };
                return cb(null, user);
            } catch (err) {
                console.error('Google Auth Error:', err);
                return cb(err);
            }
        }
    ));
    console.log('✅ Google OAuth configured');
} else {
    console.log('⚠️  Google OAuth not configured (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET not set)');
}

// Auth Routes (Only if Google OAuth is configured)
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    app.get('/api/auth/google',
        passport.authenticate('google', { scope: ['profile', 'email'] }));

    app.get('/api/auth/google/callback',
        passport.authenticate('google', { failureRedirect: `${FRONTEND_URL}/login?error=access_denied` }),
        (req, res) => {
            if (!req.user) {
                return res.redirect(`${FRONTEND_URL}/login?error=access_denied`);
            }
            const user = req.user;
            const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET);
            const avatar = user.avatar_url || '';
            const role = user.role || 'user';
            const isActive = user.is_active !== false; // Default true if undefined (old users)
            res.redirect(`${FRONTEND_URL}/login?token=${token}&username=${encodeURIComponent(user.username)}&image=${encodeURIComponent(avatar)}&role=${encodeURIComponent(role)}&setup_required=${!isActive}`);
        });
}

// Complete setup for authenticated users (e.g. from Google login)
app.post('/api/auth/complete-setup', authenticateToken, async (req, res) => {
    const { password } = req.body;
    if (!password || password.length < 6) return res.status(400).send('Password must be at least 6 characters');

    try {
        const userRef = db.collection('users').doc(req.user.id);
        const hashedPassword = await bcrypt.hash(password, 10);

        await userRef.update({
            password: hashedPassword,
            setup_token: null,
            is_active: true,
            email_verified: true
        });

        res.send('Account setup completed');
    } catch (e) {
        console.error(e);
        res.status(500).send('Error completing setup');
    }
});

// Login (Only for existing users)
// Login (Only for existing users)
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const usersRef = db.collection('users');
        const snapshot = await usersRef.where('email', '==', email).get();

        if (snapshot.empty) {
            return res.status(400).send('Invalid credentials');
        }

        const doc = snapshot.docs[0];
        const user = doc.data();

        // Check if user is active (has set password)
        if (user.is_active === false) {
             return res.status(403).send('Account not activated. Please check your email.');
        }

        if (!user.password || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).send('Invalid credentials');
        }

        const token = jwt.sign({ id: doc.id, username: user.username, role: user.role }, JWT_SECRET);
        res.json({ token, username: user.username, role: user.role });
    } catch (e) {
        res.status(500).send('Login error');
    }
});

app.post('/api/auth/set-password', async (req, res) => {
    const { token, password } = req.body;
    if (!token || !password || password.length < 6) return res.status(400).send('Invalid request');

    try {
        const usersRef = db.collection('users');
        const snapshot = await usersRef.where('setup_token', '==', token).get();

        if (snapshot.empty) {
            return res.status(400).send('Invalid or expired token');
        }

        const doc = snapshot.docs[0];
        const hashedPassword = await bcrypt.hash(password, 10);

        await doc.ref.update({
            password: hashedPassword,
            setup_token: null, // Clear token
            is_active: true,
            email_verified: true
        });

        res.send('Password set successfully');
    } catch (e) {
        console.error(e);
        res.status(500).send('Error setting password');
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).send('Email required');

    try {
        const usersRef = db.collection('users');
        const snapshot = await usersRef.where('email', '==', email).get();

        if (snapshot.empty) {
            // Security: Don't reveal if user exists. Just return success or simulate delay.
            // But for detailed feedback let's just say "If email exists..."
            // Or return 200 anyway.
            return res.status(200).send('If the email exists, a reset link has been sent.');
        }

        const doc = snapshot.docs[0];
        const user = doc.data();

        // Generate reset token
        const resetToken = require('crypto').randomBytes(32).toString('hex');
        
        // Update user with reset token (valid for e.g. 1 hour - simplified here)
        await doc.ref.update({
             setup_token: resetToken // Reusing setup_token field for simplicity as it behaves same way (one-time use)
        });

        // Send Email
        const resetLink = `${FRONTEND_URL}/set-password?token=${resetToken}`;
        await sendResetPasswordEmail(email, resetLink);

        res.send('Reset link sent');
    } catch (e) {
        console.error(e);
        res.status(500).send('Error requesting password reset');
    }
});

// Admin Routes: User Management
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const snapshot = await db.collection('users').get();
        const users = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        // Don't send passwords
        users.forEach(u => delete u.password);
        res.json(users);
    } catch (e) {
        res.status(500).send('Error fetching users');
    }
});

const { sendWelcomeEmail, sendResetPasswordEmail } = require('./emailService');

// ... (código existente hasta la ruta de crear usuario)

app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
    const { email, username, role } = req.body;
    if (!email || !username) return res.status(400).send('Email and username required');

    try {
        // Check if email already exists
        const usersRef = db.collection('users');
        const snapshot = await usersRef.where('email', '==', email).get();
        if (!snapshot.empty) {
            return res.status(400).send('Email already exists');
        }

        // Generate temporary setup token
        const setupToken = require('crypto').randomBytes(32).toString('hex');
        
        await db.collection('users').add({
            email,
            username,
            role: role || 'user',
            created_at: new Date().toISOString(),
            is_active: false, // User hasn't set password yet
            setup_token: setupToken
        });

        // Send Email
        const setupLink = `${FRONTEND_URL}/set-password?token=${setupToken}`;
        const emailSent = await sendWelcomeEmail(email, setupLink);

        res.status(201).json({ 
            message: 'User created and invitation sent',
            emailSent 
        });
    } catch (e) {
        console.error(e);
        res.status(500).send('Error creating user');
    }
});

app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        await db.collection('users').doc(req.params.id).delete();
        res.send('User deleted');
    } catch (e) {
        res.status(500).send('Error deleting user');
    }
});

// Change user password (Admin only, cannot change other admin passwords)
// Change password route removed entirely to enforce "Forgot Password" flow only.
// app.put('/api/users/:id/password', ... ) - DISABLED

// Document Routes (RAG)
app.post('/api/documents', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded');
        }

        // Sanitize filename to ASCII only for compatibility
        const originalName = req.file.originalname;
        const sanitizedFilename = originalName.replace(/[^\x00-\x7F]/g, "_");

        console.log('DEBUG: Uploading file:', {
            originalname: req.file.originalname,
            size: req.file.size,
            mimetype: req.file.mimetype
        });

        console.log(`Uploading document: ${sanitizedFilename} (Original: ${originalName})`);

        const result = await ragService.processDocument(req.file.buffer, sanitizedFilename, req.user.id);

        await db.collection('documents').add({
            user_id: req.user.id,
            filename: sanitizedFilename, // Store sanitized name
            original_filename: originalName, // Store original name for display if needed
            size: req.file.size,
            chunk_count: result.chunks,
            vectorIds: result.vectorIds || [], // Store vector IDs
            uploaded_at: new Date().toISOString()
        });

        res.json({ message: 'Document processed', chunks: result.chunks });
    } catch (e) {
        console.error('Error processing document:', e);
        res.status(500).send('Error processing document: ' + e.message);
    }
});

app.get('/api/documents', authenticateToken, async (req, res) => {
    try {
        const snapshot = await db.collection('documents')
            .where('user_id', '==', req.user.id)
            .orderBy('uploaded_at', 'desc')
            .get();
        const documents = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json(documents);
    } catch (e) {
        // Handle missing index error
        if (e.code === 9 || e.message.includes('requires an index')) {
            console.warn('⚠️ Firestore index missing for documents. Falling back to client-side sorting.');
            try {
                const snapshot = await db.collection('documents')
                    .where('user_id', '==', req.user.id)
                    .get();
                const documents = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
                // Sort in memory
                documents.sort((a, b) => new Date(b.uploaded_at) - new Date(a.uploaded_at));
                return res.json(documents);
            } catch (retryErr) {
                console.error('Retry failed:', retryErr);
            }
        }

        console.error('Error fetching documents:', e);
        res.status(500).send('Error fetching documents');
    }
});

// Batch Delete Documents
app.post('/api/documents/batch-delete', authenticateToken, async (req, res) => {
    const { ids } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).send('Invalid IDs provided');
    }

    try {
        const batch = db.batch();
        const vectorIdsToDelete = [];
        const validDocIds = [];

        // 1. Fetch all documents to Verify ownership and collect Vector IDs
        const docsSnapshot = await db.collection('documents')
            .where('user_id', '==', req.user.id)
            .where(require('firebase-admin').firestore.FieldPath.documentId(), 'in', ids)
            .get();

        if (docsSnapshot.empty) {
            return res.status(404).send('No documents found');
        }

        docsSnapshot.forEach(doc => {
            const data = doc.data();
            validDocIds.push(doc.id);
            if (data.vectorIds && Array.isArray(data.vectorIds)) {
                vectorIdsToDelete.push(...data.vectorIds);
            }
            batch.delete(doc.ref);
        });

        // 2. Delete from Pinecone (Single Batch Call)
        if (vectorIdsToDelete.length > 0) {
            console.log(`Deleting ${vectorIdsToDelete.length} vectors for batch document deletion...`);
            await ragService.deleteDocument(vectorIdsToDelete);
        }

        // 3. Delete from Firestore
        await batch.commit();

        res.json({ message: 'Documents deleted', count: validDocIds.length });
    } catch (e) {
        console.error('Error batch deleting documents:', e);
        res.status(500).send('Error deleting documents');
    }
});

app.delete('/api/documents/:id', authenticateToken, async (req, res) => {
    try {
        const docRef = db.collection('documents').doc(req.params.id);
        const doc = await docRef.get();

        if (!doc.exists) {
            return res.status(404).send('Document not found');
        }

        const data = doc.data();
        if (data.user_id !== req.user.id) {
            return res.status(403).send('Unauthorized');
        }

        // Delete from Pinecone using vector IDs
        if (data.vectorIds && data.vectorIds.length > 0) {
            await ragService.deleteDocument(data.vectorIds);
        } else if (data.filename) {
            // Fallback for old documents (try deleting by filename if no IDs)
            // Note: This might fail on Starter plan but worth a try for legacy data
            // Actually, ragService.deleteDocument now expects IDs. 
            // We should probably warn or try to fetch IDs if possible, but for now let's just log.
            console.warn('⚠️ No vectorIds found for document. Skipping Pinecone deletion.');
        }

        // Delete from Firestore
        await docRef.delete();

        res.send('Document deleted');
    } catch (e) {
        console.error('Error deleting document:', e);
        res.status(500).send('Error deleting document');
    }
});

app.get('/api/threads', authenticateToken, async (req, res) => {
    try {
        const snapshot = await db.collection('threads')
            .where('user_id', '==', req.user.id)
            .orderBy('created_at', 'desc')
            .get();
        const threads = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json(threads);
    } catch (e) {
        console.error('Error fetching threads:', e);
        // If index is missing, it returns a specific error code (9). 
        // We can temporarily return empty array or unsorted results to avoid 500
        if (e.code === 9 || e.message.includes('requires an index')) {
            console.log('Index missing. Returning unsorted threads temporarily.');
            try {
                const snapshot = await db.collection('threads')
                    .where('user_id', '==', req.user.id)
                    .get();
                const threads = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
                // Sort manually in memory
                threads.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
                return res.json(threads);
            } catch (retryErr) {
                console.error('Retry failed:', retryErr);
            }
        }
        res.status(500).send('Error fetching threads');
    }
});

app.post('/api/threads', authenticateToken, async (req, res) => {
    const id = req.body.id || require('crypto').randomUUID();
    const title = req.body.title || 'New Chat';
    const timestamp = new Date().toISOString();

    try {
        await db.collection('threads').doc(id).set({
            id,
            user_id: req.user.id,
            title,
            created_at: timestamp
        });
        res.json({ id, title, created_at: timestamp });
    } catch (e) {
        res.status(500).send('Error creating thread');
    }
});

app.put('/api/threads/:id', authenticateToken, async (req, res) => {
    const { title } = req.body;
    try {
        const threadRef = db.collection('threads').doc(req.params.id);
        const doc = await threadRef.get();
        if (!doc.exists || doc.data().user_id !== req.user.id) {
            return res.status(404).send('Thread not found');
        }
        await threadRef.update({ title });
        res.json({ id: req.params.id, title });
    } catch (e) {
        res.status(500).send('Error updating thread');
    }
});

app.delete('/api/threads/:id', authenticateToken, async (req, res) => {
    try {
        const threadRef = db.collection('threads').doc(req.params.id);
        const doc = await threadRef.get();
        if (!doc.exists || doc.data().user_id !== req.user.id) {
            return res.status(404).send('Thread not found');
        }
        // Delete thread and its messages
        const batch = db.batch();
        batch.delete(threadRef);
        const messagesSnapshot = await threadRef.collection('messages').get();
        messagesSnapshot.docs.forEach(doc => {
            batch.delete(doc.ref);
        });
        await batch.commit();
        res.send('Thread deleted');
    } catch (e) {
        console.error('Error deleting thread:', e);
        res.status(500).send('Error deleting thread');
    }
});

app.get('/api/threads/:id/messages', authenticateToken, async (req, res) => {
    try {
        const threadDoc = await db.collection('threads').doc(req.params.id).get();
        if (!threadDoc.exists || threadDoc.data().user_id !== req.user.id) {
            return res.status(404).send('Thread not found');
        }

        const snapshot = await db.collection('threads').doc(req.params.id)
            .collection('messages')
            .orderBy('timestamp', 'asc')
            .get();

        const messages = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json(messages);
    } catch (e) {
        res.status(500).send('Error fetching messages');
    }
});

app.post('/api/threads/:id/messages', authenticateToken, async (req, res) => {
    const { content } = req.body;
    const threadId = req.params.id;

    try {
        const threadRef = db.collection('threads').doc(threadId);
        const threadDoc = await threadRef.get();

        if (!threadDoc.exists || threadDoc.data().user_id !== req.user.id) {
            return res.status(404).send('Thread not found');
        }

        // Save user message
        const userMsgTimestamp = new Date().toISOString();
        const userMsg = {
            role: 'user',
            content,
            timestamp: userMsgTimestamp
        };
        await threadRef.collection('messages').add(userMsg);

        // AI Response
        let aiContent = '';
        if (process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY.startsWith('sk-')) {
            try {
                const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
                const historySnapshot = await threadRef.collection('messages').orderBy('timestamp', 'asc').get();
                const history = historySnapshot.docs.map(d => d.data());

                // RAG: Query Context
                let systemPrompt = `You are a helpful assistant helping a user with their uploaded documents.
                                    IMPORTANT: If the user asks a question about specific data, reservations, files, or facts, and you do not see the answer in the context provided below, you MUST say "I cannot find that information in your uploaded documents."
                                    Do NOT make up facts. Do NOT use general knowledge to answer questions about specific entities (like "Reservation 14") if they are not in the context.`;

                try {
                    console.log(`DEBUG: Querying RAG for user ${req.user.id} with content: "${content}"`);
                    const context = await ragService.queryContext(content, req.user.id);
                    console.log('DEBUG: RAG Context result length:', context ? context.length : 0);
                    if (context) {
                        systemPrompt = `You are a precise assistant. Your goal is to answer based ONLY on the provided context.
                                        
                                        Strict Rules:
                                        1. Use ONLY the information in the "Context from uploaded documents" below to answer the question.
                                        2. If the answer is not explicitly in the context, say "I cannot find that information in your documents."
                                        3. Do NOT use your general training data to answer questions about specific "reservations", "files", "people", or "projects".
                                        4. Do not mention that you are an AI or that you are using a context block, just answer the question naturally but strictly based on the text.
                                        
                                        Context from uploaded documents:
                                        ${context}`;
                        console.log('DEBUG: RAG Context injected into system prompt');
                    } else {
                        console.log('DEBUG: No relevant context found');
                    }
                } catch (ragError) {
                    console.error('DEBUG: RAG Error:', ragError);
                }

                const messages = [
                    { role: 'system', content: systemPrompt },
                    ...history.map(m => ({ role: m.role, content: m.content }))
                ];

                const completion = await openai.chat.completions.create({
                    messages: messages,
                    model: process.env.OPENAI_MODEL,
                });
                aiContent = completion.choices[0].message.content;
            } catch (error) {
                console.error('OpenAI Error:', error);
                aiContent = 'Error connecting to AI service.';
            }
        } else {
            aiContent = `(Mock AI) I received: "${content}".`;
        }

        // Save AI message
        const aiMsgTimestamp = new Date().toISOString();
        const aiMsg = {
            role: 'assistant',
            content: aiContent,
            timestamp: aiMsgTimestamp
        };
        await threadRef.collection('messages').add(aiMsg);

        // Generate Title if it's a new chat
        let newTitle = null;
        if (threadDoc.data().title === 'New Chat' && process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY.startsWith('sk-')) {
            try {
                const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
                const titleCompletion = await openai.chat.completions.create({
                    messages: [
                        { role: 'system', content: 'Generate a very short, concise title (max 5 words) for this chat based on the user message. Do not use quotes.' },
                        { role: 'user', content }
                    ],
                    model: process.env.OPENAI_MODEL,
                });
                newTitle = titleCompletion.choices[0].message.content.trim();
                await threadRef.update({ title: newTitle });
            } catch (error) {
                console.error('Error generating title:', error);
            }
        }

        res.json({
            userMessage: { role: 'user', content, timestamp: userMsgTimestamp },
            aiMessage: { role: 'assistant', content: aiContent, timestamp: aiMsgTimestamp },
            newTitle // Return the new title if generated
        });
    } catch (e) {
        console.error(e);
        res.status(500).send('Error sending message');
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
