const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
// const { db } = require('./firebase'); // Removed Firebase
const { supabase } = require('./supabase'); // Added Supabase
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
        const { data: user, error } = await supabase
            .from('users')
            .select('role')
            .eq('id', req.user.id)
            .single();
            
        if (error || !user || user.role !== 'admin') {
            return res.status(403).send('Admin access required');
        }
        next();
    } catch (e) {
        console.error('Error checking permissions:', e);
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

                // Query Supabase for email
                console.log('Querying Supabase for email:', email);
                const { data: user, error } = await supabase
                    .from('users')
                    .select('*')
                    .eq('email', email)
                    .single();

                if (error || !user) {
                    console.warn('User not found in DB for email:', email);
                    // User not found in DB -> Deny Access
                    return cb(null, false, { message: 'Access denied. You must be registered by an admin.' });
                }

                console.log('User found in DB:', user.username);

                // Update google_id and avatar if needed
                if (!user.google_id || !user.avatar_url) {
                    console.log('Updating user with Google info...');
                    const updates = {};
                    if (!user.google_id) updates.google_id = profile.id;
                    if (!user.avatar_url) updates.avatar_url = profile.photos?.[0]?.value;
                    
                    await supabase
                        .from('users')
                        .update(updates)
                        .eq('id', user.id);
                        
                    // Update local user object
                    if (updates.google_id) user.google_id = updates.google_id;
                    if (updates.avatar_url) user.avatar_url = updates.avatar_url;
                }

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
        const hashedPassword = await bcrypt.hash(password, 10);

        const { error } = await supabase
            .from('users')
            .update({
                password: hashedPassword,
                setup_token: null,
                is_active: true,
                email_verified: true
            })
            .eq('id', req.user.id);

        if (error) throw error;

        res.send('Account setup completed');
    } catch (e) {
        console.error(e);
        res.status(500).send('Error completing setup');
    }
});

// Login (Only for existing users)
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(400).send('Invalid credentials');
        }

        // Check if user is active (has set password)
        if (user.is_active === false) {
             return res.status(403).send('Account not activated. Please check your email.');
        }

        if (!user.password || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).send('Invalid credentials');
        }

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET);
        res.json({ token, username: user.username, role: user.role });
    } catch (e) {
        console.error('Login error:', e);
        res.status(500).send('Login error');
    }
});

app.post('/api/auth/set-password', async (req, res) => {
    const { token, password } = req.body;
    if (!token || !password || password.length < 6) return res.status(400).send('Invalid request');

    try {
        // Find user by token
        const { data: user, error: fetchError } = await supabase
            .from('users')
            .select('*')
            .eq('setup_token', token)
            .single();

        if (fetchError || !user) {
            return res.status(400).send('Invalid or expired token');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const { error: updateError } = await supabase
            .from('users')
            .update({
                password: hashedPassword,
                setup_token: null, // Clear token
                is_active: true,
                email_verified: true
            })
            .eq('id', user.id);

        if (updateError) throw updateError;

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
         const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            // Security: Don't reveal if user exists
            return res.status(200).send('If the email exists, a reset link has been sent.');
        }

        // Generate reset token
        const resetToken = require('crypto').randomBytes(32).toString('hex');
        
        // Update user with reset token
        await supabase
            .from('users')
            .update({ setup_token: resetToken })
            .eq('id', user.id);

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
        const { data: users, error } = await supabase
            .from('users')
            .select('*');
            
        if (error) throw error;
        
        // Don't send passwords
        const sanitizedUsers = users.map(user => {
            const { password, ...rest } = user;
            return rest;
        });
        res.json(sanitizedUsers);
    } catch (e) {
        console.error('Error fetching users:', e);
        res.status(500).send('Error fetching users');
    }
});

const { sendWelcomeEmail, sendResetPasswordEmail } = require('./emailService');

app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
    const { email, username, role } = req.body;
    if (!email || !username) return res.status(400).send('Email and username required');

    try {
        // Check if email already exists
        const { data: existingUser, error: checkError } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).send('Email already exists');
        }

        // Generate temporary setup token
        const setupToken = require('crypto').randomBytes(32).toString('hex');
        
        const { data: newUser, error: insertError } = await supabase
            .from('users')
            .insert({
                email,
                username,
                role: role || 'user',
                created_at: new Date().toISOString(),
                is_active: false, // User hasn't set password yet
                setup_token: setupToken
            })
            .select();

        if (insertError) throw insertError;

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
        const { error } = await supabase
            .from('users')
            .delete()
            .eq('id', req.params.id);

        if (error) throw error;

        res.send('User deleted');
    } catch (e) {
        console.error('Error deleting user:', e);
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

        console.log(`Uploading document: ${sanitizedFilename} (Original: ${originalName})`);

        const result = await ragService.processDocument(req.file.buffer, sanitizedFilename, req.user.id);

        const { error } = await supabase
            .from('documents')
            .insert({
                user_id: req.user.id,
                filename: sanitizedFilename,
                original_filename: originalName,
                size: req.file.size,
                chunk_count: result.chunks,
                vector_ids: result.vectorIds || [], // Store vector IDs as JSONB
                uploaded_at: new Date().toISOString()
            });

        if (error) throw error;

        res.json({ message: 'Document processed', chunks: result.chunks });
    } catch (e) {
        console.error('Error processing document:', e);
        res.status(500).send('Error processing document: ' + e.message);
    }
});

app.get('/api/documents', authenticateToken, async (req, res) => {
    try {
        const { data: documents, error } = await supabase
            .from('documents')
            .select('*')
            .eq('user_id', req.user.id)
            .order('uploaded_at', { ascending: false });

        if (error) throw error;

        // Map vector_ids back to vectorIds if frontend expects camelCase?
        // Frontend likely doesn't use vectorIds directly, but just lists files.
        // But for consistency let's map keys if needed. Current frontend usage is just list.
        res.json(documents);
    } catch (e) {
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
        // 1. Fetch documents to get Vector IDs
        const { data: docs, error: fetchError } = await supabase
            .from('documents')
            .select('id, vector_ids')
            .eq('user_id', req.user.id)
            .in('id', ids);

        if (fetchError || !docs || docs.length === 0) {
            return res.status(404).send('No documents found');
        }

        const vectorIdsToDelete = [];
        const validDocIds = docs.map(d => d.id);

        docs.forEach(doc => {
            if (doc.vector_ids && Array.isArray(doc.vector_ids)) {
                vectorIdsToDelete.push(...doc.vector_ids);
            }
        });

        // 2. Delete from Pinecone
        if (vectorIdsToDelete.length > 0) {
            await ragService.deleteDocument(vectorIdsToDelete);
        }

        // 3. Delete from Supabase
        const { error: deleteError } = await supabase
            .from('documents')
            .delete()
            .in('id', validDocIds);

        if (deleteError) throw deleteError;

        res.json({ message: 'Documents deleted', count: validDocIds.length });
    } catch (e) {
        console.error('Error batch deleting documents:', e);
        res.status(500).send('Error deleting documents');
    }
});

app.delete('/api/documents/:id', authenticateToken, async (req, res) => {
    try {
        const { data: doc, error: fetchError } = await supabase
            .from('documents')
            .select('*')
            .eq('id', req.params.id)
            .single();

        if (fetchError || !doc) {
            return res.status(404).send('Document not found');
        }

        if (doc.user_id !== req.user.id) {
            return res.status(403).send('Unauthorized');
        }

        // Delete from Pinecone
        if (doc.vector_ids && doc.vector_ids.length > 0) {
            await ragService.deleteDocument(doc.vector_ids);
        }

        // Delete from Supabase
        const { error: deleteError } = await supabase
            .from('documents')
            .delete()
            .eq('id', req.params.id);

        if (deleteError) throw deleteError;

        res.send('Document deleted');
    } catch (e) {
        console.error('Error deleting document:', e);
        res.status(500).send('Error deleting document');
    }
});

app.get('/api/threads', authenticateToken, async (req, res) => {
    try {
        const { data: threads, error } = await supabase
            .from('threads')
            .select('*')
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json(threads);
    } catch (e) {
        console.error('Error fetching threads:', e);
        res.status(500).send('Error fetching threads');
    }
});

app.post('/api/threads', authenticateToken, async (req, res) => {
    const id = req.body.id || require('crypto').randomUUID();
    const title = req.body.title || 'New Chat';
    const timestamp = new Date().toISOString();

    try {
        const { error } = await supabase
            .from('threads')
            .insert({
                id,
                user_id: req.user.id,
                title,
                created_at: timestamp
            });

        if (error) throw error;

        res.json({ id, title, created_at: timestamp });
    } catch (e) {
        console.error('Error creating thread:', e);
        res.status(500).send('Error creating thread');
    }
});

app.put('/api/threads/:id', authenticateToken, async (req, res) => {
    const { title } = req.body;
    try {
        // Verify ownership
        const { data: thread, error: fetchError } = await supabase
            .from('threads')
            .select('user_id')
            .eq('id', req.params.id)
            .single();

        if (fetchError || !thread) return res.status(404).send('Thread not found');
        if (thread.user_id !== req.user.id) return res.status(403).send('Unauthorized');

        const { error: updateError } = await supabase
            .from('threads')
            .update({ title })
            .eq('id', req.params.id);

        if (updateError) throw updateError;

        res.json({ id: req.params.id, title });
    } catch (e) {
        console.error('Error updating thread:', e);
        res.status(500).send('Error updating thread');
    }
});

app.delete('/api/threads/:id', authenticateToken, async (req, res) => {
    try {
        // Verify ownership
        const { data: thread, error: fetchError } = await supabase
            .from('threads')
            .select('user_id')
            .eq('id', req.params.id)
            .single();

        if (fetchError || !thread) return res.status(404).send('Thread not found');
        if (thread.user_id !== req.user.id) return res.status(403).send('Unauthorized');

        // Delete thread (Messages will cascade delete due to Schema)
        const { error: deleteError } = await supabase
            .from('threads')
            .delete()
            .eq('id', req.params.id);

        if (deleteError) throw deleteError;

        res.send('Thread deleted');
    } catch (e) {
        console.error('Error deleting thread:', e);
        res.status(500).send('Error deleting thread');
    }
});

app.get('/api/threads/:id/messages', authenticateToken, async (req, res) => {
    try {
        // Check thread ownership
        const { data: thread, error: fetchError } = await supabase
            .from('threads')
            .select('user_id')
            .eq('id', req.params.id)
            .single();

        if (fetchError || !thread) return res.status(404).send('Thread not found');
        if (thread.user_id !== req.user.id) return res.status(403).send('Unauthorized');

        const { data: messages, error: msgError } = await supabase
            .from('messages')
            .select('*')
            .eq('thread_id', req.params.id)
            .order('timestamp', { ascending: true });

        if (msgError) throw msgError;

        res.json(messages);
    } catch (e) {
        console.error('Error fetching messages:', e);
        res.status(500).send('Error fetching messages');
    }
});

app.post('/api/threads/:id/messages', authenticateToken, async (req, res) => {
    const { content } = req.body;
    const threadId = req.params.id;

    try {
        // Check ownership
        const { data: thread, error: fetchError } = await supabase
            .from('threads')
            .select('user_id, title')
            .eq('id', threadId)
            .single();

        if (fetchError || !thread) return res.status(404).send('Thread not found');
        if (thread.user_id !== req.user.id) return res.status(403).send('Unauthorized');

        // Save user message
        const userMsgTimestamp = new Date().toISOString();
        const { error: userMsgError } = await supabase
            .from('messages')
            .insert({
                thread_id: threadId,
                role: 'user',
                content,
                timestamp: userMsgTimestamp
            });
            
        if (userMsgError) throw userMsgError;

        // AI Response
        let aiContent = '';
        if (process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY.startsWith('sk-')) {
            try {
                const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
                // Fetch History
                const { data: history, error: historyError } = await supabase
                    .from('messages')
                    .select('role, content')
                    .eq('thread_id', threadId)
                    .order('timestamp', { ascending: true });

                // RAG: Query Context
                let systemPrompt = `You are a helpful assistant helping a user with their uploaded documents.
                                    IMPORTANT: If the user asks a question about specific data, reservations, files, or facts, and you do not see the answer in the context provided below, you MUST say "I cannot find that information in your uploaded documents."
                                    Do NOT make up facts. Do NOT use general knowledge to answer questions about specific entities (like "Reservation 14") if they are not in the context.`;

                try {
                    console.log(`DEBUG: Querying RAG for user ${req.user.id} with content: "${content}"`);
                    const context = await ragService.queryContext(content, req.user.id);
                    console.log('DEBUG: RAG Context result length:', context ? context.length : 0);
                    if (context) {
                        systemPrompt = `Eres un asistente experto en maquinaria y herramientas de construcción de la empresa NAR. Tu objetivo es recomendar la mejor herramienta basándote ÚNICAMENTE en el contexto proporcionado.
                                        
                                        INSTRUCCIONES DE FORMATO ESTRICTAS:
                                        Debes responder SIEMPRE siguiendo esta estructura y formato exactos.

                                        [Párrafo introductorio directo y profesional]

                                        ### Opciones Recomendadas

                                        1. **[Nombre de la Herramienta]**
                                        - **Uso:** [Descripción breve]
                                        - **Enganche:** [Tipo]
                                        - **Consumo:** [W]
                                        - **Ideal para:** [Caso de uso específico]

                                        ... (repite para cada opción)

                                        ### Factores a Considerar
                                        - **[Factor Clave]:** [Comparativa breve]

                                        SI TIENES CLARO CUÁL ES LA MEJOR OPCIÓN:
                                        ### Conclusión
                                        [Recomendación definitiva]

                                        SI DEPENDE DE DATOS QUE NO TIENES (ej. tipo de pared, grosor):
                                        ### Recomendación
                                        [Explica los casos: "Si es hormigón usa X, si es yeso usa Y"]

                                        ### Preguntas Clave
                                        [Pregunta lo que falta: "¿Qué tipo de pared es?", "¿Qué diámetro necesitas?"]

                                        REGLAS:
                                        - Usa "1. **Nombre**" para títulos.
                                        - Usa "- **Clave:**" para características.
                                        - Solo pon "Conclusión" si es una respuesta definitiva. Si no, usa "Recomendación" condicional y pregunta.
                                        - Mantén el idioma Español.
                                        - Cíñete al contexto.

                                        Contexto de documentos subidos:
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
        const { error: aiMsgError } = await supabase
            .from('messages')
            .insert({
                thread_id: threadId,
                role: 'assistant',
                content: aiContent,
                timestamp: aiMsgTimestamp
            });

        if (aiMsgError) throw aiMsgError;

        // Generate Title if it's a new chat
        let newTitle = null;
        if (thread.title === 'New Chat' && process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY.startsWith('sk-')) {
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
                await supabase
                    .from('threads')
                    .update({ title: newTitle })
                    .eq('id', threadId);
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
