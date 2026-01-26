const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { supabase, supabaseAdmin } = require('./supabase');
const OpenAI = require('openai');
const multer = require('multer');
const ragService = require('./rag');
require('dotenv').config();

// Multer config for memory storage
const upload = multer({ storage: multer.memoryStorage() });

const app = express();
const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

console.log('Configuring CORS for origin:', FRONTEND_URL);

app.use(cors({
    origin: FRONTEND_URL,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.static('public'));

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

// Middleware to authenticate token using Supabase Auth
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    try {
        // 1. Verify token with Supabase
        const { data: { user }, error } = await supabase.auth.getUser(token);
        
        if (error || !user) {
            console.error('Supabase Auth verification failed:', error?.message);
            return res.sendStatus(403);
        }

        // 2. Fetch user from our public.users table to get Role
        // Use supabaseAdmin to bypass RLS
        const { data: dbUser, error: dbError } = await supabaseAdmin
            .from('users')
            .select('*')
            .eq('email', user.email)
            .single();
        
        if (dbError || !dbUser) {
             console.warn(`User ${user.email} authenticated via Google but not found in public.users.`);
             return res.status(403).send('User not registered in system.');
        }

        req.user = dbUser; // Attach our DB user (with role)
        console.log('DEBUG: Auth Success, attached user:', req.user?.email, req.user?.id);
        next();
    } catch (err) {
        console.error('Auth Error:', err.message);
        return res.sendStatus(403);
    }
};

// Auth Routes
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const { data, error } = await supabase.auth.signInWithPassword({
            email,
            password,
        });

        if (error) return res.status(401).send(error.message);

        // Fetch user role details
        const { data: dbUser, error: dbError } = await supabaseAdmin
            .from('users')
            .select('*')
            .eq('email', email)
            .single();
        
        if (dbError || !dbUser) {
             return res.status(403).send('User not found in system record.');
        }

        res.json({
            token: data.session.access_token,
            username: dbUser.username,
            role: dbUser.role,
            image: data.user.user_metadata?.avatar_url || ''
        });
    } catch (e) {
        console.error('Login error:', e);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/api/auth/set-password', async (req, res) => {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).send('Token and password required');

    try {
        // 1. Find invite in public.users
        const { data: dbUser, error } = await supabase
            .from('users')
            .select('*')
            .eq('setup_token', token)
            .single();

        if (error || !dbUser) return res.status(404).send('Invalid or expired token');

        if (!supabaseAdmin) {
            return res.status(500).send('Server misconfiguration: Missing Service Role Key');
        }

        // 2. Create Supabase Auth User OR Update existing
        let authUser;
        
        try {
            const { data, error } = await supabaseAdmin.auth.admin.createUser({
                email: dbUser.email,
                password: password,
                email_confirm: true,
                user_metadata: { username: dbUser.username }
            });
            
            if (error) throw error;
            authUser = data.user;
        } catch (err) {
            // If user exists, find them and update password
            if (err.message?.includes('already registered') || err.code === 'email_exists' || err.status === 422) {
                 console.log('User exists, updating password...');
                 // 2a. Find existing user ID
                 // listUsers is the only way to search by email in admin api without getUserById
                 // Alternatively, if we trust the email is unique... 
                 // We can't use getUserByEmail directly in admin-js sometimes, let's use listUsers
                 const { data: { users }, error: searchError } = await supabaseAdmin.auth.admin.listUsers();
                 if (searchError) throw searchError;
                 
                 const existingAuthUser = users.find(u => u.email === dbUser.email);
                 if (!existingAuthUser) throw new Error('User reported existing but not found');
                 
                 // 2b. Update password
                 const { data: updatedUser, error: updateError } = await supabaseAdmin.auth.admin.updateUserById(
                    existingAuthUser.id,
                    { password: password, email_confirm: true }
                 );
                 if (updateError) throw updateError;
                 authUser = updatedUser.user;
            } else {
                throw err;
            }
        }

        // 3. Link public.users
        // Check if the AUTH ID already exists in public.users (Collision check)
        const { data: existingPublicUser } = await supabaseAdmin
            .from('users')
            .select('id')
            .eq('id', authUser.id)
            .single();

        if (existingPublicUser) {
            // User already has a real public record. 
            // Update it with info from invitation and delete the temporary invitation row
             await supabase.from('users').update({
                username: dbUser.username,
                role: dbUser.role,
                is_active: true,
                setup_token: null
             }).eq('id', authUser.id);

             // Delete the invitation/temp row
             await supabase.from('users').delete().eq('id', dbUser.id);
        } else {
            // SWAP IDs: Delete old placeholder row and insert new one with correct ID
            await supabase.from('users').delete().eq('id', dbUser.id);

            const { error: insertError } = await supabase.from('users').insert({
                id: authUser.id,
                email: dbUser.email,
                username: dbUser.username,
                role: dbUser.role,
                created_at: dbUser.created_at,
                is_active: true,
                setup_token: null
            });
            if (insertError) throw insertError;
        }

        res.json({ message: 'Password set successfully' });
    } catch (e) {
        console.error('Set password error:', e);
        res.status(500).send('Error setting password');
    }
});

app.post('/api/auth/complete-setup', authenticateToken, async (req, res) => {
     const { password } = req.body;
     try {
        if (!supabaseAdmin) {
             return res.status(500).send('Server misconfiguration: Missing Service Role Key');
        }

        // Authenticated user wants to set password (e.g. Google user adding password)
        const { error } = await supabaseAdmin.auth.admin.updateUserById(
            req.user.id, // This comes from authenticateToken (public.users id)
                         // Ideally matches Auth ID. If login was via Google, it DOES match.
            { password }
        );

        if (error) throw error;
        
        // Also clear setup_token/activate if needed
        await supabase.from('users').update({ 
            setup_token: null,
            is_active: true 
        }).eq('id', req.user.id);

        res.json({ message: 'Password updated successfully' });
     } catch(e) {
         console.error('Error completing setup:', e);
         res.status(500).send('Error updating password');
     }
});




app.get('/api/auth/me', authenticateToken, (req, res) => {
    // Return the user data attached by authenticateToken (from public.users)
    res.json(req.user);
});

// Middleware to check admin role
const isAdmin = async (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Admin access required');
    }
    next();
};

// Admin Routes: User Management
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { data: users, error } = await supabaseAdmin.from('users').select('*');

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

app.get('/api/admin/analytics', authenticateToken, isAdmin, async (req, res) => {
    try {
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        const isoDate = thirtyDaysAgo.toISOString();

        // 1. Fetch data
        const { data: messages, error: msgError } = await supabaseAdmin
            .from('messages')
            .select('timestamp')
            .gte('timestamp', isoDate);
            
        const { data: threads, error: threadsError } = await supabaseAdmin
            .from('threads')
            .select('created_at')
            .gte('created_at', isoDate);
            
        const { data: users, error: usersError } = await supabaseAdmin
            .from('users')
            .select('created_at, role');

        if (msgError || threadsError || usersError) throw new Error('Error fetching raw data');

        // 2. Aggregate Data Helper
        const groupByDate = (items, dateKey) => {
            const groups = {};
            items.forEach(item => {
                const date = new Date(item[dateKey]).toLocaleDateString();
                groups[date] = (groups[date] || 0) + 1;
            });
            return groups;
        };

        // 3. Process
        const messageStats = groupByDate(messages, 'timestamp');
        const threadStats = groupByDate(threads, 'created_at');
        
        // Generate last 30 days labels to ensure continuity
        const dates = [];
        for (let i = 29; i >= 0; i--) {
            const d = new Date();
            d.setDate(d.getDate() - i);
            dates.push(d.toLocaleDateString());
        }

        const chartData = {
            labels: dates,
            messages: dates.map(d => messageStats[d] || 0),
            threads: dates.map(d => threadStats[d] || 0)
        };
        
        const userDistribution = {
            admins: users.filter(u => u.role === 'admin').length,
            users: users.filter(u => u.role === 'user').length
        };

        res.json({
            chartData,
            userDistribution,
            totalMessages: messages.length,
            totalThreads: threads.length,
            totalUsers: users.length
        });

    } catch (e) {
        console.error('Error in analytics:', e);
        res.status(500).send('Error generating analytics');
    }
});

const { sendWelcomeEmail, sendResetPasswordEmail } = require('./emailService');

app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
    const { email, username, role } = req.body;
    if (!email || !username) return res.status(400).send('Email and username required');

    try {
        // Check if email already exists
        const { data: existingUser, error: checkError } = await supabaseAdmin
            .from('users')
            .select('id')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).send('Email already exists');
        }

        const setupToken = require('crypto').randomBytes(32).toString('hex');
        
        // Just create the user in public.users. 
        // Real Auth user will be created when they login via Google.
        const { data: newUser, error: insertError } = await supabaseAdmin
            .from('users')
            .insert({
                email,
                username,
                role: role || 'user',
                created_at: new Date().toISOString(),
                is_active: false,
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
        const { error } = await supabaseAdmin
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

// Document Routes (RAG)
app.post('/api/documents', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded');
        }

        const originalName = req.file.originalname;
        const sanitizedFilename = originalName.replace(/[^\x00-\x7F]/g, "_");

        console.log(`Uploading document: ${sanitizedFilename} (Original: ${originalName})`);

        const result = await ragService.processDocument(req.file.buffer, sanitizedFilename, req.user.id);

        const { error } = await supabase.from('documents').insert({
            user_id: req.user.id,
            filename: sanitizedFilename,
            original_filename: originalName,
            size: req.file.size,
            chunk_count: result.chunks,
            vector_ids: result.vectorIds || [], 
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
        let query = supabaseAdmin
            .from('documents')
            .select('*')
            .order('uploaded_at', { ascending: false });

        const { data: documents, error } = await query;
        if (error) throw error;

        // If not admin, sanitize filenames or hide details
        if (req.user.role !== 'admin') {
            // Return a simplified list so the frontend knows "there is knowledge"
            // but doesn't see actual filenames/links if that's what "verlo" means.
            // Actually, simply returning the list allows the frontend to say "Configuration Ready".
            // If the user means "Don't show the PDF list in a UI", the ToolAdvisor doesn't show the list anyway (only KnowledgeBase view does).
            // But main layout might allow navigation to KnowledgeBase?
            // User said: "que no puedan verlo" (that they cannot see it).
            // ToolAdvisor uses it to enable chat.
            // KnowledgeView uses it to list/manage.
            // I should probably BLOCK specific details for non-admins if they call the API.
            const sanitized = documents.map(d => ({
                id: d.id,
                filename: 'Conocimiento del Sistema', // Hide real name
                size: d.size,
                uploaded_at: d.uploaded_at
            }));
            return res.json(sanitized);
        }

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

        if (vectorIdsToDelete.length > 0) {
            await ragService.deleteDocument(vectorIdsToDelete);
        }

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

        if (doc.vector_ids && doc.vector_ids.length > 0) {
            await ragService.deleteDocument(doc.vector_ids);
        }

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
        const { data: threads, error } = await supabaseAdmin
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
    console.log('DEBUG: POST /threads handler reached. User:', req.user?.id, 'Body:', req.body);
    const body = req.body || {};
    const id = body.id || require('crypto').randomUUID();
    const title = body.title || 'New Chat';
    const timestamp = new Date().toISOString();

    try {
        const { error } = await supabaseAdmin.from('threads').insert({
            id,
            user_id: req.user.id,
            title,
            created_at: timestamp
        });

        if (error) throw error;

        res.json({ id, title, created_at: timestamp });
    } catch (e) {
        console.error('Error creating thread:', e);
        res.status(500).send('Error creating thread: ' + e.message);
    }
});

app.put('/api/threads/:id', authenticateToken, async (req, res) => {
    const { title } = req.body;
    try {
        const { data: thread, error: fetchError } = await supabaseAdmin
            .from('threads')
            .select('user_id')
            .eq('id', req.params.id)
            .single();

        if (fetchError || !thread) return res.status(404).send('Thread not found');
        if (thread.user_id !== req.user.id) return res.status(403).send('Unauthorized');

        const { error: updateError } = await supabaseAdmin
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
        const { data: thread, error: fetchError } = await supabaseAdmin
            .from('threads')
            .select('user_id')
            .eq('id', req.params.id)
            .single();

        if (fetchError || !thread) return res.status(404).send('Thread not found');
        if (thread.user_id !== req.user.id) return res.status(403).send('Unauthorized');

        const { error: deleteError } = await supabaseAdmin
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
        const { data: thread, error: fetchError } = await supabaseAdmin
            .from('threads')
            .select('user_id')
            .eq('id', req.params.id)
            .single();

        if (fetchError || !thread) return res.status(404).send('Thread not found');
        if (thread.user_id !== req.user.id) return res.status(403).send('Unauthorized');

        const { data: messages, error: msgError } = await supabaseAdmin
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

// NON-STREAMING ROUTE IMPLEMENTATION WITH SUPABASE
app.post('/api/threads/:id/messages', authenticateToken, async (req, res) => {
    const { content } = req.body;
    const threadId = req.params.id;

    try {
        // Check thread ownership
        // Use supabaseAdmin to bypass RLS since we verify ownership manually
        const { data: thread, error: fetchError } = await supabaseAdmin
            .from('threads')
            .select('user_id, title')
            .eq('id', threadId)
            .single();

        if (fetchError || !thread) {
            return res.status(404).send('Thread not found');
        }
        if (thread.user_id !== req.user.id) {
            return res.status(403).send('Unauthorized');
        }

        // Save user message
        const userMsgTimestamp = new Date().toISOString();
        const { data: savedUserMsg, error: userMsgError } = await supabaseAdmin
            .from('messages')
            .insert({
                thread_id: threadId,
                role: 'user',
                content,
                timestamp: userMsgTimestamp
            })
            .select()
            .single();

        if (userMsgError) throw userMsgError;

        // AI Response Logic
        let aiContent = '';

        if (process.env.OPENAI_API_KEY) {
            try {
                // Initialize OpenAI
                const openaiClient = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

                // Fetch History
                const { data: history, error: historyError } = await supabaseAdmin
                    .from('messages')
                    .select('role, content')
                    .eq('thread_id', threadId)
                    .order('timestamp', { ascending: true });

                // DATABASE CONTEXT: Query Machinery Table
                let systemPrompt = `Eres Sonar, un asistente experto en maquinaria y herramientas de construcción de la empresa NAR.`;
                
                try {
                    console.log(`DEBUG: Fetching Machinery Context for AI`);
                    
                    // Fetch all machinery with categories
                    const { data: machines, error } = await supabaseAdmin
                        .from('machinery')
                        .select(`
                            model,
                            description,
                            specs,
                            power_consumption_watts,
                            power_consumption_text,
                            categories ( name )
                        `);
                    
                    if (error) throw error;

                    if (machines && machines.length > 0) {
                        // Format context
                        const contextString = machines.map(m => {
                            const cat = m.categories?.name || 'General';
                            const specs = m.specs ? JSON.stringify(m.specs) : '';
                            const power = m.power_consumption_watts ? `${m.power_consumption_watts}W` : m.power_consumption_text;
                            return `[${cat}] Modelo: ${m.model} | Desc: ${m.description} | Potencia: ${power} | Specs: ${specs}`;
                        }).join('\n');

                        systemPrompt = `Eres Sonar, un asistente experto en maquinaria y herramientas de construcción de la empresa NAR. 
                        
                                        TU ÚNICA FUENTE DE INFORMACIÓN ES EL SIGUIENTE CATÁLOGO DE MAQUINARIA. NO USES INFORMACIÓN EXTERNA.
                                        SI LA MÁQUINA NO ESTÁ EN ESTA LISTA, DI QUE NO DISPONES DE INFORMACIÓN SOBRE ELLA.

                                        CATÁLOGO DE MAQUINARIA NAR:
                                        ${contextString}

                                        INSTRUCCIONES DE FORMATO ESTRICTAS:
                                        Debes responder SIEMPRE siguiendo esta estructura y formato exactos.

                                        [Párrafo introductorio directo y profesional]

                                        ### Opciones Recomendadas

                                        1. **Nombre de la Herramienta**
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
                                        - Cíñete al contexto.`;

                    } else {
                        console.warn('No machinery found in DB');
                        systemPrompt += ` Actualmente no tengo acceso al catálogo de maquinaria.`;
                    }
                } catch (dbError) {
                    console.error('DEBUG: DB Context Error:', dbError);
                    systemPrompt += ` Hubo un error al recuperar el catálogo.`;
                }

                const messages = [
                    { role: 'system', content: systemPrompt },
                    ...(history || []).map(m => ({ role: m.role, content: m.content }))
                ];

                const completion = await openaiClient.chat.completions.create({
                    messages: messages,
                    model: process.env.OPENAI_MODEL || 'gpt-4o',
                    // stream: false (default)
                });
                aiContent = completion.choices[0].message.content;

            } catch (error) {
                console.error('OpenAI Error:', error);
                aiContent = 'Error connecting to AI service.';
            }
        } else {
             // Mock AI
            aiContent = `(Mock AI) I received: "${content}".`;
        }

        // Save AI message to Supabase
        const aiMsgTimestamp = new Date().toISOString();
        const { data: savedAiMsg, error: aiMsgError } = await supabaseAdmin
            .from('messages')
            .insert({
                thread_id: threadId,
                role: 'assistant',
                content: aiContent,
                timestamp: aiMsgTimestamp
            })
            .select()
            .single();

        if (aiMsgError) throw aiMsgError;

        // Generate/Update Title if needed
        let newTitle = null;
        if (thread.title === 'New Chat' && process.env.OPENAI_API_KEY) {
            try {
                const openaiClient = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
                const titleCompletion = await openaiClient.chat.completions.create({
                     messages: [
                        { role: 'system', content: 'Generate a very short, concise title (max 5 words) for this chat based on the user message. Do not use quotes.' },
                        { role: 'user', content }
                    ],
                    model: process.env.OPENAI_MODEL || 'gpt-4o',
                });
                newTitle = titleCompletion.choices[0].message.content.trim();
                await supabaseAdmin
                    .from('threads')
                    .update({ title: newTitle })
                    .eq('id', threadId);
            } catch (ignore) {}
        }

        res.json({
            userMessage: savedUserMsg,
            aiMessage: savedAiMsg,
            newTitle 
        });
    } catch (e) {
        console.error('SERVER MESSAGE ERROR:', e);
        res.status(500).send('Error sending message: ' + e.message);
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
