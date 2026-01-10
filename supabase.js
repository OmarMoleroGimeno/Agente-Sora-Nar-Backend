const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY; // Anon Key
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY; // Service Role Key

if (!supabaseUrl || !supabaseKey) {
    console.error('❌ Supabase URL or Key missing in .env');
}

const supabase = createClient(supabaseUrl, supabaseKey);

// Admin client for backend operations (createUser, deleteUser, etc.)
let supabaseAdmin = null;
if (supabaseServiceKey) {
    supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        }
    });
} else {
    console.warn('⚠️ SUPABASE_SERVICE_ROLE_KEY missing. Admin operations will fail.');
    // Fallback? No, it will fail.
}

module.exports = { supabase, supabaseAdmin };

