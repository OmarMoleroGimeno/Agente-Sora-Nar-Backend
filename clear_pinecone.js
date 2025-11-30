const { Pinecone } = require('@pinecone-database/pinecone');
require('dotenv').config();

async function clearIndex() {
    if (!process.env.PINECONE_API_KEY || !process.env.PINECONE_INDEX) {
        console.error('❌ Missing Pinecone configuration');
        return;
    }

    try {
        const pc = new Pinecone({ apiKey: process.env.PINECONE_API_KEY });
        const index = pc.index(process.env.PINECONE_INDEX);

        console.log('⚠️  WARNING: This will delete ALL vectors in the Pinecone index.');
        console.log('Starting deletion...');

        await index.deleteAll();

        console.log('✅ Pinecone index cleared successfully.');
    } catch (error) {
        console.error('❌ Error clearing index:', error);
    }
}

clearIndex();
