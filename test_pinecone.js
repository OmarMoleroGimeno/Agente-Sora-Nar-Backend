const { Pinecone } = require('@pinecone-database/pinecone');
require('dotenv').config();

async function test() {
    console.log('Initializing Pinecone...');
    if (!process.env.PINECONE_API_KEY || !process.env.PINECONE_INDEX) {
        console.error('Missing env vars');
        return;
    }

    try {
        const pc = new Pinecone({ apiKey: process.env.PINECONE_API_KEY });
        const index = pc.index(process.env.PINECONE_INDEX);

        console.log('Attempting deleteMany with array of IDs...');
        // Try deleting a dummy ID
        await index.deleteMany(['dummy-id-123']);
        console.log('✅ deleteMany(array) worked!');
    } catch (error) {
        console.error('❌ deleteMany(array) failed:', error);

        try {
            console.log('Attempting deleteMany with object { ids: ... }...');
            await index.deleteMany({ ids: ['dummy-id-123'] });
            console.log('✅ deleteMany({ ids: [] }) worked!');
        } catch (e2) {
            console.error('❌ deleteMany({ ids: [] }) failed:', e2);
        }
    }
}

test();
