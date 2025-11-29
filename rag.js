const { Pinecone } = require('@pinecone-database/pinecone');
const OpenAI = require('openai');
const pdf = require('pdf-parse');
require('dotenv').config();

// Initialize OpenAI
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Initialize Pinecone
let pineconeIndex;

// Helper: Chunk text
function chunkText(text, chunkSize = 1000, overlap = 200) {
    const chunks = [];
    let start = 0;
    while (start < text.length) {
        const end = Math.min(start + chunkSize, text.length);
        chunks.push(text.slice(start, end));
        start += chunkSize - overlap;
    }
    return chunks;
}

// Helper: Generate Embedding
async function embedText(text) {
    const response = await openai.embeddings.create({
        model: "text-embedding-3-small",
        input: text,
    });
    return response.data[0].embedding;
}

const ragService = {
    init() {
        console.log('Initializing RAG Service...');
        if (process.env.PINECONE_API_KEY && process.env.PINECONE_INDEX) {
            try {
                const pc = new Pinecone({ apiKey: process.env.PINECONE_API_KEY });
                pineconeIndex = pc.index(process.env.PINECONE_INDEX);
                console.log('✅ Pinecone initialized successfully');
            } catch (error) {
                console.error('❌ Error initializing Pinecone:', error);
            }
        } else {
            console.warn('⚠️ Pinecone not configured (PINECONE_API_KEY or PINECONE_INDEX missing)');
            console.log('Current Env Vars:', {
                PINECONE_INDEX: process.env.PINECONE_INDEX,
                PINECONE_API_KEY_EXISTS: !!process.env.PINECONE_API_KEY
            });
        }
    },

    async processDocument(fileBuffer, fileName, userId) {
        if (!pineconeIndex) {
            console.error('❌ Pinecone not initialized');
            throw new Error('Pinecone not configured');
        }

        console.log(`Processing document: ${fileName} for user: ${userId}`);
        
        try {
            // 1. Extract Text
            console.log('DEBUG: Starting PDF parsing...');
            const data = await pdf(fileBuffer);
            const text = data.text;
            console.log(`DEBUG: Extracted text length: ${text.length}`);
            
            if (!text || text.trim().length < 50) {
                console.warn('⚠️ Extracted text is too short. Likely a scanned PDF or empty file.');
                throw new Error('Could not extract text from document. If this is a scanned PDF (images), it is not supported yet.');
            }
            
            // 2. Chunk Text
            const chunks = chunkText(text);
            console.log(`Generated ${chunks.length} chunks`);

            // 3. Embed and Upsert
            const vectors = [];
            console.log('DEBUG: Starting embedding generation...');
            for (let i = 0; i < chunks.length; i++) {
                const chunk = chunks[i];
                const embedding = await embedText(chunk);
                
                vectors.push({
                    id: require('crypto').randomUUID(),
                    values: embedding,
                    metadata: {
                        text: chunk,
                        fileName: fileName,
                        userId: userId,
                        chunkIndex: i
                    }
                });
            }
            console.log(`DEBUG: Generated ${vectors.length} vectors. Starting upsert...`);

            // Batch upsert
            const batchSize = 50;
            for (let i = 0; i < vectors.length; i += batchSize) {
                const batch = vectors.slice(i, i + batchSize);
                console.log(`DEBUG: Upserting batch ${i / batchSize + 1} of ${Math.ceil(vectors.length / batchSize)}`);
                await pineconeIndex.upsert(batch);
            }
            console.log('DEBUG: Upsert complete');
            
            return { chunks: chunks.length };
        } catch (error) {
            console.error('❌ Error in processDocument:', error);
            throw error;
        }
    },

    async queryContext(query, userId) {
        if (!pineconeIndex) return [];

        try {
            // 1. Embed Query
            const embedding = await embedText(query);

            // 2. Query Pinecone
            console.log('DEBUG: Querying Pinecone...');
            const queryResponse = await pineconeIndex.query({
                vector: embedding,
                topK: 3,
                filter: { userId: userId },
                includeMetadata: true
            });
            console.log('DEBUG: Pinecone matches:', queryResponse.matches.length);
            
            // 3. Extract Text
            return queryResponse.matches.map(match => match.metadata.text).join('\n\n');
        } catch (error) {
            console.error('❌ Error in queryContext:', error);
            return ''; // Return empty context on error to avoid breaking chat
        }
    },
    
    async deleteDocument(fileName, userId) {
         if (!pineconeIndex) return;
         try {
             console.log(`DEBUG: Deleting vectors for file: ${fileName}`);
             await pineconeIndex.deleteMany({
                 filter: {
                     userId: userId,
                     fileName: fileName
                 }
             });
             console.log('DEBUG: Vectors deleted successfully');
         } catch (e) {
             console.error('⚠️ Error deleting vectors from Pinecone (proceeding with Firestore delete):', e.message);
             // We swallow the error here to allow Firestore deletion to proceed
             // This is important for cleaning up "corrupted" documents where Pinecone metadata might be invalid
         }
    }
};

module.exports = ragService;
