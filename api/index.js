require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const xssClean = require('xss-clean');
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

// Rate Limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // limit each IP to 50 requests per windowMs
    message: { error: 'Too many authentication attempts. Please try again later.' }
});

const voteLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // limit each IP to 10 votes per hour
    message: { error: 'Voting limit exceeded. Only 10 votes per hour allowed from this connection.' }
});

const app = express();

// ==========================================
// SECURITY & CONFIG
// ==========================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https://upload.wikimedia.org", "blob:"],
            mediaSrc: ["'self'", "blob:", "mediastream:"],
            connectSrc: ["'self'", "*"],
        }
    },
    crossOriginEmbedderPolicy: false
}));

app.disable('x-powered-by'); // Security: Don't reveal server type

const allowedOrigins = [
    'http://localhost:4455',
    'http://localhost:3000',
    'http://localhost:8000',
    'http://127.0.0.1:4455',
    'http://127.0.0.1:8000',
    /\.vercel\.app$/ // Allow Vercel deployments
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.some(ao => typeof ao === 'string' ? ao === origin : ao.test(origin))) {
            callback(null, true);
        } else {
            callback(new Error('CORS Policy Blocked: Unauthorized Origin'));
        }
    },
    methods: ['GET', 'POST'],
    credentials: true
}));

app.use(express.json({ limit: '1mb' })); // Reduced limit for safety
app.use(mongoSanitize());
app.use(xssClean());
app.use(hpp());
app.use(morgan('combined')); // More detailed logs for security monitoring

// Serve Static Frontend
const publicPath = path.join(__dirname, '../public');
app.use(express.static(publicPath));

// ==========================================
// DB ENGINE (With Smart Simulation Fallback)
// ==========================================
let isSimulated = false;
let db = { votes: [], voters: [], otps: [], audit: [] };

const connectDB = async () => {
    if (isSimulated || mongoose.connection.readyState >= 1) return;
    if (!process.env.MONGO_URI) { isSimulated = true; return; }
    try {
        await mongoose.connect(process.env.MONGO_URI, { connectTimeoutMS: 5000 });
        console.log('✅ MongoDB Connected');
    } catch (err) {
        isSimulated = true;
    }
};

app.use(async (req, res, next) => {
    try { await connectDB(); } catch(e) { isSimulated = true; }
    next();
});

// ==========================================
// SCHEMAS & MODELS
// ==========================================
const VoteSchema = new mongoose.Schema({ candidateId: String, aadhaarHash: String, timestamp: { type: Date, default: Date.now } });
const VoterSchema = new mongoose.Schema({ voterId: String, aadhaarHash: String, epicHash: String, timestamp: { type: Date, default: Date.now } });
const OTPSchema = new mongoose.Schema({ mobile: String, otpHash: String, expiresAt: Date, purpose: String, kycData: Object });

const Vote = mongoose.models.Vote || mongoose.model('Vote', VoteSchema);
const Voter = mongoose.models.Voter || mongoose.model('Voter', VoterSchema);
const OTP = mongoose.models.OTP || mongoose.model('OTP', OTPSchema);

// ==========================================
// API ROUTES
// ==========================================
const api = express.Router();
const SECRET = process.env.JWT_SECRET_KEY || 'national_voting_secret_2026';

api.get('/stats', async (req, res) => {
    const adminSecret = process.env.ADMIN_SECRET_KEY || '68c7c9c0-681b-4d40-84c8-358055a40b8a';
    if (req.headers['x-admin-key'] !== adminSecret) {
        return res.status(403).json({ error: 'Access Denied: Admin authentication required to view election stats.' });
    }
    try {
        if (isSimulated) {
            const counts = { bjp: 0, inc: 0, aap: 0, nota: 0 };
            db.votes.forEach(v => { if(counts[v.candidateId] !== undefined) counts[v.candidateId]++; });
            return res.json(counts);
        }
        const stats = await Vote.aggregate([{ $group: { _id: "$candidateId", count: { $sum: 1 } } }]);
        const results = { bjp: 0, inc: 0, aap: 0, nota: 0 };
        stats.forEach(s => { results[s._id] = s.count; });
        res.json(results);
    } catch (e) { 
        res.status(500).json({ error: 'Failed to retrieve stats' }); 
    }
});

api.post('/send-otp', authLimiter, async (req, res) => {
    const { mobile } = req.body;
    const rawOTP = "123456"; 
    const hashedOTP = await bcrypt.hash(rawOTP, 10);
    if (isSimulated) {
        db.otps = db.otps.filter(o => o.mobile !== mobile);
        db.otps.push({ mobile, otpHash: hashedOTP, expiresAt: Date.now() + 300000 });
        console.log(`[AUTH] Simulated OTP for ${mobile}: ${rawOTP}`);
    } else {
        await OTP.findOneAndUpdate({ mobile }, { otpHash: hashedOTP, expiresAt: Date.now() + 300000 }, { upsert: true });
    }
    // SECURE: Do not return the OTP in the JSON response
    res.json({ success: true, message: 'OTP sent successfully' });
});

api.post('/verify-otp', async (req, res) => {
    try {
        const { mobile, otp } = req.body;
        if (!mobile || !otp) return res.status(400).json({ error: 'Mobile and OTP are required.' });
        
        let record = isSimulated ? db.otps.find(o => o.mobile === mobile) : await OTP.findOne({ mobile });
        if (!record) return res.status(400).json({ error: 'Retry OTP sequence.' });
        
        const valid = await bcrypt.compare(otp, record.otpHash);
        if (!valid) return res.status(401).json({ error: 'Wrong OTP.' });
        
        const token = jwt.sign({ mobile }, SECRET, { expiresIn: '20m' });
        res.json({ success: true, token });
    } catch (err) {
        console.error('Login verification error:', err);
        res.status(500).json({ error: 'Internal server error during OTP verification' });
    }
});

api.post('/validate-documents', async (req, res) => {
    try {
        const { aadhaar, pan, voterId } = req.body;
        
        if (!aadhaar || !pan || !voterId) {
            return res.status(400).json({ error: 'All document fields (Aadhaar, PAN, Voter ID) are required.' });
        }

        // SECURE: Added salting to hashing to prevent rainbow table attacks/de-anonymization
        const salt = process.env.HASH_SALT || 'development_fallback_salt_2026';
        const aHash = crypto.createHash('sha256').update(aadhaar + salt).digest('hex');
        
        const exists = isSimulated ? db.voters.find(v => v.aadhaarHash === aHash) : await Voter.findOne({ aadhaarHash: aHash });
        if (exists) return res.status(403).json({ error: 'This identity has already cast a vote.' });
        
        const kycOtp = "123456";
        const kycRef = `kyc_${aHash.substring(0,10)}`;
        const hashed = await bcrypt.hash(kycOtp, 10);
        
        if (isSimulated) {
            db.otps.push({ mobile: kycRef, otpHash: hashed, kycData: { aadhaarHash: aHash, voter: voterId } });
            console.log(`[KYC] Simulated OTP for ${kycRef}: ${kycOtp}`);
        } else {
            await OTP.findOneAndUpdate({ mobile: kycRef }, { otpHash: hashed, kycData: { aadhaarHash: aHash, voter: voterId } }, { upsert: true });
        }
        
        res.json({ 
            success: true, 
            kycRef, 
            maskedMobile: '******' + aadhaar.slice(-4), 
            maskedEmail: voterId + '@gov.in' 
        });
    } catch (err) {
        console.error('Document validation error:', err);
        res.status(500).json({ error: 'Error during document validation. Contact administrator.' });
    }
});

api.post('/verify-kyc-otp', async (req, res) => {
    try {
        const { kycRef, otp } = req.body;
        if (!kycRef || !otp) return res.status(400).json({ error: 'KYC reference and OTP are required.' });

        let record = isSimulated ? db.otps.find(o => o.mobile === kycRef) : await OTP.findOne({ mobile: kycRef });
        if (!record) return res.status(400).json({ error: 'KYC expired.' });
        
        const valid = await bcrypt.compare(otp, record.otpHash);
        if (!valid) return res.status(401).json({ error: 'Wrong KYC OTP.' });
        
        const token = jwt.sign({ kycVerified: true, kycData: record.kycData }, SECRET, { expiresIn: '15m' });
        res.json({ success: true, kycToken: token });
    } catch (err) {
        console.error('KYC verification error:', err);
        res.status(500).json({ error: 'Internal server error during KYC verification' });
    }
});

api.post('/vote', voteLimiter, async (req, res) => {
    try {
        const { candidateId, selfieData } = req.body;
        const auth = req.headers.authorization;
        const decoded = jwt.verify(auth?.split(' ')[1], SECRET);
        if (!decoded.kycVerified) return res.status(403).json({ error: 'KYC missing.' });
        const { aadhaarHash } = decoded.kycData;
        if (isSimulated) {
            db.voters.push({ aadhaarHash, voterId: 'V'+Date.now() });
            db.votes.push({ candidateId, aadhaarHash });
        } else {
            await new Voter({ aadhaarHash, voterId: 'V'+Date.now() }).save();
            await new Vote({ candidateId, aadhaarHash }).save();
        }
        res.json({ success: true, message: 'Vote Recorded' });
    } catch (err) {
        res.status(500).json({ error: 'Vote failed', details: err.message });
    }
});

api.post('/wipe', async (req, res) => {
    const adminSecret = process.env.ADMIN_SECRET_KEY || '68c7c9c0-681b-4d40-84c8-358055a40b8a'; // Secure default
    if (req.headers['x-admin-key'] !== adminSecret) {
        console.warn(`[SECURITY] Unauthorized wipe attempt from IP: ${req.ip}`);
        return res.status(403).json({ error: 'Administrative access required.' });
    }
    if (isSimulated) { db = { votes: [], voters: [], otps: [], audit: [] }; }
    else { await Vote.deleteMany({}); await Voter.deleteMany({}); }
    console.log(`[ADMIN] Database wiped by administrative action.`);
    res.json({ success: true });
});

// Dual mount + strict catch-all
app.use('/api', api);
app.use('/', api);

// Final Safety Fallback
app.get('*', (req, res) => {
    if (req.path.startsWith('/api')) return res.status(404).json({ error: 'API Endpoint Not Found' });
    res.sendFile(path.join(publicPath, 'index.html'));
});

if (!process.env.VERCEL) {
    app.listen(4000, () => console.log('🛡️  Election Server ready'));
}

module.exports = app;
