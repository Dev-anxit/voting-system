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
const crypto = require('crypto');
const path = require('path');

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

app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(mongoSanitize());
app.use(xssClean());
app.use(hpp());
app.use(morgan('dev'));

// Serve Static Frontend
const publicPath = path.join(__dirname, '../public');
app.use(express.static(publicPath));

// ==========================================
// DB ENGINE (With Smart Simulation Fallback)
// ==========================================
let isSimulated = false;
let db = { votes: [], voters: [], otps: [], audit: [] }; // In-memory fallback if Mongo fails

const connectDB = async () => {
    if (isSimulated || mongoose.connection.readyState >= 1) return;

    if (!process.env.MONGO_URI) {
        console.warn('⚠️ No MONGO_URI found. Switching to IN-MEMORY SIMULATION MODE for demo purposes.');
        isSimulated = true;
        return;
    }

    try {
        await mongoose.connect(process.env.MONGO_URI, { connectTimeoutMS: 5000 });
        console.log('✅ MongoDB Connected');
    } catch (err) {
        console.error('❌ MongoDB failed. Falling back to simulation.');
        isSimulated = true;
    }
};

app.use(async (req, res, next) => {
    await connectDB();
    next();
});

// ==========================================
// SCHEMAS & MODELS
// ==========================================
// Keep these for when MONGO_URI is eventually added
const VoteSchema = new mongoose.Schema({ candidateId: String, aadhaarHash: String, timestamp: { type: Date, default: Date.now } });
const VoterSchema = new mongoose.Schema({ voterId: String, aadhaarHash: String, epicHash: String, timestamp: { type: Date, default: Date.now } });
const OTPSchema = new mongoose.Schema({ mobile: String, otpHash: String, expiresAt: Date, purpose: String });

const Vote = mongoose.models.Vote || mongoose.model('Vote', VoteSchema);
const Voter = mongoose.models.Voter || mongoose.model('Voter', VoterSchema);
const OTP = mongoose.models.OTP || mongoose.model('OTP', OTPSchema);

// ==========================================
// API ROUTES
// ==========================================

// Global JWT Secret Fallback
const SECRET = process.env.JWT_SECRET_KEY || 'national_voting_secret_2026';

app.get('/api/stats', async (req, res) => {
    if (isSimulated) {
        const counts = { bjp: 0, inc: 0, aap: 0, nota: 0 };
        db.votes.forEach(v => counts[v.candidateId]++);
        return res.json(counts);
    }
    const stats = await Vote.aggregate([{ $group: { _id: "$candidateId", count: { $sum: 1 } } }]);
    const results = { bjp: 0, inc: 0, aap: 0, nota: 0 };
    stats.forEach(s => { results[s._id] = s.count; });
    res.json(results);
});

app.post('/api/send-otp', async (req, res) => {
    const { mobile } = req.body;
    const rawOTP = "123456"; // Fixed for easier testing in simulation
    const hashedOTP = await bcrypt.hash(rawOTP, 10);

    if (isSimulated) {
        db.otps = db.otps.filter(o => o.mobile !== mobile);
        db.otps.push({ mobile, otpHash: hashedOTP, expiresAt: Date.now() + 300000 });
    } else {
        await OTP.findOneAndUpdate({ mobile }, { otpHash: hashedOTP, expiresAt: Date.now() + 300000 }, { upsert: true });
    }

    res.json({ success: true, message: 'OTP sent (Simulated)', simulatedOtp: rawOTP });
});

app.post('/api/verify-otp', async (req, res) => {
    const { mobile, otp } = req.body;
    let record = isSimulated ? db.otps.find(o => o.mobile === mobile) : await OTP.findOne({ mobile });

    if (!record) return res.status(400).json({ error: 'Retry OTP sequence.' });
    const valid = await bcrypt.compare(otp, record.otpHash);
    if (!valid) return res.status(401).json({ error: 'Wrong OTP.' });

    const token = jwt.sign({ mobile }, SECRET, { expiresIn: '20m' });
    res.json({ success: true, token });
});

app.post('/api/validate-documents', async (req, res) => {
    const { aadhaar, pan, voterId } = req.body;
    const aHash = crypto.createHash('sha256').update(aadhaar).digest('hex');
    
    const exists = isSimulated ? db.voters.find(v => v.aadhaarHash === aHash) : await Voter.findOne({ aadhaarHash: aHash });
    if (exists) return res.status(403).json({ error: 'Document already voted.' });

    const kycOtp = "123456";
    const kycRef = `kyc_${aHash.substring(0,10)}`;
    const hashed = await bcrypt.hash(kycOtp, 10);

    if (isSimulated) {
        db.otps.push({ mobile: kycRef, otpHash: hashed, kycData: { aadhaarHash: aHash, voter: voterId } });
    } else {
        await OTP.findOneAndUpdate({ mobile: kycRef }, { otpHash: hashed, kycData: { aadhaarHash: aHash, voter: voterId } }, { upsert: true });
    }

    res.json({ success: true, kycRef, simulatedKycOtp: kycOtp, maskedMobile: '******'+aadhaar.slice(-4), maskedEmail: voterId+'@gov.in' });
});

app.post('/api/verify-kyc-otp', async (req, res) => {
    const { kycRef, otp } = req.body;
    let record = isSimulated ? db.otps.find(o => o.mobile === kycRef) : await OTP.findOne({ mobile: kycRef });

    if (!record) return res.status(400).json({ error: 'KYC expired.' });
    const valid = await bcrypt.compare(otp, record.otpHash);
    if (!valid) return res.status(401).json({ error: 'Wrong KYC OTP.' });

    const token = jwt.sign({ kycVerified: true, kycData: record.kycData }, SECRET, { expiresIn: '15m' });
    res.json({ success: true, kycToken: token });
});

app.post('/api/vote', async (req, res) => {
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

app.post('/api/wipe', async (req, res) => {
    if (req.headers['x-admin-key'] !== (process.env.ADMIN_SECRET_KEY || 'admin')) return res.status(403).json({ error: 'No' });
    if (isSimulated) { db = { votes: [], voters: [], otps: [], audit: [] }; }
    else { await Vote.deleteMany({}); await Voter.deleteMany({}); }
    res.json({ success: true });
});

// Fallback for SPA routing
app.get('*', (req, res) => {
    res.sendFile(path.join(projectRoot, 'index.html'));
});

if (!process.env.VERCEL) {
    app.listen(4000, () => console.log('🛡️  Election Server ready on port 4000'));
}

module.exports = app;
