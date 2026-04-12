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
const { MongoMemoryServer } = require('mongodb-memory-server');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const twilio = require('twilio');
const crypto = require('crypto');
const path = require('path');

const app = express();

// ==========================================
// SECURITY LAYER 1: HTTP Security Headers
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
            connectSrc: ["'self'", "*"], // Allow connecting to any API endpoint for convenience in deployment
        }
    },
    crossOriginEmbedderPolicy: false
}));

// ==========================================
// SECURITY LAYER 2: CORS
// ==========================================
app.use(cors()); // Simplified for deployment; restrict in production if needed
app.use(express.json({ limit: '5mb' }));

// ==========================================
// SECURITY LAYER 3: Input Sanitization
// ==========================================
app.use(mongoSanitize());
app.use(xssClean());
app.use(hpp());

// ==========================================
// SECURITY LAYER 4: Audit Logging
// ==========================================
app.use(morgan('dev'));

// ==========================================
// SECURITY LAYER 5: Serve Static Frontend
// ==========================================
app.use(express.static(path.join(__dirname, '../')));

// ==========================================
// SCHEMAS & MODELS (Defined GLOBALLY for reliable access)
// ==========================================
const VoteSchema = new mongoose.Schema({
    candidateId: { type: String, required: true },
    aadhaarHash: { type: String, required: true },
    selfieHash: { type: String },
    ipHash: { type: String },
    timestamp: { type: Date, default: Date.now }
});

const VoterSchema = new mongoose.Schema({
    voterId: { type: String, required: true, unique: true },
    aadhaarHash: { type: String, required: true, unique: true },
    panHash: { type: String, required: true, unique: true },
    epicHash: { type: String, required: true, unique: true },
    selfieHash: { type: String },
    ipHash: { type: String },
    timestamp: { type: Date, default: Date.now }
});

const OTPSchema = new mongoose.Schema({
    mobile: { type: String, required: true, unique: true },
    otpHash: { type: String, required: true },
    purpose: { type: String, default: 'login' },
    attempts: { type: Number, default: 0 },
    kycData: { type: Object },
    expiresAt: { type: Date, default: () => Date.now() + 5 * 60 * 1000 }
});

const AuditSchema = new mongoose.Schema({
    event: { type: String, required: true },
    ipHash: { type: String },
    mobileHash: { type: String },
    metadata: { type: Object },
    timestamp: { type: Date, default: Date.now }
});

const Vote = mongoose.models.Vote || mongoose.model('Vote', VoteSchema);
const Voter = mongoose.models.Voter || mongoose.model('Voter', VoterSchema);
const OTP = mongoose.models.OTP || mongoose.model('OTP', OTPSchema);
const Audit = mongoose.models.Audit || mongoose.model('Audit', AuditSchema);

// ==========================================
// DATABASE CONNECTION (Initiated but NOT blocking route registration)
// ==========================================
const connectDB = async () => {
    if (mongoose.connection.readyState >= 1) return;

    let MONGO_URI = process.env.MONGO_URI;

    if (!MONGO_URI) {
        if (process.env.VERCEL) {
            console.error('❌ MONGO_URI is missing. Vercel deployments REQUIRE a real MongoDB connection string.');
            return;
        }
        console.log('⚠️ No MONGO_URI. Starting local MongoMemoryServer...');
        const mongoServer = await MongoMemoryServer.create();
        MONGO_URI = mongoServer.getUri();
    }

    try {
        await mongoose.connect(MONGO_URI);
        console.log('✅ MongoDB Connected');
    } catch (err) {
        console.error('❌ MongoDB Connection Error:', err);
    }
};

// Middleware to ensure DB connection
app.use(async (req, res, next) => {
    await connectDB();
    next();
});

// ==========================================
// UTILITIES
// ==========================================
const hashIP = (ip) => crypto.createHash('sha256').update(ip + (process.env.JWT_SECRET_KEY || 'salt')).digest('hex').substring(0, 16);
const hashMobile = (mobile) => crypto.createHash('sha256').update(mobile).digest('hex').substring(0, 16);

const logEvent = async (event, req, metadata = {}) => {
    try {
        const ip = req.ip || req.connection?.remoteAddress || 'unknown';
        const mobile = req.body?.mobile;
        await Audit.create({
            event,
            ipHash: hashIP(ip),
            mobileHash: mobile ? hashMobile(mobile) : undefined,
            metadata
        });
    } catch(e) {}
};

// ==========================================
// RATE LIMITERS
// ==========================================
const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many OTP requests.' } });
const voteLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'Vote rate limit reached.' } });

// ==========================================
// VALIDATION
// ==========================================
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
    next();
};

// ==========================================
// API ROUTES
// ==========================================

app.post('/api/send-otp', otpLimiter, [
    body('mobile').matches(/^[6-9]\d{9}$/).withMessage('Valid 10-digit Indian mobile required.')
], handleValidationErrors, async (req, res) => {
    try {
        const { mobile } = req.body;
        const rawOTP = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedOTP = await bcrypt.hash(rawOTP, 12);

        await OTP.findOneAndUpdate(
            { mobile },
            { otpHash: hashedOTP, expiresAt: Date.now() + 5 * 60 * 1000, purpose: 'login', attempts: 0 },
            { upsert: true }
        );

        if (process.env.TWILIO_ACCOUNT_SID && !['your_actual_twilio_account_sid'].includes(process.env.TWILIO_ACCOUNT_SID)) {
            const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
            await client.messages.create({
                body: `[National e-Voting] Your OTP is ${rawOTP}.`,
                from: process.env.TWILIO_SMS_NUMBER,
                to: `+91${mobile}`
            });
            return res.json({ success: true, smsSent: true });
        }
        res.json({ success: true, simulatedOtp: rawOTP });
    } catch (err) {
        res.status(500).json({ error: 'OTP Dispatch Error' });
    }
});

app.post('/api/verify-otp', async (req, res) => {
    try {
        const { mobile, otp } = req.body;
        const record = await OTP.findOne({ mobile });
        if (!record || Date.now() > record.expiresAt) return res.status(400).json({ error: 'Invalid or expired OTP.' });

        const isValid = await bcrypt.compare(otp, record.otpHash);
        if (!isValid) return res.status(401).json({ error: 'Wrong OTP.' });

        await OTP.deleteOne({ mobile });
        const token = jwt.sign({ mobile }, process.env.JWT_SECRET_KEY, { expiresIn: '15m' });
        res.json({ success: true, token });
    } catch (err) {
        res.status(500).json({ error: 'Verification failed.' });
    }
});

app.post('/api/validate-documents', async (req, res) => {
    // Simplified logic for document validation endpoint
    const { aadhaar, pan, voterId } = req.body;
    if (!aadhaar || !pan || !voterId) return res.status(400).json({ error: 'All documents required.' });

    const aadhaarHash = crypto.createHash('sha256').update(aadhaar).digest('hex');
    const panHash = crypto.createHash('sha256').update(pan).digest('hex');
    const epicHash = crypto.createHash('sha256').update(voterId).digest('hex');

    if (await Voter.findOne({ $or: [{ aadhaarHash }, { panHash }, { epicHash }] })) {
        return res.status(403).json({ error: 'Document already used to vote.' });
    }

    const kycOTP = Math.floor(100000 + Math.random() * 900000).toString();
    const kycRef = `kyc_${aadhaarHash.substring(0,16)}`;
    const hashedKycOTP = await bcrypt.hash(kycOTP, 12);

    await OTP.findOneAndUpdate(
        { mobile: kycRef },
        { otpHash: hashedKycOTP, expiresAt: Date.now() + 5 * 60 * 1000, purpose: 'kyc_verify', kycData: { aadhaarHash, panHash, epicHash, voter: voterId } },
        { upsert: true }
    );

    res.json({ success: true, kycRef, simulatedKycOtp: kycOTP, maskedMobile: '91******'+aadhaar.slice(-4), maskedEmail: 'citizen@gov.in' });
});

app.post('/api/verify-kyc-otp', async (req, res) => {
    const { kycRef, otp } = req.body;
    const record = await OTP.findOne({ mobile: kycRef });
    if (!record) return res.status(400).json({ error: 'Invalid KYC reference.' });

    const isValid = await bcrypt.compare(otp, record.otpHash);
    if (!isValid) return res.status(401).json({ error: 'Wrong KYC OTP.' });

    const token = jwt.sign({ kycVerified: true, kycData: record.kycData }, process.env.JWT_SECRET_KEY, { expiresIn: '10m' });
    res.json({ success: true, kycToken: token });
});

app.post('/api/vote', async (req, res) => {
    try {
        const { candidateId, selfieData } = req.body;
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized.' });
        
        const decoded = jwt.verify(authHeader.split(' ')[1], process.env.JWT_SECRET_KEY);
        if (!decoded.kycVerified) return res.status(403).json({ error: 'KYC Required.' });

        const { aadhaarHash, panHash, epicHash, voter } = decoded.kycData;

        // Final duplicate check
        if (await Voter.findOne({ $or: [{ aadhaarHash }, { panHash }, { epicHash }] })) {
            return res.status(403).json({ error: 'Already voted.' });
        }

        const selfieHash = crypto.createHash('sha256').update(selfieData || 'none').digest('hex');
        const ipHash = hashIP(req.ip || '0.0.0.0');

        await new Voter({ voterId: `V_${voter}`, aadhaarHash, panHash, epicHash, selfieHash, ipHash }).save();
        await new Vote({ candidateId, aadhaarHash, selfieHash, ipHash }).save();

        res.json({ success: true, message: 'Vote Recorded.' });
    } catch (err) {
        res.status(500).json({ error: 'Voting failed.', details: err.message });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const stats = await Vote.aggregate([{ $group: { _id: "$candidateId", count: { $sum: 1 } } }]);
        const results = { bjp: 0, inc: 0, aap: 0, nota: 0 };
        stats.forEach(s => { results[s._id] = s.count; });
        res.json(results);
    } catch (err) {
        res.json({ bjp: 0, inc: 0, aap: 0, nota: 0 });
    }
});

app.post('/api/wipe', async (req, res) => {
    const key = req.headers['x-admin-key'];
    if (key !== process.env.ADMIN_SECRET_KEY) return res.status(403).json({ error: 'Unauthorized.' });
    await Vote.deleteMany({});
    await Voter.deleteMany({});
    await OTP.deleteMany({});
    res.json({ success: true });
});

// ==========================================
// STARTUP
// ==========================================
if (!process.env.VERCEL) {
    const PORT = process.env.PORT || 4000;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;
