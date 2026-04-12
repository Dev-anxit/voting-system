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
// SECURITY LAYER 1: HTTP Security Headers (Helmet)
// Prevents: XSS, Clickjacking, MIME sniffing, etc.
// ==========================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'",
                "https://unpkg.com", "https://cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'",
                "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https://upload.wikimedia.org", "blob:"],
            mediaSrc: ["'self'", "blob:", "mediastream:"],
            connectSrc: ["'self'", "http://localhost:4000"],
        }
    },
    crossOriginEmbedderPolicy: false // Needed for camera/webcam
}));

// ==========================================
// SECURITY LAYER 2: CORS — Strict Origin Restriction
// ==========================================
const allowedOrigins = [
    'http://localhost:4455',
    'http://localhost:4000',
    'http://127.0.0.1:4455',
    process.env.FRONTEND_URL // Production URL from env
].filter(Boolean);

app.use(cors({
    origin: (origin, callback) => {
        // Allow no-origin (same-origin) requests and known origins
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error(`CORS Policy: Origin '${origin}' is not permitted.`));
        }
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

app.use(express.json({ limit: '5mb' })); // Limit body size (5MB for selfie)

// ==========================================
// SECURITY LAYER 3: Input Sanitization
// Prevents: MongoDB NoSQL Injection, XSS, HTTP Parameter Pollution
// ==========================================
app.use(mongoSanitize()); // Strips $ and . from user input to block injection
app.use(xssClean());      // Sanitizes HTML tags in input
app.use(hpp());            // Prevents HTTP Parameter Pollution attacks

// ==========================================
// SECURITY LAYER 4: Audit Logging
// Every request is logged with timestamp, IP, method, path, and status
// ==========================================
app.use(morgan('[:date[clf]] :remote-addr ":method :url" :status :response-time ms'));

// ==========================================
// SECURITY LAYER 5: Serve Static Frontend
// ==========================================
app.use(express.static(path.join(__dirname, '../')));

// ==========================================
// SECURITY LAYER 6: Rate Limiting (Tiered)
// ==========================================
// Global rate limit — 100 requests per 15 mins per IP
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please try again later.' }
});
app.use('/api/', globalLimiter);

// Strict OTP limit — 5 requests per 15 mins (brute force guard)
const otpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many OTP requests from this IP. Wait 15 minutes.' }
});

// Strict Vote limit — 3 requests per hour (one person can't submit multiple times)
const voteLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Vote rate limit exceeded. Suspected automated voting.' }
});

// Admin endpoint limiter — very strict
const adminLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: 'Admin endpoint throttled.' }
});

// ==========================================
// SECURITY LAYER 7: Input Validation Rules
// ==========================================
const validateMobile = [
    body('mobile')
        .trim()
        .isLength({ min: 10, max: 10 }).withMessage('Mobile must be exactly 10 digits.')
        .isNumeric().withMessage('Mobile must be numeric only.')
        .matches(/^[6-9]\d{9}$/).withMessage('Mobile number must be a valid Indian number starting with 6-9.')
];

const validateOtp = [
    body('otp')
        .trim()
        .isLength({ min: 6, max: 6 }).withMessage('OTP must be exactly 6 digits.')
        .isNumeric().withMessage('OTP must be numeric only.')
];

const validateDocuments = [
    body('aadhaar')
        .trim()
        .isLength({ min: 12, max: 12 }).withMessage('Aadhaar must be 12 digits.')
        .isNumeric().withMessage('Aadhaar must be numeric only.'),
    body('pan')
        .trim()
        .isLength({ min: 10, max: 10 }).withMessage('PAN must be 10 characters.')
        .matches(/^[A-Z]{5}[0-9]{4}[A-Z]$/).withMessage('PAN format invalid.'),
    body('voterId')
        .trim()
        .isLength({ min: 10, max: 10 }).withMessage('Voter ID must be 10 characters.')
        .matches(/^[A-Z]{3}\d{7}$/).withMessage('Voter ID format invalid.')
];

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
    }
    next();
};

// ==========================================
// DOCUMENT VALIDATION UTILITIES
// ==========================================
const verhoeffTableD = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0]
];
const verhoeffTableP = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]
];

function validateAadhaar(aadhaar) {
    if (!/^\d{12}$/.test(aadhaar)) return { valid: false, reason: 'Aadhaar must be exactly 12 digits.' };
    if (/^[01]/.test(aadhaar)) return { valid: false, reason: 'Aadhaar cannot start with 0 or 1.' };
    let c = 0;
    const digits = aadhaar.split('').map(Number).reverse();
    for (let i = 0; i < digits.length; i++) {
        c = verhoeffTableD[c][verhoeffTableP[i % 8][digits[i]]];
    }
    if (c !== 0) return { valid: false, reason: 'Aadhaar checksum verification FAILED. This number is not genuine.' };
    return { valid: true };
}

function validatePAN(pan) {
    if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(pan)) {
        return { valid: false, reason: 'PAN format invalid (e.g., ABCDE1234F).' };
    }
    const validEntities = ['A','B','C','F','G','H','J','L','P','T'];
    if (!validEntities.includes(pan[3])) {
        return { valid: false, reason: `PAN 4th character '${pan[3]}' is not a valid entity type.` };
    }
    return { valid: true, entityType: pan[3] === 'P' ? 'Individual' : 'Entity' };
}

function validateVoterId(voterId) {
    if (!/^[A-Z]{3}\d{7}$/.test(voterId)) {
        return { valid: false, reason: 'Voter ID format invalid (3 letters + 7 digits, e.g., ABC1234567).' };
    }
    return { valid: true };
}

function lookupGovernmentRecords(aadhaar, pan, voterId) {
    const hash = crypto.createHash('sha256').update(aadhaar + pan + voterId).digest('hex');
    const registeredMobile = `9${hash.substring(0, 9)}`;
    const maskedMobile = `${registeredMobile.substring(0,2)}******${registeredMobile.substring(8)}`;
    const maskedEmail = `${voterId.toLowerCase().substring(0,3)}***@gov.in`;
    return { registeredMobile, maskedMobile, maskedEmail };
}

// ==========================================
// CORE INFRASTRUCTURE
// ==========================================
(async () => {
    // ==========================================
    // CLOUD DATABASE ROUTING
    // ==========================================
    let MONGO_URI = process.env.MONGO_URI;

    if (MONGO_URI) {
        console.log('☁️  Connecting to Dedicated Cloud Database...');
    } else {
        const mongoServer = await MongoMemoryServer.create();
        MONGO_URI = mongoServer.getUri();
        console.log('⚠️ No cloud MONGO_URI detected. Spun up temporary local MongoDB node.');
    }

    mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
        .then(() => console.log('✅ Secured MongoDB Cluster Loaded'))
        .catch(err => console.error('MongoDB error:', err));

    // ==========================================
    // SCHEMAS
    // ==========================================
    const VoteSchema = new mongoose.Schema({
        candidateId: { type: String, required: true },
        aadhaarHash: { type: String, required: true },
        selfieHash: { type: String },
        ipHash: { type: String },          // NEW: hashed IP for audit, preserving privacy
        timestamp: { type: Date, default: Date.now }
    });

    const VoterSchema = new mongoose.Schema({
        voterId: { type: String, required: true, unique: true },
        aadhaarHash: { type: String, required: true, unique: true },
        panHash: { type: String, required: true, unique: true },
        epicHash: { type: String, required: true, unique: true },
        selfieHash: { type: String },
        ipHash: { type: String },          // NEW: hashed IP at vote time
        timestamp: { type: Date, default: Date.now }
    });

    const OTPSchema = new mongoose.Schema({
        mobile: { type: String, required: true, unique: true },
        otpHash: { type: String, required: true },
        purpose: { type: String, default: 'login' },
        attempts: { type: Number, default: 0 },  // NEW: track wrong attempts
        kycData: { type: Object },
        expiresAt: { type: Date, default: () => Date.now() + 5 * 60 * 1000 }
    });

    // NEW: Audit log — immutable record of all security events
    const AuditSchema = new mongoose.Schema({
        event: { type: String, required: true },
        ipHash: { type: String },
        mobileHash: { type: String },
        metadata: { type: Object },
        timestamp: { type: Date, default: Date.now }
    });

    const Vote = mongoose.model('Vote', VoteSchema);
    const Voter = mongoose.model('Voter', VoterSchema);
    const OTP = mongoose.model('OTP', OTPSchema);
    const Audit = mongoose.model('Audit', AuditSchema);

    // ==========================================
    // AUDIT HELPER
    // ==========================================
    const hashIP = (ip) => crypto.createHash('sha256').update(ip + (process.env.JWT_SECRET_KEY || 'salt')).digest('hex').substring(0, 16);
    const hashMobile = (mobile) => crypto.createHash('sha256').update(mobile).digest('hex').substring(0, 16);

    const log = async (event, req, metadata = {}) => {
        try {
            const ip = req.ip || req.connection?.remoteAddress || 'unknown';
            const mobile = req.body?.mobile;
            await Audit.create({
                event,
                ipHash: hashIP(ip),
                mobileHash: mobile ? hashMobile(mobile) : undefined,
                metadata
            });
        } catch(e) { /* Non-blocking audit */ }
    };

    // ==========================================
    // MIDDLEWARE: JWT Authentication
    // ==========================================
    const authenticateJWT = (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing or malformed Authorization header.' });
        }
        const token = authHeader.split(' ')[1];
        jwt.verify(token, process.env.JWT_SECRET_KEY, (err, user) => {
            if (err) {
                return res.status(403).json({ error: 'Token tampered or expired. Please login again.' });
            }
            req.user = user;
            next();
        });
    };

    // SECURITY: Admin secret middleware — requires a hardcoded admin key in header
    const authenticateAdmin = (req, res, next) => {
        const adminKey = req.headers['x-admin-key'];
        const expectedKey = process.env.ADMIN_SECRET_KEY;
        if (!expectedKey || !adminKey || adminKey !== expectedKey) {
            log('ADMIN_UNAUTHORIZED', req);
            return res.status(403).json({ error: 'Admin access denied. Invalid key.' });
        }
        next();
    };

    // ==========================================
    // API: Step 1 - Send Mobile OTP
    // ==========================================
    app.post('/api/send-otp', otpLimiter, validateMobile, handleValidationErrors, async (req, res) => {
        try {
            const { mobile } = req.body;
            await log('OTP_REQUESTED', req, { mobile: `****${mobile.slice(-4)}` });

            const rawOTP = Math.floor(100000 + Math.random() * 900000).toString();
            const salt = await bcrypt.genSalt(12); // Increased rounds from 10 to 12
            const hashedOTP = await bcrypt.hash(rawOTP, salt);

            await OTP.findOneAndUpdate(
                { mobile },
                { otpHash: hashedOTP, expiresAt: Date.now() + 5 * 60 * 1000, purpose: 'login', attempts: 0 },
                { upsert: true, new: true }
            );

            if (process.env.TWILIO_ACCOUNT_SID && !['your_actual_twilio_account_sid','your_twilio_sid_here'].includes(process.env.TWILIO_ACCOUNT_SID)) {
                try {
                    const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
                    await client.messages.create({
                        body: `[National e-Voting] Your OTP is ${rawOTP}. DO NOT share. Valid 5 mins.`,
                        from: process.env.TWILIO_SMS_NUMBER,
                        to: `+91${mobile}`
                    });
                    console.log(`\n✅ [REAL SMS SENT] → +91${mobile.substring(0,2)}****${mobile.slice(-2)}`);
                    return res.json({ success: true, message: `OTP sent to +91******${mobile.slice(-4)}.`, smsSent: true });
                } catch (twilioErr) {
                    console.log(`\n⚠️ Twilio SMS failed: ${twilioErr.message}`);
                    console.log(`🔒 [FALLBACK OTP]: ${rawOTP}`);
                    await log('OTP_SMS_FAILED', req, { error: twilioErr.message });
                    return res.json({ success: true, simulatedOtp: rawOTP, smsFailed: true, smsError: 'Verify number on Twilio dashboard.' });
                }
            } else {
                console.log(`\n🔒 [SIMULATED OTP]: ${rawOTP}`);
                return res.json({ success: true, simulatedOtp: rawOTP });
            }
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'OTP dispatch failure.' });
        }
    });

    // ==========================================
    // API: Step 2 - Verify Mobile OTP
    // ==========================================
    app.post('/api/verify-otp', validateOtp, handleValidationErrors, async (req, res) => {
        try {
            const { mobile, otp } = req.body;
            const record = await OTP.findOne({ mobile, purpose: 'login' });

            if (!record) return res.status(404).json({ error: 'OTP not found. Request a new one.' });
            if (Date.now() > record.expiresAt) {
                await OTP.deleteOne({ mobile });
                await log('OTP_EXPIRED', req);
                return res.status(403).json({ error: 'OTP expired. Request a new one.' });
            }

            // SECURITY: Block after 5 wrong attempts
            if (record.attempts >= 5) {
                await OTP.deleteOne({ mobile });
                await log('OTP_BRUTE_FORCE_BLOCKED', req);
                return res.status(429).json({ error: 'Too many wrong OTP attempts. Request a new OTP.' });
            }

            const isValid = await bcrypt.compare(otp, record.otpHash);
            if (!isValid) {
                await OTP.findOneAndUpdate({ mobile }, { $inc: { attempts: 1 } });
                await log('OTP_WRONG_ATTEMPT', req, { attemptNo: record.attempts + 1 });
                return res.status(401).json({ error: `Incorrect OTP. ${4 - record.attempts} attempts remaining.` });
            }

            await OTP.deleteOne({ mobile });
            await log('OTP_VERIFIED', req);

            const token = jwt.sign({ mobile }, process.env.JWT_SECRET_KEY, { expiresIn: '15m' });
            res.json({ success: true, token });
        } catch (err) {
            res.status(500).json({ error: 'OTP verification failure.' });
        }
    });

    // ==========================================
    // API: Step 3 - Validate Documents
    // ==========================================
    app.post('/api/validate-documents', authenticateJWT, validateDocuments, handleValidationErrors, async (req, res) => {
        try {
            const { aadhaar, pan, voterId } = req.body;

            const aadhaarResult = validateAadhaar(aadhaar);
            if (!aadhaarResult.valid) return res.status(400).json({ error: `UIDAI: ${aadhaarResult.reason}`, field: 'aadhaar' });

            const panResult = validatePAN(pan);
            if (!panResult.valid) return res.status(400).json({ error: `IT DEPT: ${panResult.reason}`, field: 'pan' });

            const voterResult = validateVoterId(voterId);
            if (!voterResult.valid) return res.status(400).json({ error: `ECI: ${voterResult.reason}`, field: 'voterId' });

            // Triple de-duplication check
            const aadhaarHash = crypto.createHash('sha256').update(aadhaar).digest('hex');
            const panHash = crypto.createHash('sha256').update(pan).digest('hex');
            const epicHash = crypto.createHash('sha256').update(voterId).digest('hex');

            if (await Voter.findOne({ aadhaarHash })) {
                await log('DUPLICATE_AADHAAR', req);
                return res.status(403).json({ error: 'This Aadhaar has already voted. One citizen, one vote.' });
            }
            if (await Voter.findOne({ panHash })) {
                await log('DUPLICATE_PAN', req);
                return res.status(403).json({ error: 'This PAN is linked to an existing ballot.' });
            }
            if (await Voter.findOne({ epicHash })) {
                await log('DUPLICATE_EPIC', req);
                return res.status(403).json({ error: 'This Voter ID has already been used.' });
            }

            const govRecord = lookupGovernmentRecords(aadhaar, pan, voterId);

            // KYC OTP
            const kycOTP = Math.floor(100000 + Math.random() * 900000).toString();
            const salt = await bcrypt.genSalt(12);
            const hashedKycOTP = await bcrypt.hash(kycOTP, salt);
            const kycMobile = `kyc_${aadhaarHash.substring(0,16)}`;

            await OTP.findOneAndUpdate(
                { mobile: kycMobile },
                { otpHash: hashedKycOTP, expiresAt: Date.now() + 5 * 60 * 1000, purpose: 'kyc_verify', attempts: 0, kycData: { aadhaarHash, panHash, epicHash, voter: voterId } },
                { upsert: true, new: true }
            );

            console.log(`\n🏛️  [GOVERNMENT KYC OTP]: ${kycOTP}`);
            await log('DOCUMENTS_VALIDATED', req, { voter: voterId });

            res.json({
                success: true,
                maskedMobile: govRecord.maskedMobile,
                maskedEmail: govRecord.maskedEmail,
                kycRef: kycMobile,
                entityType: panResult.entityType,
                simulatedKycOtp: kycOTP
            });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Document validation failure.' });
        }
    });

    // ==========================================
    // API: Step 4 - Verify KYC OTP
    // ==========================================
    app.post('/api/verify-kyc-otp', authenticateJWT, async (req, res) => {
        try {
            const { kycRef, otp } = req.body;

            if (!kycRef || typeof kycRef !== 'string' || !kycRef.startsWith('kyc_')) {
                return res.status(400).json({ error: 'Invalid KYC reference.' });
            }
            if (!otp || !/^\d{6}$/.test(otp)) {
                return res.status(400).json({ error: 'KYC OTP must be 6 digits.' });
            }

            const record = await OTP.findOne({ mobile: kycRef, purpose: 'kyc_verify' });
            if (!record) return res.status(404).json({ error: 'KYC OTP expired. Re-verify documents.' });
            if (Date.now() > record.expiresAt) {
                await OTP.deleteOne({ mobile: kycRef });
                return res.status(403).json({ error: 'KYC OTP expired.' });
            }
            if (record.attempts >= 5) {
                await OTP.deleteOne({ mobile: kycRef });
                await log('KYC_OTP_BRUTE_FORCE_BLOCKED', req);
                return res.status(429).json({ error: 'Too many wrong KYC OTP attempts.' });
            }

            const isValid = await bcrypt.compare(otp, record.otpHash);
            if (!isValid) {
                await OTP.findOneAndUpdate({ mobile: kycRef }, { $inc: { attempts: 1 } });
                return res.status(401).json({ error: `KYC OTP incorrect. ${4 - record.attempts} attempts remaining.` });
            }

            const kycToken = jwt.sign(
                { ...req.user, kycVerified: true, kycData: record.kycData },
                process.env.JWT_SECRET_KEY,
                { expiresIn: '10m' }
            );

            await OTP.deleteOne({ mobile: kycRef });
            await log('KYC_VERIFIED', req);

            res.json({ success: true, kycToken });
        } catch (err) {
            res.status(500).json({ error: 'KYC verification failure.' });
        }
    });

    // ==========================================
    // API: Check Voter (legacy compatibility)
    // ==========================================
    app.post('/api/check-voter', authenticateJWT, async (req, res) => {
        try {
            const { voterId } = req.body;
            if (!voterId || typeof voterId !== 'string') return res.status(400).json({ error: 'Invalid voter ID.' });
            const existingVoter = await Voter.findOne({ voterId });
            res.json({ hasVoted: !!existingVoter });
        } catch (err) {
            res.status(500).json({ error: 'Database error.' });
        }
    });

    // ==========================================
    // API: Step 5 - Cast Vote (with Selfie + Triple Dedup + IP Logging)
    // ==========================================
    app.post('/api/vote', authenticateJWT, voteLimiter, async (req, res) => {
        try {
            const { candidateId, selfieData } = req.body;

            const kycData = req.user.kycData;
            if (!req.user.kycVerified || !kycData) {
                await log('VOTE_REJECTED_NO_KYC', req);
                return res.status(403).json({ error: 'KYC verification incomplete.' });
            }
            if (!selfieData || typeof selfieData !== 'string' || !selfieData.startsWith('data:image')) {
                return res.status(400).json({ error: 'Valid live selfie image is required.' });
            }
            const validCandidates = ['bjp', 'inc', 'aap', 'nota'];
            if (!validCandidates.includes(candidateId)) {
                return res.status(400).json({ error: 'Invalid candidate selection.' });
            }

            const { aadhaarHash, panHash, epicHash, voter } = kycData;
            const ip = req.ip || req.connection?.remoteAddress || 'unknown';
            const ipHash = hashIP(ip);

            // Final triple de-duplication at vote time
            if (await Voter.findOne({ aadhaarHash })) return res.status(403).json({ error: 'FATAL: Aadhaar already voted. ONE PERSON, ONE VOTE.' });
            if (await Voter.findOne({ panHash })) return res.status(403).json({ error: 'FATAL: PAN already voted.' });
            if (await Voter.findOne({ epicHash })) return res.status(403).json({ error: 'FATAL: Voter ID already voted.' });

            const selfieHash = crypto.createHash('sha256').update(selfieData.substring(0, 500)).digest('hex');
            const uniqueVoterId = `VOTER_${voter}_${aadhaarHash.substring(0,8)}`;

            await new Voter({ voterId: uniqueVoterId, aadhaarHash, panHash, epicHash, selfieHash, ipHash }).save();
            await new Vote({ candidateId, aadhaarHash, selfieHash, ipHash }).save();

            await log('VOTE_CAST', req, { candidate: candidateId, voter: voter });
            console.log(`\n🗳️  VOTE RECORDED → ${candidateId} | Voter: ${voter} | IP: ${ipHash}\n`);

            res.json({ success: true, message: 'Your vote has been securely recorded.' });
        } catch (err) {
            if (err.code === 11000) {
                await log('VOTE_DUPLICATE_KEY', req);
                return res.status(403).json({ error: 'DUPLICATE DETECTION: Document already used to vote.' });
            }
            console.error(err);
            res.status(500).json({ error: 'Vote commit failure.' });
        }
    });

    // ==========================================
    // API: Public Stats
    // ==========================================
    app.get('/api/stats', async (req, res) => {
        try {
            const stats = await Vote.aggregate([{ $group: { _id: "$candidateId", count: { $sum: 1 } } }]);
            const votesDict = { bjp: 0, inc: 0, aap: 0, nota: 0 };
            stats.forEach(s => { votesDict[s._id] = s.count; });
            res.json(votesDict);
        } catch (err) {
            res.status(500).json({ error: 'Failed to fetch stats.' });
        }
    });

    // ==========================================
    // API: Admin — Wipe DB (NOW PROTECTED with Admin Key)
    // ==========================================
    app.post('/api/wipe', adminLimiter, authenticateAdmin, async (req, res) => {
        try {
            await Vote.deleteMany({});
            await Voter.deleteMany({});
            await OTP.deleteMany({});
            await log('ADMIN_WIPE', req);
            console.log('\n⚠️  ADMIN: Database wiped.\n');
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ error: 'Failed to wipe DB.' });
        }
    });

    // NEW: Admin — View audit logs (protected)
    app.get('/api/audit-logs', adminLimiter, authenticateAdmin, async (req, res) => {
        try {
            const logs = await Audit.find().sort({ timestamp: -1 }).limit(100);
            res.json({ success: true, logs });
        } catch (err) {
            res.status(500).json({ error: 'Failed to fetch audit logs.' });
        }
    });

    // ==========================================
    // 404 Handler
    // ==========================================
    app.use((req, res) => {
        res.status(404).json({ error: 'Endpoint not found.' });
    });

    // ==========================================
    // Global Error Handler (no stack traces in prod)
    // ==========================================
    app.use((err, req, res, next) => {
        console.error(err.stack);
        const isProd = process.env.NODE_ENV === 'production';
        res.status(err.status || 500).json({
            error: isProd ? 'An internal error occurred.' : err.message
        });
    });

    if (!process.env.VERCEL) {
        const PORT = process.env.PORT || 4000;
        app.listen(PORT, () => {
            console.log(`\n🛡️  Backend secured and active on port ${PORT}`);
            console.log(`   Security headers: ✅ Helmet`);
            console.log(`   NoSQL injection guard: ✅ mongoSanitize`);
            console.log(`   XSS protection: ✅ xss-clean`);
            console.log(`   HPP protection: ✅ hpp`);
            console.log(`   Input validation: ✅ express-validator`);
            console.log(`   Audit logging: ✅ Morgan + DB logs`);
            console.log(`   Rate limiting: ✅ Global + Tiered\n`);
        });
    }
})();

module.exports = app;
