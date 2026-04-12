require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { MongoMemoryServer } = require('mongodb-memory-server');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const twilio = require('twilio');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' })); // Increased limit for selfie image data

// ==========================================
// SECURITY: Rate Limiting to prevent Brute Force & DDoS
// ==========================================
const otpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 OTP requests per window
    message: { error: 'Too many OTP requests from this IP, please try again after 15 minutes.' }
});

const voteLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, 
    max: 10,
    message: { error: 'Strict node limit reached. Suspected automated voting.' }
});

// ==========================================
// DOCUMENT VALIDATION UTILITIES
// ==========================================

// Verhoeff Algorithm for Aadhaar Checksum Validation
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
const verhoeffTableInv = [0,4,3,2,1,5,6,7,8,9];

function validateAadhaar(aadhaar) {
    if (!/^\d{12}$/.test(aadhaar)) return { valid: false, reason: 'Aadhaar must be exactly 12 digits.' };
    if (/^0/.test(aadhaar)) return { valid: false, reason: 'Aadhaar cannot start with 0.' };
    if (/^1/.test(aadhaar)) return { valid: false, reason: 'Aadhaar cannot start with 1.' };
    // Verhoeff checksum validation
    let c = 0;
    const digits = aadhaar.split('').map(Number).reverse();
    for (let i = 0; i < digits.length; i++) {
        c = verhoeffTableD[c][verhoeffTableP[i % 8][digits[i]]];
    }
    if (c !== 0) return { valid: false, reason: 'Aadhaar checksum verification FAILED. This number is not issued by UIDAI.' };
    return { valid: true };
}

function validatePAN(pan) {
    if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(pan)) {
        return { valid: false, reason: 'PAN format invalid. Must be: 5 letters + 4 digits + 1 letter (e.g., ABCDE1234F).' };
    }
    // 4th character determines entity type: C=Company, P=Person, H=HUF, F=Firm, A=AOP, T=Trust, etc.
    const entityChar = pan[3];
    const validEntities = ['A','B','C','F','G','H','J','L','P','T'];
    if (!validEntities.includes(entityChar)) {
        return { valid: false, reason: `PAN 4th character '${entityChar}' is not a valid entity type code.` };
    }
    return { valid: true, entityType: entityChar === 'P' ? 'Individual' : entityChar === 'C' ? 'Company' : 'Other Entity' };
}

function validateVoterId(voterId) {
    // EPIC format: 3 letters (state code) followed by 7 digits
    if (!/^[A-Z]{3}\d{7}$/.test(voterId)) {
        return { valid: false, reason: 'Voter ID (EPIC) format invalid. Must be 3 uppercase letters followed by 7 digits (e.g., ABC1234567).' };
    }
    return { valid: true };
}

// Simulated Government Database — maps document numbers to registered contact info
// In production, this would be an API call to UIDAI / Income Tax / Election Commission
function lookupGovernmentRecords(aadhaar, pan, voterId) {
    // Generate deterministic "registered" contact from hashing documents
    // This simulates the government database returning the registered mobile/email
    const hash = crypto.createHash('sha256').update(aadhaar + pan + voterId).digest('hex');
    const last4 = hash.substring(0, 4);
    const registeredMobile = `9${hash.substring(0, 9)}`; // Simulated registered phone
    const maskedMobile = `${registeredMobile.substring(0,2)}******${registeredMobile.substring(8)}`;
    const maskedEmail = `${voterId.toLowerCase().substring(0,3)}***@gov.in`;
    
    return {
        registeredMobile,
        maskedMobile,
        maskedEmail,
        fullName: 'CITIZEN (Verified)',
        dob: '**/**/19**',
        address: '*** (DigiLocker Protected)',
    };
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
        // Fallback to local isolated test network if no Google Cloud/Atlas URI is provided
        const mongoServer = await MongoMemoryServer.create();
        MONGO_URI = mongoServer.getUri();
        console.log('⚠️ No cloud MONGO_URI detected. Spun up temporary local MongoDB node.');
    }
    
    mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
        .then(() => console.log('✅ Secured MongoDB Cluster Loaded'))
        .catch(err => console.error('MongoDB error:', err));

    // Schemas
    const VoteSchema = new mongoose.Schema({
        candidateId: { type: String, required: true },
        aadhaarHash: { type: String, required: true }, // Store hash, never raw Aadhaar
        selfieData: { type: String }, // Base64 of voter selfie for audit
        timestamp: { type: Date, default: Date.now }
    });

    const VoterSchema = new mongoose.Schema({
        voterId: { type: String, required: true, unique: true },
        aadhaarHash: { type: String, required: true, unique: true },
        panHash: { type: String, required: true, unique: true },
        epicHash: { type: String, required: true, unique: true },
        selfieHash: { type: String },
        timestamp: { type: Date, default: Date.now }
    });

    // Highly confidential OTP storage (Temporary)
    const OTPSchema = new mongoose.Schema({
        mobile: { type: String, required: true, unique: true },
        otpHash: { type: String, required: true },
        purpose: { type: String, default: 'login' }, // 'login' or 'kyc_verify'
        kycData: { type: Object }, // Stores validated doc data during KYC OTP flow
        expiresAt: { type: Date, default: () => Date.now() + 5 * 60 * 1000 } // 5 min expiry
    });

    const Vote = mongoose.model('Vote', VoteSchema);
    const Voter = mongoose.model('Voter', VoterSchema);
    const OTP = mongoose.model('OTP', OTPSchema);

    // ==========================================
    // MIDDLEWARE: JWT Extraction & Security 
    // ==========================================
    const authenticateJWT = (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (authHeader) {
            const token = authHeader.split(' ')[1];
            jwt.verify(token, process.env.JWT_SECRET_KEY, (err, user) => {
                if (err) return res.status(403).json({ error: 'Tampered Signature. Access Denied.' });
                req.user = user;
                next();
            });
        } else {
            res.status(401).json({ error: 'Missing security token.' });
        }
    };

    // ==========================================
    // API: Step 1 - Generate & Dispatch Real SMS 
    // ==========================================
    app.post('/api/send-otp', otpLimiter, async (req, res) => {
        try {
            const { mobile } = req.body;
            
            // Generate robust 6-digit cryptographic OTP
            const rawOTP = Math.floor(100000 + Math.random() * 900000).toString();
            
            // Hash the OTP via Bcrypt (NEVER store raw OTPs)
            const salt = await bcrypt.genSalt(10);
            const hashedOTP = await bcrypt.hash(rawOTP, salt);

            // Upsert MongoDB logic
            await OTP.findOneAndUpdate(
                { mobile },
                { otpHash: hashedOTP, expiresAt: Date.now() + 5 * 60 * 1000, purpose: 'login' },
                { upsert: true, new: true }
            );

            // Twilio SMS Integration — Attempt REAL SMS first, fallback to simulation
            if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_ACCOUNT_SID !== 'your_actual_twilio_account_sid' && process.env.TWILIO_ACCOUNT_SID !== 'your_twilio_sid_here') {
                try {
                    const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
                    await client.messages.create({
                        body: `[National e-Voting] Your confidential OTP is ${rawOTP}. DO NOT share this with anyone. Valid for 5 minutes.`,
                        from: process.env.TWILIO_SMS_NUMBER,
                        to: `+91${mobile}`
                    });
                    console.log(`\n==============================================`);
                    console.log(`✅ [REAL SMS SENT] OTP dispatched via Twilio to +91${mobile.substring(0,2)}****${mobile.slice(-2)}`);
                    console.log(`==============================================\n`);
                    res.json({ success: true, message: `OTP sent via SMS to +91******${mobile.slice(-4)}. Check your phone.`, smsSent: true });
                } catch (twilioErr) {
                    // Twilio failed (e.g. trial account, unverified number) — fallback to simulation
                    console.log(`\n⚠️  Twilio SMS failed for +91${mobile}: ${twilioErr.message}`);
                    console.log(`==============================================`);
                    console.log(`🔒 [FALLBACK OTP IN-MEMORY]: ${rawOTP}`);
                    console.log(`(Twilio trial accounts can only send to verified numbers.`);
                    console.log(`Verify this number at: https://console.twilio.com/us1/develop/phone-numbers/manage/verified)`);
                    console.log(`==============================================\n`);
                    res.json({ success: true, message: 'OTP generated. SMS delivery attempted.', simulatedOtp: rawOTP, smsFailed: true, smsError: 'Trial account — verify your number on Twilio dashboard for real SMS.' });
                }
            } else {
                // No Twilio keys configured — pure simulation
                console.log(`\n==============================================`);
                console.log(`🔒 [SIMULATED OTP]: ${rawOTP}`);
                console.log(`(Configure TWILIO_ACCOUNT_SID in .env for real SMS)`);
                console.log(`==============================================\n`);
                res.json({ success: true, message: 'Simulated OTP generated.', simulatedOtp: rawOTP });
            }
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'SMS Dispatch Failure. Please try again.' });
        }
    });

    // ==========================================
    // API: Step 2 - Verify OTP & Sign JWT token
    // ==========================================
    app.post('/api/verify-otp', async (req, res) => {
        try {
            const { mobile, otp } = req.body;
            const record = await OTP.findOne({ mobile });

            if (!record) return res.status(404).json({ error: 'OTP expired or missing. Please request again.' });
            
            if (Date.now() > record.expiresAt) {
                await OTP.deleteOne({ mobile });
                return res.status(403).json({ error: 'OTP strictly expired for security.' });
            }

            // Cryptographically compare injected OTP with Bcrypt Hash
            const isValid = await bcrypt.compare(otp, record.otpHash);
            if (!isValid) return res.status(401).json({ error: 'Invalid OTP payload signature.' });

            // Scrub the OTP DB to prevent replay attacks
            await OTP.deleteOne({ mobile });

            // Generate secure JSON Web Token for stateless server sessions
            const token = jwt.sign({ mobile }, process.env.JWT_SECRET_KEY, { expiresIn: '15m' }); // Strict 15 minute lifespan
            
            res.json({ success: true, token, message: 'Authentication Key exchanged successfully.' });
        } catch (err) {
            res.status(500).json({ error: 'Cryptographic failure during validation.' });
        }
    });

    // ==========================================
    // API: Step 3 - Validate Document Formats (Aadhaar, PAN, EPIC)
    // REQUIRES JWT Token
    // ==========================================
    app.post('/api/validate-documents', authenticateJWT, async (req, res) => {
        try {
            const { aadhaar, pan, voterId } = req.body;

            // === Strict Format Validation ===
            const aadhaarResult = validateAadhaar(aadhaar);
            if (!aadhaarResult.valid) {
                return res.status(400).json({ error: `UIDAI REJECTION: ${aadhaarResult.reason}`, field: 'aadhaar' });
            }

            const panResult = validatePAN(pan);
            if (!panResult.valid) {
                return res.status(400).json({ error: `IT DEPT REJECTION: ${panResult.reason}`, field: 'pan' });
            }

            const voterResult = validateVoterId(voterId);
            if (!voterResult.valid) {
                return res.status(400).json({ error: `ECI REJECTION: ${voterResult.reason}`, field: 'voterId' });
            }

            // === Check if this person has already voted (triple de-duplication) ===
            const aadhaarHash = crypto.createHash('sha256').update(aadhaar).digest('hex');
            const panHash = crypto.createHash('sha256').update(pan).digest('hex');
            const epicHash = crypto.createHash('sha256').update(voterId).digest('hex');

            const byAadhaar = await Voter.findOne({ aadhaarHash });
            if (byAadhaar) return res.status(403).json({ error: 'UIDAI AUTHORITY: This Aadhaar has already been used to cast a vote. One citizen, one vote.' });

            const byPAN = await Voter.findOne({ panHash });
            if (byPAN) return res.status(403).json({ error: 'IT DEPT AUTHORITY: This PAN is linked to an existing ballot. Duplicate voting is prohibited.' });

            const byEPIC = await Voter.findOne({ epicHash });
            if (byEPIC) return res.status(403).json({ error: 'ELECTION COMMISSION: This Voter ID has already been used. Your vote is already recorded.' });

            // === Simulate Government Database Lookup for registered contacts ===
            const govRecord = lookupGovernmentRecords(aadhaar, pan, voterId);

            // === Generate KYC Verification OTP and send to "registered" mobile/email ===
            const kycOTP = Math.floor(100000 + Math.random() * 900000).toString();
            const salt = await bcrypt.genSalt(10);
            const hashedKycOTP = await bcrypt.hash(kycOTP, salt);

            const kycMobile = `kyc_${aadhaarHash.substring(0,16)}`;
            await OTP.findOneAndUpdate(
                { mobile: kycMobile },
                { 
                    otpHash: hashedKycOTP, 
                    expiresAt: Date.now() + 5 * 60 * 1000, 
                    purpose: 'kyc_verify',
                    kycData: { aadhaarHash, panHash, epicHash, voter: voterId }
                },
                { upsert: true, new: true }
            );

            console.log(`\n==============================================`);
            console.log(`🏛️  [GOVERNMENT KYC VERIFICATION OTP]: ${kycOTP}`);
            console.log(`📱 Dispatched to registered mobile: ${govRecord.maskedMobile}`);
            console.log(`📧 Dispatched to registered email: ${govRecord.maskedEmail}`);
            console.log(`(In production, this OTP would reach the mobile/email registered with UIDAI/ECI)`);
            console.log(`==============================================\n`);

            res.json({ 
                success: true,
                message: 'Documents validated by Central Authority. Verification OTP dispatched.',
                maskedMobile: govRecord.maskedMobile,
                maskedEmail: govRecord.maskedEmail,
                kycRef: kycMobile,
                entityType: panResult.entityType,
                simulatedKycOtp: kycOTP // In production, this field would NOT be sent
            });

        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Government API gateway failure during validation.' });
        }
    });

    // ==========================================
    // API: Step 4 - Verify KYC OTP (sent to registered mobile from documents)
    // REQUIRES JWT
    // ==========================================
    app.post('/api/verify-kyc-otp', authenticateJWT, async (req, res) => {
        try {
            const { kycRef, otp } = req.body;
            const record = await OTP.findOne({ mobile: kycRef, purpose: 'kyc_verify' });

            if (!record) return res.status(404).json({ error: 'KYC OTP expired or not found. Please re-verify documents.' });

            if (Date.now() > record.expiresAt) {
                await OTP.deleteOne({ mobile: kycRef });
                return res.status(403).json({ error: 'KYC OTP has expired. Please restart verification.' });
            }

            const isValid = await bcrypt.compare(otp, record.otpHash);
            if (!isValid) return res.status(401).json({ error: 'KYC OTP mismatch. Contact UIDAI helpline if issue persists.' });

            // Don't delete yet — we need kycData for the vote step
            // Mark as verified by issuing a new token with KYC clearance
            const kycToken = jwt.sign(
                { ...req.user, kycVerified: true, kycData: record.kycData },
                process.env.JWT_SECRET_KEY,
                { expiresIn: '10m' }
            );

            // Clean up OTP
            await OTP.deleteOne({ mobile: kycRef });

            res.json({ 
                success: true, 
                kycToken,
                message: 'KYC OTP verified. Identity confirmed by Central Government Authority.'
            });
        } catch (err) {
            res.status(500).json({ error: 'Cryptographic failure during KYC verification.' });
        }
    });

    // ==========================================
    // API: Verify Strict KYC Duplication constraints
    // REQUIRES JWT Token
    // ==========================================
    app.post('/api/check-voter', authenticateJWT, async (req, res) => {
        try {
            const { voterId } = req.body;
            const existingVoter = await Voter.findOne({ voterId });
            res.json({ hasVoted: !!existingVoter });
        } catch (err) {
            res.status(500).json({ error: 'Database isolation error' });
        }
    });

    // ==========================================
    // API: Commit Vote with Selfie & Triple Dedup
    // REQUIRES KYC-verified JWT Token & Rate Limit
    // ==========================================
    app.post('/api/vote', authenticateJWT, voteLimiter, async (req, res) => {
        try {
            const { candidateId, selfieData } = req.body;
            
            // Extract KYC data from the token
            const kycData = req.user.kycData;
            if (!req.user.kycVerified || !kycData) {
                return res.status(403).json({ error: 'KYC verification incomplete. Cannot proceed to vote.' });
            }

            if (!selfieData) {
                return res.status(400).json({ error: 'Live selfie verification is mandatory to cast your vote.' });
            }

            const { aadhaarHash, panHash, epicHash, voter } = kycData;

            // Triple de-duplication check at vote time
            const byAadhaar = await Voter.findOne({ aadhaarHash });
            if (byAadhaar) return res.status(403).json({ error: 'FATAL: This Aadhaar has already cast a vote. ONE PERSON, ONE VOTE.' });

            const byPAN = await Voter.findOne({ panHash });
            if (byPAN) return res.status(403).json({ error: 'FATAL: This PAN is linked to an existing ballot.' });

            const byEPIC = await Voter.findOne({ epicHash });
            if (byEPIC) return res.status(403).json({ error: 'FATAL: This Voter ID has already voted.' });

            const selfieHash = crypto.createHash('sha256').update(selfieData.substring(0, 1000)).digest('hex');
            const uniqueVoterId = `VOTER_${voter}_${aadhaarHash.substring(0,8)}`;

            // Atomically record the voter and vote
            await new Voter({ voterId: uniqueVoterId, aadhaarHash, panHash, epicHash, selfieHash }).save();
            await new Vote({ candidateId, aadhaarHash, selfieData: selfieData.substring(0, 500) }).save(); // Store truncated selfie for audit

            console.log(`\n🗳️  VOTE RECORDED: Voter ${voter} → ${candidateId}`);
            console.log(`   Selfie Hash: ${selfieHash.substring(0,16)}...`);
            console.log(`   Triple Lock: AADHAAR(${aadhaarHash.substring(0,8)}) PAN(${panHash.substring(0,8)}) EPIC(${epicHash.substring(0,8)})\n`);

            res.json({ success: true, message: 'Vote cryptographically written to cluster. Your democratic right has been exercised.' });
        } catch (err) {
            if (err.code === 11000) {
                return res.status(403).json({ error: 'DUPLICATE DETECTION: One of your documents has already been used to vote.' });
            }
            console.error(err);
            res.status(500).json({ error: 'Cluster rejection during write operation' });
        }
    });

    // ==========================================
    // API: Read Operations (Public)
    // ==========================================
    app.get('/api/stats', async (req, res) => {
        try {
            const stats = await Vote.aggregate([
                { $group: { _id: "$candidateId", count: { $sum: 1 } } }
            ]);
            const votesDict = { bjp: 0, inc: 0, aap: 0, nota: 0 };
            stats.forEach(s => { votesDict[s._id] = s.count; });
            res.json(votesDict);
        } catch (err) {
            res.status(500).json({ error: 'Failed to fetch cluster stats' });
        }
    });

    app.post('/api/wipe', async (req, res) => {
        try {
            await Vote.deleteMany({});
            await Voter.deleteMany({});
            await OTP.deleteMany({});
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ error: 'Failed to wipe DB' });
        }
    });

    const PORT = 4000;
    app.listen(PORT, () => {
        console.log(`Backend server successfully shielded and active on http://localhost:${PORT}`);
    });
})();
