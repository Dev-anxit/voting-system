const { useState, useEffect, useRef, useCallback } = React;

const candidates = [
    { id: 'bjp', name: 'Bharatiya Janata Party (BJP)', shortName: 'BJP', image: 'https://upload.wikimedia.org/wikipedia/commons/0/03/Bharatiya_Janata_Party_%28icon%29.svg', color: '#ff9933' },
    { id: 'inc', name: 'Indian National Congress (INC)', shortName: 'Congress', image: 'https://upload.wikimedia.org/wikipedia/commons/6/6c/Indian_National_Congress_hand_logo.svg', color: '#00BFFF' },
    { id: 'aap', name: 'Aam Aadmi Party (AAP)', shortName: 'AAP', image: 'https://upload.wikimedia.org/wikipedia/commons/6/65/Aam_Aadmi_Party_logo_%28English%29.svg', color: '#0055A4' },
    { id: 'nota', name: 'None of the Above (NOTA)', shortName: 'NOTA', image: 'https://upload.wikimedia.org/wikipedia/commons/f/f6/NOTA_Option_Logo.svg', color: '#9CA3AF' }
];

const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
    ? 'http://localhost:4005/api' 
    : '/api';

// Views: login → login_otp → verification → kyc_otp → selfie → voting → success → results

function App() {
    const [view, setView] = useState('login');
    const [mobile, setMobile] = useState('');
    const [otp, setOtp] = useState('');
    
    // KYC Documents
    const [aadhaar, setAadhaar] = useState('');
    const [pan, setPan] = useState('');
    const [voterId, setVoterId] = useState('');
    const [userInputCaptcha, setUserInputCaptcha] = useState('');
    const [captcha, setCaptcha] = useState('');

    // KYC OTP flow
    const [kycOtp, setKycOtp] = useState('');
    const [kycRef, setKycRef] = useState('');
    const [maskedMobile, setMaskedMobile] = useState('');
    const [maskedEmail, setMaskedEmail] = useState('');

    // Selfie
    const [selfieData, setSelfieData] = useState(null);
    const [cameraActive, setCameraActive] = useState(false);
    const videoRef = useRef(null);
    const canvasRef = useRef(null);
    const streamRef = useRef(null);

    // Loading state
    const [isLoading, setIsLoading] = useState(false);

    const handlePanChange = (e) => {
        const val = e.target.value.toUpperCase();
        let res = '';
        for (let i = 0; i < val.length && i < 10; i++) {
            if (i < 5 || i === 9) {
                if (/[A-Z]/.test(val[i])) res += val[i];
            } else {
                if (/[0-9]/.test(val[i])) res += val[i];
            }
        }
        setPan(res);
    };

    const handleVoterIdChange = (e) => {
        const val = e.target.value.toUpperCase();
        let res = '';
        for (let i = 0; i < val.length && i < 10; i++) {
            if (i < 3) {
                if (/[A-Z]/.test(val[i])) res += val[i];
            } else {
                if (/[0-9]/.test(val[i])) res += val[i];
            }
        }
        setVoterId(res);
    };

    const generateCaptcha = () => {
        const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        let result = '';
        for (let i = 0; i < 6; i++) result += chars[Math.floor(Math.random() * chars.length)];
        setCaptcha(result);
    };

    useEffect(() => {
        generateCaptcha();
    }, []);

    const [toast, setToast] = useState(null);
    const [authenticatedVoter, setAuthenticatedVoter] = useState(null);
    const [otpHintVisible, setOtpHintVisible] = useState(false);
    const otpHintTimerRef = useRef(null);

    const showOtpHint = () => {
        setOtpHintVisible(true);
        if (otpHintTimerRef.current) clearTimeout(otpHintTimerRef.current);
        otpHintTimerRef.current = setTimeout(() => setOtpHintVisible(false), 6000);
    };
    
    // Security Tokens
    const [jwtToken, setJwtToken] = useState(null);
    const [kycToken, setKycToken] = useState(null);

    const [votes, setVotes] = useState({ bjp: 0, inc: 0, aap: 0, nota: 0 });

    const fetchStats = async (adminKey) => {
        if (!adminKey) return;
        try {
            const res = await fetch(`${API_BASE}/stats`, {
                headers: { 'x-admin-key': adminKey }
            });
            if (res.ok) {
                const data = await res.json();
                setVotes(prev => ({...prev, ...data}));
                return true;
            } else {
                const data = await res.json();
                showToast(data.error || 'Unauthorized', 'error');
                return false;
            }
        } catch (err) {
            showToast('Failed to connect to stats server.', 'error');
            return false;
        }
    };

    // Removed automatic stats polling for privacy
    useEffect(() => {
        // Stats are only fetched when admin logs in
    }, []);

    const showToast = (message, type = 'success') => {
        setToast({ message, type });
        setTimeout(() => setToast(null), 4000);
    };

    // ==========================================
    // STEP 1: Login with Mobile + Captcha
    // ==========================================
    const handleLogin = async (e) => {
        e.preventDefault();
        if (mobile.length !== 10 || !/^\d+$/.test(mobile)) {
            showToast('Please enter a valid 10-digit mobile number', 'error');
            return;
        }
        if (userInputCaptcha !== captcha) {
            showToast('Invalid Captcha. Please try again.', 'error');
            generateCaptcha();
            setUserInputCaptcha('');
            return;
        }

        setIsLoading(true);
        try {
            const res = await fetch(`${API_BASE}/send-otp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mobile })
            });
            const data = await res.json();

            if (res.ok && data.success) {
                setView('login_otp');
                showToast(`OTP sent successfully!`, 'success');
                showOtpHint();
                console.log("Check server logs for the simulated OTP if testing locally.");
            } else {
                showToast(data.error || 'Failed to send OTP', 'error');
            }
        } catch (err) {
            showToast('Unable to reach authentication server.', 'error');
        }
        setIsLoading(false);
    };

    // ==========================================
    // STEP 2: Verify Login OTP
    // ==========================================
    const handleVerifyLoginOTP = async (e) => {
        e.preventDefault();
        if (otp.length < 6) {
             showToast('OTP must be 6 digits', 'error');
             return;
        }

        setIsLoading(true);
        try {
            const res = await fetch(`${API_BASE}/verify-otp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mobile, otp })
            });
            const data = await res.json();

            if (res.ok && data.success) {
                showToast('Mobile verified successfully!', 'success');
                setJwtToken(data.token);
                setView('verification');
                setOtp('');
            } else {
                showToast(data.error || 'OTP verification failed', 'error');
            }
        } catch(err) {
            showToast('Server communication error.', 'error');
        }
        setIsLoading(false);
    };

    // ==========================================
    // STEP 3: Submit Documents for Validation
    // ==========================================
    const handleVerifyDocuments = async (e) => {
        e.preventDefault();

        setIsLoading(true);
        try {
            const res = await fetch(`${API_BASE}/validate-documents`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${jwtToken}`
                },
                body: JSON.stringify({ aadhaar, pan, voterId })
            });

            const data = await res.json();
            
            if (res.status === 400) {
                showToast(data.error, 'error');
                setIsLoading(false);
                return;
            }

            if (res.status === 401 || res.status === 403) {
                 showToast(data.error || 'Authorization error', 'error');
                 setIsLoading(false);
                 return;
            }

            if (res.ok && data.success) {
                showToast('Documents verified! OTP sent to registered contacts.', 'success');
                setKycRef(data.kycRef);
                setMaskedMobile(data.maskedMobile);
                setMaskedEmail(data.maskedEmail);
                setView('kyc_otp');
                showOtpHint();
                console.log("KYC OTP generated. Check server logs.");
            } else {
                showToast(data.error || 'Document validation failed', 'error');
            }
        } catch (err) {
            showToast('Government API gateway unreachable.', 'error');
        }
        setIsLoading(false);
    };

    // ==========================================
    // STEP 4: Verify KYC OTP
    // ==========================================
    const handleVerifyKycOtp = async (e) => {
        e.preventDefault();
        if (kycOtp.length < 6) {
            showToast('Enter the 6-digit KYC OTP', 'error');
            return;
        }

        setIsLoading(true);
        try {
            const res = await fetch(`${API_BASE}/verify-kyc-otp`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${jwtToken}`
                },
                body: JSON.stringify({ kycRef, otp: kycOtp })
            });
            const data = await res.json();

            if (res.ok && data.success) {
                showToast('KYC identity confirmed by government authority!', 'success');
                setKycToken(data.kycToken);
                setAuthenticatedVoter(voterId);
                setView('selfie');
            } else {
                showToast(data.error || 'KYC OTP verification failed', 'error');
            }
        } catch(err) {
            showToast('Verification server error.', 'error');
        }
        setIsLoading(false);
    };

    // ==========================================
    // STEP 5: Live Selfie Capture
    // ==========================================
    const startCamera = useCallback(async () => {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ 
                video: { facingMode: 'user', width: 640, height: 480 } 
            });
            streamRef.current = stream;
            if (videoRef.current) {
                videoRef.current.srcObject = stream;
            }
            setCameraActive(true);
        } catch (err) {
            showToast('Camera access denied. Please allow camera permissions.', 'error');
        }
    }, []);

    const capturePhoto = useCallback(() => {
        if (!videoRef.current || !canvasRef.current) return;
        const canvas = canvasRef.current;
        const video = videoRef.current;
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const ctx = canvas.getContext('2d');
        // Mirror the image (selfie mode)
        ctx.translate(canvas.width, 0);
        ctx.scale(-1, 1);
        ctx.drawImage(video, 0, 0);
        const dataUrl = canvas.toDataURL('image/jpeg', 0.8);
        setSelfieData(dataUrl);

        // Stop camera
        if (streamRef.current) {
            streamRef.current.getTracks().forEach(t => t.stop());
        }
        setCameraActive(false);
    }, []);

    const retakePhoto = useCallback(() => {
        setSelfieData(null);
        startCamera();
    }, [startCamera]);

    // Cleanup camera on unmount
    useEffect(() => {
        return () => {
            if (streamRef.current) {
                streamRef.current.getTracks().forEach(t => t.stop());
            }
        };
    }, []);

    // Auto-start camera when entering selfie view
    useEffect(() => {
        if (view === 'selfie' && !selfieData) {
            startCamera();
        }
    }, [view, selfieData, startCamera]);

    // ==========================================
    // STEP 6: Cast Vote with Selfie
    // ==========================================
    const handleVote = async (candidateId, candidateName) => {
        if (!authenticatedVoter || !kycToken || !selfieData) {
            showToast('Verification incomplete.', 'error');
            return;
        }

        setIsLoading(true);
        try {
            const res = await fetch(`${API_BASE}/vote`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${kycToken}`
                },
                body: JSON.stringify({ candidateId, selfieData })
            });

            const data = await res.json();

            if (res.ok && data.success) {
                showToast(`Vote recorded securely!`, 'success');
                setView('success');
            } else {
                showToast(data.error || 'Vote rejected by server.', 'error');
            }
        } catch (err) {
            showToast('Failed to submit vote.', 'error');
        }
        setIsLoading(false);
    };

    const handleLogout = () => {
        if (streamRef.current) {
            streamRef.current.getTracks().forEach(t => t.stop());
        }
        setView('login');
        setMobile('');
        setOtp('');
        setAadhaar('');
        setPan('');
        setVoterId('');
        setKycOtp('');
        setKycRef('');
        setSelfieData(null);
        setCameraActive(false);
        setAuthenticatedVoter(null);
        setJwtToken(null);
        setKycToken(null);
        setUserInputCaptcha('');
        generateCaptcha();
        localStorage.removeItem('admin_key');
    }

    const handleWipeDatabase = async () => {
        if (confirm('⚠️ WARNING: This will permanently erase ALL votes and voter records. Continue?')) {
            let adminKey = localStorage.getItem('admin_key');
            if (!adminKey) {
                adminKey = prompt('Enter Admin Secret Key to authorize this action:');
            }
            if (!adminKey) return;
            try {
                const res = await fetch(`${API_BASE}/wipe`, { 
                    method: 'POST',
                    headers: { 'x-admin-key': adminKey }
                });
                if (res.ok) {
                    showToast('Database wiped clean.', 'success');
                    setVotes({bjp:0, inc:0, aap:0, nota:0});
                } else {
                    const data = await res.json();
                    showToast(data.error || 'Admin authorization failed.', 'error');
                }
            } catch (err) {
                showToast('Could not reach backend.', 'error');
            }
        }
    }

    // Step indicator
    const steps = [
        { id: 'login', label: 'Mobile', icon: 'fa-mobile-alt' },
        { id: 'login_otp', label: 'OTP', icon: 'fa-key' },
        { id: 'verification', label: 'KYC', icon: 'fa-id-card' },
        { id: 'kyc_otp', label: 'Verify', icon: 'fa-shield-alt' },
        { id: 'selfie', label: 'Selfie', icon: 'fa-camera' },
        { id: 'voting', label: 'Vote', icon: 'fa-vote-yea' },
    ];
    const currentStepIdx = steps.findIndex(s => s.id === view);

    return (
        <main className="app-container">
            <header className="header" style={{marginBottom: "1.5rem"}}>
                <h1 className="title" style={{fontSize: "2.5rem"}}>
                    National <span className="highlight">e-Voting</span>
                </h1>
                <p className="subtitle">Secure Mobile & DigiLocker KYC Integration Platform</p>
                <div style={{marginTop: "0.5rem", fontSize: "0.8rem", color: "var(--success-color)", fontWeight: "600"}}>
                    <i className="fas fa-shield-alt"></i> Active End-to-End Encryption
                </div>
            </header>

            {/* Step Progress Bar */}
            {currentStepIdx >= 0 && view !== 'success' && view !== 'results' && (
                <div className="step-progress fade-in">
                    {steps.map((step, idx) => (
                        <div key={step.id} className={`step-item ${idx < currentStepIdx ? 'completed' : ''} ${idx === currentStepIdx ? 'active' : ''}`}>
                            <div className="step-circle">
                                {idx < currentStepIdx ? <i className="fas fa-check"></i> : <i className={`fas ${step.icon}`}></i>}
                            </div>
                            <span className="step-label">{step.label}</span>
                        </div>
                    ))}
                </div>
            )}

            {/* ==================== VIEW: LOGIN ==================== */}
            {view === 'login' && (
                <div className="fade-in form-container">
                    <h2 className="section-heading"><i className="fas fa-lock"></i> Identity Login (Step 1)</h2>
                    <form onSubmit={handleLogin}>
                        <div className="input-group">
                            <label>Registered Mobile Number <span style={{color: "var(--danger-color)"}}>*</span></label>
                            <input 
                                type="text" 
                                placeholder="Enter 10-digit Mobile Number" 
                                maxLength="10"
                                value={mobile}
                                onChange={(e) => setMobile(e.target.value.replace(/\D/g, ''))}
                                className="styled-input"
                                required
                            />
                        </div>
                        
                        <div className="input-group">
                            <label>Verify Identity (Captcha) <span style={{color: "var(--danger-color)"}}>*</span></label>
                            <div className="captcha-container">
                                <div className="captcha-box" onClick={generateCaptcha} title="Click to refresh">
                                    {captcha}
                                </div>
                                <input 
                                    type="text" 
                                    placeholder="Enter Captcha" 
                                    value={userInputCaptcha}
                                    onChange={(e) => setUserInputCaptcha(e.target.value)}
                                    className="styled-input captcha-input"
                                    required
                                />
                            </div>
                        </div>

                        <button type="submit" className="btn btn-primary" disabled={isLoading}>
                            {isLoading ? <><i className="fas fa-spinner fa-spin"></i> Processing...</> : <><i className="fas fa-fingerprint"></i> Generate Security OTP</>}
                        </button>
                    </form>
                    <button onClick={async () => {
                        const key = prompt('Enter Administrative Secret Key to view results:');
                        if (key) {
                            const success = await fetchStats(key);
                            if (success) {
                                localStorage.setItem('admin_key', key);
                                setView('results');
                            }
                        }
                    }} className="btn btn-secondary" style={{marginTop: '1rem', background: 'rgba(255,255,255,0.05)', border: '1px dashed rgba(255,255,255,0.2)'}}>
                        <i className="fas fa-lock"></i> Admin Dashboard
                    </button>
                </div>
            )}

            {/* ==================== VIEW: LOGIN OTP ==================== */}
            {view === 'login_otp' && (
                <div className="fade-in form-container">
                    <h2 className="section-heading"><i className="fas fa-shield-alt"></i> OTP Verification (Step 2)</h2>
                    <p style={{marginBottom: '1.5rem', color: "var(--text-secondary)", lineHeight: "1.5"}}>
                        A 6-digit OTP has been sent to <strong style={{color:"white"}}>******{mobile.substring(6,10)}</strong>.
                    </p>
                    <form onSubmit={handleVerifyLoginOTP}>
                        <div className="input-group">
                            <label>One Time Password</label>
                            <input 
                                type="text" 
                                placeholder="Enter 6-digit OTP" 
                                maxLength="6"
                                value={otp}
                                onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))}
                                className="styled-input"
                                style={{letterSpacing: '8px', textAlign: 'center', fontSize: '1.3rem', fontWeight: '700'}}
                                required
                            />
                        </div>
                        <button type="submit" className="btn btn-primary" disabled={isLoading}>
                            {isLoading ? <><i className="fas fa-spinner fa-spin"></i> Verifying...</> : <><i className="fas fa-key"></i> Verify OTP</>}
                        </button>
                        <button type="button" onClick={() => setView('login')} className="btn btn-secondary" style={{marginTop: '1rem'}}>
                            <i className="fas fa-arrow-left"></i> Back
                        </button>
                    </form>
                </div>
            )}

            {/* ==================== VIEW: KYC DOCUMENT VERIFICATION ==================== */}
            {view === 'verification' && (
                <div className="fade-in form-container">
                    <div className="auth-banner">
                        <i className="fas fa-fingerprint"></i> 
                        Mobile Verified: {mobile.substring(0,2)}******{mobile.substring(8,10)}
                    </div>
                    <h2 className="section-heading"><i className="fas fa-id-card"></i> KYC Document Verification (Step 3)</h2>
                    <div className="info-box">
                        <i className="fas fa-info-circle"></i>
                        <p>Your documents will be verified against <strong>UIDAI</strong>, <strong>Income Tax Dept</strong>, and <strong>Election Commission</strong> databases. An OTP will be sent to the <strong>mobile number & email registered</strong> with your official documents.</p>
                    </div>
                    <form onSubmit={handleVerifyDocuments}>
                        <div className="input-group">
                            <label><i className="fas fa-address-card" style={{marginRight:'6px',color:'#f59e0b'}}></i>Aadhaar Number (UIDAI) <span style={{color: "var(--danger-color)"}}>*</span></label>
                            <input 
                                type="text" 
                                placeholder="Enter 12-digit Aadhaar Number" 
                                maxLength="12"
                                value={aadhaar}
                                onChange={(e) => setAadhaar(e.target.value.replace(/\D/g, ''))}
                                className="styled-input"
                                required
                            />
                            <small style={{color:'var(--text-secondary)', marginTop:'4px', fontSize:'0.75rem'}}>
                                Validated with Verhoeff checksum algorithm
                            </small>
                        </div>
                        <div className="input-group">
                            <label><i className="fas fa-file-invoice" style={{marginRight:'6px',color:'#3b82f6'}}></i>PAN Card Number (IT Dept) <span style={{color: "var(--danger-color)"}}>*</span></label>
                            <input 
                                type="text" 
                                placeholder="e.g. ABCDE1234F" 
                                maxLength="10"
                                value={pan}
                                onChange={handlePanChange}
                                className="styled-input"
                                style={{textTransform: "uppercase", letterSpacing: "2px", fontWeight: "600"}}
                                required
                            />
                            <small style={{color:'var(--text-secondary)', marginTop:'4px', fontSize:'0.75rem'}}>
                                Format: 5 letters + 4 digits + 1 letter
                            </small>
                        </div>
                        <div className="input-group">
                            <label><i className="fas fa-user-check" style={{marginRight:'6px',color:'#10b981'}}></i>Voter ID / EPIC Number (ECI) <span style={{color: "var(--danger-color)"}}>*</span></label>
                            <input 
                                type="text" 
                                placeholder="e.g. ABC1234567" 
                                maxLength="10"
                                value={voterId}
                                onChange={handleVoterIdChange}
                                className="styled-input"
                                style={{textTransform: "uppercase", letterSpacing: "2px", fontWeight: "600"}}
                                required
                            />
                            <small style={{color:'var(--text-secondary)', marginTop:'4px', fontSize:'0.75rem'}}>
                                Format: 3 letters + 7 digits (state code + serial)
                            </small>
                        </div>
                        <button type="submit" className="btn btn-primary" style={{background: 'linear-gradient(135deg, #10b981, #059669)'}} disabled={isLoading}>
                            {isLoading ? <><i className="fas fa-spinner fa-spin"></i> Validating with Government APIs...</> : <><i className="fas fa-cloud-download-alt"></i> Verify Documents via DigiLocker</>}
                        </button>
                        <button type="button" onClick={handleLogout} className="btn btn-secondary" style={{marginTop: '1rem'}}>
                            <i className="fas fa-sign-out-alt"></i> Cancel & Logout
                        </button>
                    </form>
                </div>
            )}

            {/* ==================== VIEW: KYC OTP VERIFICATION ==================== */}
            {view === 'kyc_otp' && (
                <div className="fade-in form-container">
                    <div className="auth-banner" style={{background: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b', borderColor: 'rgba(245, 158, 11, 0.3)'}}>
                        <i className="fas fa-university"></i> 
                        Government Authority Verification
                    </div>
                    <h2 className="section-heading"><i className="fas fa-shield-alt"></i> KYC OTP Verification (Step 4)</h2>
                    <div className="info-box" style={{borderColor: 'rgba(245, 158, 11, 0.3)'}}>
                        <i className="fas fa-lock" style={{color: '#f59e0b'}}></i>
                        <div>
                            <p>An OTP has been sent to your <strong>government-registered</strong> contacts:</p>
                            <p style={{marginTop:'0.5rem'}}>📱 Mobile: <strong style={{color:'white'}}>{maskedMobile}</strong></p>
                            <p>📧 Email: <strong style={{color:'white'}}>{maskedEmail}</strong></p>
                            <p style={{marginTop:'0.5rem', fontSize:'0.8rem', color:'var(--text-secondary)'}}>
                                This OTP is sent to the mobile/email linked with your Aadhaar, NOT the number you logged in with.
                            </p>
                        </div>
                    </div>
                    <form onSubmit={handleVerifyKycOtp}>
                        <div className="input-group">
                            <label>Government KYC Verification OTP</label>
                            <input 
                                type="text" 
                                placeholder="Enter 6-digit KYC OTP" 
                                maxLength="6"
                                value={kycOtp}
                                onChange={(e) => setKycOtp(e.target.value.replace(/\D/g, ''))}
                                className="styled-input"
                                style={{letterSpacing: '8px', textAlign: 'center', fontSize: '1.3rem', fontWeight: '700'}}
                                required
                            />
                        </div>
                        <button type="submit" className="btn btn-primary" style={{background: 'linear-gradient(135deg, #f59e0b, #d97706)'}} disabled={isLoading}>
                            {isLoading ? <><i className="fas fa-spinner fa-spin"></i> Verifying...</> : <><i className="fas fa-check-double"></i> Confirm Government Identity</>}
                        </button>
                        <button type="button" onClick={() => setView('verification')} className="btn btn-secondary" style={{marginTop: '1rem'}}>
                            <i className="fas fa-arrow-left"></i> Back to Documents
                        </button>
                    </form>
                </div>
            )}

            {/* ==================== VIEW: LIVE SELFIE CAPTURE ==================== */}
            {view === 'selfie' && (
                <div className="fade-in form-container">
                    <div className="auth-banner" style={{background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', borderColor: 'rgba(56, 189, 248, 0.2)'}}>
                        <i className="fas fa-check-circle"></i> 
                        Identity Confirmed: AADHAAR ****{aadhaar.substring(8, 12)} | VOTER {voterId}
                    </div>
                    <h2 className="section-heading"><i className="fas fa-camera"></i> Live Photo Verification (Step 5)</h2>
                    <div className="info-box" style={{borderColor: 'rgba(56, 189, 248, 0.3)'}}>
                        <i className="fas fa-user-shield" style={{color: '#38bdf8'}}></i>
                        <p>Take a <strong>live selfie</strong> to confirm your physical identity. This photo will be securely stored for audit purposes and prevents impersonation.</p>
                    </div>

                    <div className="selfie-container">
                        {!selfieData ? (
                            <>
                                <div className="camera-viewport">
                                    <video ref={videoRef} autoPlay playsInline muted className="camera-feed"></video>
                                    <div className="face-guide">
                                        <div className="face-oval"></div>
                                        <p>Position your face within the oval</p>
                                    </div>
                                </div>
                                <button type="button" onClick={capturePhoto} className="btn btn-primary" style={{marginTop:'1rem', background: 'linear-gradient(135deg, #38bdf8, #0284c7)'}}>
                                    <i className="fas fa-camera"></i> Capture Photo
                                </button>
                            </>
                        ) : (
                            <>
                                <div className="selfie-preview">
                                    <img src={selfieData} alt="Your selfie" className="selfie-image" />
                                    <div className="selfie-verified-badge">
                                        <i className="fas fa-check-circle"></i> Photo Captured
                                    </div>
                                </div>
                                <div style={{display:'flex', gap:'1rem', marginTop:'1rem'}}>
                                    <button type="button" onClick={retakePhoto} className="btn btn-secondary" style={{flex:1}}>
                                        <i className="fas fa-redo"></i> Retake
                                    </button>
                                    <button type="button" onClick={() => setView('voting')} className="btn btn-primary" style={{flex:1, background: 'linear-gradient(135deg, #10b981, #059669)'}}>
                                        <i className="fas fa-arrow-right"></i> Proceed to Vote
                                    </button>
                                </div>
                            </>
                        )}
                    </div>
                    <canvas ref={canvasRef} style={{display:'none'}}></canvas>
                </div>
            )}

            {/* ==================== VIEW: VOTING ==================== */}
            {(view === 'voting' || view === 'success') && (
                <div className="fade-in" style={{ opacity: view === 'success' ? 0.2 : 1, filter: view === 'success' ? 'blur(3px)' : 'none', pointerEvents: view === 'success' ? 'none' : 'auto', transition: 'all 0.6s ease' }}>
                    <div className="auth-banner" style={{background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', borderColor: 'rgba(56, 189, 248, 0.2)'}}>
                        <i className="fas fa-user-check"></i> 
                        Verified: AADHAAR ****{aadhaar.substring(8, 12)} | VOTER {voterId} | 📸 Selfie ✓
                    </div>
                    <h2 className="section-heading" style={{textAlign:"center"}}>Cast Your Democratic Ballot</h2>
                    <div className="candidates-grid">
                        {candidates.map((c, idx) => (
                            <div 
                                key={c.id} 
                                className="candidate-card" 
                                style={{animationDelay: `${idx * 0.1}s`}}
                                onClick={() => {
                                    if(confirm(`You are about to vote for ${c.name}.\n\nThis action is IRREVERSIBLE.\nYou will NOT be able to vote again.\n\nProceed?`)) {
                                        handleVote(c.id, c.name);
                                    }
                                }}
                            >
                                <div className="candidate-logo-wrapper">
                                    <img src={c.image} alt={c.name} className="candidate-logo" />
                                </div>
                                <h3 className="candidate-name" style={{fontSize: "1.1rem"}}>{c.shortName}</h3>
                            </div>
                        ))}
                    </div>
                    <p style={{textAlign:"center", color:"var(--text-secondary)", fontSize:"0.85rem", margin: "1rem 0"}}>
                        <i className="fas fa-lock"></i> One Person, One Vote — enforced by triple document deduplication.
                    </p>
                </div>
            )}

            {/* ==================== VIEW: SUCCESS (MODAL OVERLAY) ==================== */}
            {view === 'success' && (
                <div className="modal-overlay">
                    <div className="text-center appreciation-card">
                        <div className="tricolor-strip">
                            <div className="strip-saffron"></div>
                            <div className="strip-white"></div>
                            <div className="strip-green"></div>
                        </div>
                        
                        <div className="chakra-container">
                            <svg className="ashoka-chakra-svg" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                                <circle cx="50" cy="50" r="48" fill="none" stroke="#000080" strokeWidth="1" />
                                <circle cx="50" cy="50" r="8" fill="none" stroke="#000080" strokeWidth="0.5" />
                                {[...Array(24)].map((_, i) => (
                                    <line 
                                        key={i}
                                        x1="50" y1="50" 
                                        x2={50 + 40 * Math.cos(i * (Math.PI / 12))} 
                                        y2={50 + 40 * Math.sin(i * (Math.PI / 12))} 
                                        stroke="#000080" strokeWidth="1.2" 
                                    />
                                ))}
                            </svg>
                        </div>

                        <h2 className="pulse-success" style={{color: "white", marginBottom: '0.5rem', fontWeight: "700"}}>
                            Vote Recorded Successfully
                        </h2>
                        
                        <p className="democracy-text">
                            "The right to vote is the foundation of democracy. Your voice ensures the rule of law prevails."
                        </p>

                        <div className="law-message">
                            <h4><i className="fas fa-balance-scale"></i> Equality Under Law</h4>
                            <p>One vote, one value. You have successfully fulfilled your supreme duty.</p>
                        </div>

                        <div style={{marginTop: '1.5rem', background: 'rgba(255,255,255,0.02)', padding: '10px', borderRadius: '8px', fontSize: '0.8rem', color: 'var(--text-secondary)'}}>
                           Ref: {voterId} | Sec: Encrypted ✓
                        </div>

                        <button onClick={handleLogout} className="btn btn-primary" style={{marginTop: '1.5rem', background: 'var(--success-color)', py: '0.75rem'}}>
                            <i className="fas fa-sign-out-alt"></i> Exit Securely
                        </button>
                    </div>
                </div>
            )}

            {/* ==================== VIEW: RESULTS ==================== */}
            {view === 'results' && (
                <div className="fade-in results-section">
                    <h2 className="section-heading"><i className="fas fa-shield-alt"></i> Administrative Results Portal</h2>
                    <div className="results-container">
                        {(() => {
                            const totalVotes = Object.values(votes).reduce((a, b) => a + b, 0);
                            if (totalVotes === 0) return <p style={{textAlign:"center", color:"var(--text-secondary)"}}>No votes recorded yet.</p>;
                            
                            return candidates.slice().sort((a,b) => (votes[b.id]||0) - (votes[a.id]||0)).map((c, idx) => {
                                const count = votes[c.id] || 0;
                                const percent = Math.round((count / totalVotes) * 100);
                                return (
                                    <div className="result-item fade-in" key={c.id} style={{animationDelay:`${idx*0.1}s`}}>
                                        <div className="result-info">
                                            <span style={{display: "flex", alignItems: "center", gap: "10px"}}>
                                                <img src={c.image} alt={c.shortName} style={{width:"24px", height:"24px", objectFit:"contain"}}/>
                                                {c.shortName}
                                            </span>
                                            <span>{count} Votes ({percent}%)</span>
                                        </div>
                                        <div className="progress-bar-container">
                                            <div className="progress-bar" style={{width: `${percent}%`, backgroundColor: c.color}}></div>
                                        </div>
                                    </div>
                                );
                            });
                        })()}
                    </div>
                    <button onClick={() => setView('login')} className="btn btn-secondary" style={{marginTop: '1rem'}}>
                        <i className="fas fa-arrow-left"></i> Back to Login
                    </button>
                    <button onClick={handleWipeDatabase} className="btn btn-danger" style={{marginTop: '1rem', background:'transparent', border:'none', color:'var(--danger-color)', width:'auto', margin:'1rem auto', display:'block', fontSize:'0.8rem'}}>
                        Admin: Reset Database
                    </button>
                </div>
            )}

            {toast && (
                <div className={`toast ${toast.type === 'error' ? 'toast-error' : ''}`}>
                    <i className={`fas ${toast.type === 'error' ? 'fa-exclamation-circle' : 'fa-check-circle'}`}></i>
                    <span>{toast.message}</span>
                </div>
            )}

            {/* ==================== OTP HINT POPUP ==================== */}
            {otpHintVisible && (
                <div className="otp-hint-overlay" onClick={() => setOtpHintVisible(false)}>
                    <div className="otp-hint-popup" onClick={e => e.stopPropagation()}>
                        <div className="otp-hint-icon">
                            <i className="fas fa-key"></i>
                        </div>
                        <div className="otp-hint-body">
                            <p className="otp-hint-label">Demo Mode — Default OTP</p>
                            <div className="otp-hint-code">123456</div>
                            <p className="otp-hint-sub">Use this OTP to proceed in simulation mode</p>
                        </div>
                        <button className="otp-hint-close" onClick={() => setOtpHintVisible(false)} aria-label="Close">
                            <i className="fas fa-times"></i>
                        </button>
                    </div>
                </div>
            )}
        </main>
    );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
