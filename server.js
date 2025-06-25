import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import cron from 'node-cron';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const VIRUSTOTAL_API_KEY = 'f78059d0d28ad2799567baeb2450aecb4bb7d093d9d21b60e8225054e55b5074';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Create uploads directories if they don't exist
const uploadDirs = ['uploads', 'uploads/profiles', 'uploads/submissions', 'uploads/comments'];
uploadDirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// MongoDB Connection
mongoose
  .connect('mongodb://127.0.0.1:27017/scam_alert', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => console.error('❌ MongoDB connection error:', err));

// Configure Multer for different file types
const createMulterConfig = (destination) => {
  const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, destination);
    },
    filename: function (req, file, cb) {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
      cb(null, uniqueSuffix + path.extname(file.originalname));
    },
  });

  return multer({ 
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit for media files
    fileFilter: (req, file, cb) => {
      // Check file extension
      const allowedExtensions = /\.(jpeg|jpg|png|gif|webp|mp4|avi|mov|wmv|flv|webm|mp3|wav|ogg|m4a)$/i;
      const extname = allowedExtensions.test(path.extname(file.originalname).toLowerCase());
      
      // Check mimetype - more comprehensive check
      const allowedMimetypes = [
        // Images
        'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
        // Videos
        'video/mp4', 'video/avi', 'video/quicktime', 'video/x-msvideo', 'video/x-ms-wmv', 
        'video/x-flv', 'video/webm',
        // Audio
        'audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/wave', 'audio/x-wav', 
        'audio/ogg', 'audio/mp4', 'audio/m4a', 'audio/x-m4a'
      ];
      
      const mimetypeAllowed = allowedMimetypes.includes(file.mimetype.toLowerCase());
      
      if (mimetypeAllowed && extname) {
        return cb(null, true);
      } else {
        console.log(`File rejected - Mimetype: ${file.mimetype}, Extension: ${path.extname(file.originalname)}`);
        cb(new Error('Only image, video, and audio files are allowed!'));
      }
    }
  });
};

const uploadProfile = createMulterConfig('uploads/profiles');
const uploadSubmission = createMulterConfig('uploads/submissions');
const uploadComment = createMulterConfig('uploads/comments');

// Dummy NID Database
const validNIDs = [
  '1234567890123', '2345678901234', '3456789012345', '4567890123456',
  '5678901234567', '6789012345678', '7890123456789', '8901234567890',
  '9012345678901', '0123456789012', '1122334455667', '2233445566778',
  '3344556677889', '4455667788990', '5566778899001', '6677889900112',
  '7788990011223', '8899001122334', '9900112233445', '0011223344556'
];

// In-memory OTP storage (in production, use Redis or database)
const otpStorage = new Map();

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  nid: { type: String, required: true, unique: true },
  profilePicture: { 
    filename: String,
    originalName: String,
    mimetype: String,
    path: String
  },
  isVerified: { type: Boolean, default: false },
  followedCommunities: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Community' }],
  reputation: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const communitySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: { type: String, required: true },
  icon: { type: String, default: '🛡️' },
  color: { type: String, default: '#ef4444' },
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  memberCount: { type: Number, default: 0 },
  postCount: { type: Number, default: 0 },
  isDefault: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const submissionSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['email', 'sms', 'call', 'url', 'advertisement', 'other'],
    required: true 
  },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  community: { type: mongoose.Schema.Types.ObjectId, ref: 'Community', required: true },
  context: { type: String },
  attachments: [{ 
    filename: String,
    originalName: String,
    mimetype: String,
    path: String,
    fileType: { type: String, enum: ['image', 'video', 'audio'] }
  }],
  votes: {
    legit: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    scam: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    unsure: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
  },
  scamScore: { type: Number, default: 0 },
  aiAnalysis: {
    isAnalyzed: { type: Boolean, default: false },
    virusTotalResult: { type: Object },
    flaggedPatterns: [String],
    riskLevel: { type: String, enum: ['low', 'medium', 'high'], default: 'low' }
  },
  status: { type: String, enum: ['pending', 'verified', 'disputed'], default: 'pending' },
  viewCount: { type: Number, default: 0 },
  commentCount: { type: Number, default: 0 },
  trendingScore: { type: Number, default: 0 }, // Added for better trending calculation
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const commentSchema = new mongoose.Schema({
  content: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  submission: { type: mongoose.Schema.Types.ObjectId, ref: 'Submission', required: true },
  attachments: [{ 
    filename: String,
    originalName: String,
    mimetype: String,
    path: String,
    fileType: { type: String, enum: ['image', 'video', 'audio'] }
  }],
  votes: {
    up: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    down: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Community = mongoose.model('Community', communitySchema);
const Submission = mongoose.model('Submission', submissionSchema);
const Comment = mongoose.model('Comment', commentSchema);

// Helper function to determine file type
function getFileType(mimetype) {
  if (mimetype.startsWith('image/')) return 'image';
  if (mimetype.startsWith('video/')) return 'video';
  if (mimetype.startsWith('audio/')) return 'audio';
  return 'other';
}

// Helper function to delete file
function deleteFile(filePath) {
  if (filePath && fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
}

// Helper function to calculate trending score
function calculateTrendingScore(submission) {
  const now = new Date();
  const createdAt = new Date(submission.createdAt);
  const hoursSinceCreation = (now - createdAt) / (1000 * 60 * 60);
  
  // Engagement metrics
  const totalVotes = submission.votes.legit.length + submission.votes.scam.length + submission.votes.unsure.length;
  const viewWeight = submission.viewCount * 0.1;
  const commentWeight = submission.commentCount * 2;
  const voteWeight = totalVotes * 3;
  const scamScoreWeight = submission.scamScore * 0.5;
  
  // Time decay factor (newer posts get higher scores)
  const timeDecay = Math.max(0.1, 1 / (1 + hoursSinceCreation * 0.1));
  
  const rawScore = (viewWeight + commentWeight + voteWeight + scamScoreWeight) * timeDecay;
  return Math.round(rawScore * 100) / 100;
}

// Initialize default communities
async function initializeDefaultCommunities() {
  const defaultCommunities = [
    {
      name: 'Online Shopping Scams',
      description: 'Report fake online stores, fraudulent sellers, and shopping-related scams',
      icon: '🛒',
      color: '#3b82f6',
      isDefault: true
    },
    {
      name: 'Phishing Scams',
      description: 'Email phishing, fake login pages, and identity theft attempts',
      icon: '🎣',
      color: '#ef4444',
      isDefault: true
    },
    {
      name: 'Social Media Scams',
      description: 'Facebook, Instagram, WhatsApp and other social platform scams',
      icon: '📱',
      color: '#8b5cf6',
      isDefault: true
    },
    {
      name: 'Phone Call Scams',
      description: 'Robocalls, fake tech support, and phone-based fraud',
      icon: '📞',
      color: '#f59e0b',
      isDefault: true
    },
    {
      name: 'Investment Scams',
      description: 'Cryptocurrency, trading, and investment fraud schemes',
      icon: '💰',
      color: '#10b981',
      isDefault: true
    },
    {
      name: 'Romance Scams',
      description: 'Dating app fraud and online relationship scams',
      icon: '💕',
      color: '#ec4899',
      isDefault: true
    }
  ];

  for (const communityData of defaultCommunities) {
    const existingCommunity = await Community.findOne({ name: communityData.name });
    if (!existingCommunity) {
      await Community.create(communityData);
      console.log(`✅ Created default community: ${communityData.name}`);
    }
  }
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Helper function to calculate scam score
function calculateScamScore(votes) {
  const totalVotes = votes.legit.length + votes.scam.length + votes.unsure.length;
  if (totalVotes === 0) return 0;
  
  const scamWeight = votes.scam.length * 1;
  const unsureWeight = votes.unsure.length * 0.5;
  const legitWeight = votes.legit.length * -1;
  
  const rawScore = (scamWeight + unsureWeight + legitWeight) / totalVotes;
  return Math.max(0, Math.min(1, (rawScore + 1) / 2)) * 100;
}

// AI Analysis function
async function analyzeSubmission(submission) {
  const analysis = {
    isAnalyzed: true,
    flaggedPatterns: [],
    riskLevel: 'low'
  };

  // Pattern detection
  const suspiciousPatterns = [
    /(urgent|immediate|asap).{0,20}(action|response|required|attention)/i,
    /(verify|validate|confirm).{0,20}(account|identity|details|information)/i,
    /(click|press|tap).{0,20}(here|link|button|below).{0,20}(now|immediately)/i,
    /(limited|exclusive|special).{0,20}(time|offer|deal|discount)/i,
    /(account|service|access).{0,20}(suspended|locked|disabled|terminated)/i,
    /(bank|payment|transaction|mobile).{0,20}(problem|issue|failed|pending)/i,
    /(security|verification|authentication).{0,20}(required|failed|alert)/i,
    /(dear|customer|user|valued).{0,20}(account|member|client)/i,
    /(free|gift|reward|prize).{0,20}(claim|collect|receive)/i,
    /(password|pin|otp|code).{0,20}(expire|change|update|required)/i,
    /(government|official|authority).{0,20}(notice|alert|message)/i,
    /(update|upgrade|renew).{0,20}(information|details|account)/i,
    /(unauthorized|suspicious|fraudulent).{0,20}(activity|transaction)/i,
    /(refund|compensation|rebate).{0,20}(claim|eligible|available)/i,
    /(expire|expiration).{0,20}(soon|imminent|date)/i,
    /(immediate|quick).{0,20}(payment|action|response)/i,
    
    /(জরুরী|অতি জরুরী|তাৎক্ষণিক).{0,20}(প্রতিকার|কার্যক্রম|প্রতিক্রিয়া)/i,
    /(অ্যাকাউন্ট|একাউন্ট|হিসাব).{0,20}(নিশ্চিত|যাচাই|ভেরিফাই)/i,
    /(এখানে|লিংকে|বাটনে).{0,20}(ক্লিক|প্রেস|টাচ)/i,
    /(সীমিত|বিশেষ|এক্সক্লুসিভ).{0,20}(অফার|ডিসকাউন্ট|সুযোগ)/i,
    /(অভিনন্দন|আপনি.{0,20}জিতেছেন|পুরস্কার)/i,
    /(অ্যাকাউন্ট|সেবা).{0,20}(বন্ধ|লক|নিষ্ক্রিয়)/i,
    /(ব্যাংক|পেমেন্ট|টাকা).{0,20}(সমস্যা|বিকল|অব্যবস্থা)/i,
    /(নিরাপত্তা|যাচাইকরণ).{0,20}(প্রয়োজন|ব্যর্থ|সতর্কতা)/i,
    /(প্রিয়|গ্রাহক|ব্যবহারকারী).{0,20}(হিসাব|সদস্য)/i,
    /(ফ্রি|উপহার|পুরস্কার).{0,20}(দাবি|গ্রহণ|পাওয়া)/i,
    /(পাসওয়ার্ড|পিন|ওটিপি).{0,20}(পরিবর্তন|আপডেট|প্রয়োজন)/i,
    /(সরকারি|দাপ্তরিক|কর্তৃপক্ষ).{0,20}(নোটিশ|সতর্কতা)/i,
    /(আপডেট|আধুনিকীকরণ).{0,20}(তথ্য|বিবরণ)/i,
    /(অননুমোদিত|সন্দেহজনক).{0,20}(কার্যকলাপ|লেনদেন)/i,
    /(ফেরত|ক্ষতিপূরণ).{0,20}(দাবি|প্রাপ্য)/i,
    /(মেয়াদ|সময়সীমা).{0,20}(শেষ|সমাপ্তি)/i,
    /(তাৎক্ষণিক|দ্রুত).{0,20}(পেমেন্ট|প্রতিক্রিয়া)/i,

    /(বিকাশ|নগদ|রকেট).{0,20}(পিন|অ্যাকাউন্ট|টাকা)/i,
    /(এমবিএস|এমবিএসএস|এমবিএসএস).{0,20}(লটারি|পুরস্কার)/i,
    /(টাকা.{0,20}পাঠান|টাকা.{0,20}প্রেরণ)/i,
    /(ডিপিএস|এফডিআর|সঞ্চয়).{0,20}(বোনাস|অতিরিক্ত)/i,

    /(লগইন|সাইনইন).{0,20}(তথ্য|বিবরণ)/i,
    /(ভেরিফাই|নিশ্চিত).{0,20}(নম্বর|মোবাইল)/i,
    /(কুরিয়ার|ডেলিভারি|পার্সেল).{0,20}(ফি|টাকা|পেমেন্ট)/i,
    /(পণ্য|অর্ডার).{0,20}(বিলম্ব|অবরুদ্ধ)/i,
    
    /(চাকরি|কাজ|নিয়োগ).{0,20}(সুযোগ|গ্যারান্টি)/i,
    /(বেতন|আয়).{0,20}(অতিরিক্ত|বোনাস)/i,
    
    /(করোনা|কোভিড).{0,20}(টিকা|সহায়তা|তহবিল)/i,
    /(রিলিফ|সাহায্য).{0,20}(ফান্ড|অর্থ)/i
  ];

  const content = `${submission.title} ${submission.content}`.toLowerCase();
  
  suspiciousPatterns.forEach(pattern => {
    if (pattern.test(content)) {
      analysis.flaggedPatterns.push(pattern.toString());
    }
  });

  // URL analysis with VirusTotal
  if (submission.type === 'url' || /https?:\/\/[^\s]+/i.test(submission.content)) {
    try {
      const urls = submission.content.match(/https?:\/\/[^\s]+/g);
      if (urls && urls.length > 0) {
        const url = urls[0];
        const response = await fetch(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${encodeURIComponent(url)}`);
        const result = await response.json();
        analysis.virusTotalResult = result;
        
        if (result.positives > 0) {
          analysis.flaggedPatterns.push('URL flagged by security vendors');
        }
      }
    } catch (error) {
      console.log('VirusTotal API error:', error.message);
    }
  }

  // Determine risk level
  if (analysis.flaggedPatterns.length >= 3) {
    analysis.riskLevel = 'high';
  } else if (analysis.flaggedPatterns.length >= 1) {
    analysis.riskLevel = 'medium';
  }

  return analysis;
}

// Routes

// Auth Routes
app.post('/api/auth/register', uploadProfile.single('profilePicture'), async (req, res) => {
  try {
    const { username, email, password, nid } = req.body;

    // Password validation
    const passwordRegex = /^(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])(?=.*[0-9])(?=.*[A-Za-z]).{6,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({ 
        error: 'Password must be at least 6 characters long, include at least one letter, one number, and one special character.' 
      });
    }

    // Validate NID
    if (!validNIDs.includes(nid)) {
      return res.status(400).json({ error: 'Invalid NID number' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }, { nid }] 
    });
    
    if (existingUser) {
      // Delete uploaded file if user already exists
      if (req.file) {
        deleteFile(req.file.path);
      }
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Prepare profile picture data
    let profilePicture = null;
    if (req.file) {
      profilePicture = {
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimetype: req.file.mimetype,
        path: req.file.path
      };
    }

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      nid,
      profilePicture,
      isVerified: true // Auto-verify since NID is valid
    });

    await user.save();

    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET);

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isVerified: user.isVerified,
        reputation: user.reputation,
        followedCommunities: user.followedCommunities,
        profilePicture: user.profilePicture
      }
    });
  } catch (error) {
    // Delete uploaded file if error occurs
    if (req.file) {
      deleteFile(req.file.path);
    }
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET);

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isVerified: user.isVerified,
        reputation: user.reputation,
        followedCommunities: user.followedCommunities,
        profilePicture: user.profilePicture
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Forgot Password Routes
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    
    // Store OTP with expiration (5 minutes)
    otpStorage.set(email, {
      otp,
      expires: Date.now() + 5 * 60 * 1000,
      userId: user._id
    });

    // Log OTP to terminal (for demo purposes)
    console.log(`🔐 OTP for ${email}: ${otp}`);
    console.log(`⏰ OTP expires in 5 minutes`);

    res.json({ 
      message: 'OTP sent to your email. Check the terminal for the OTP code.',
      email 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Check if OTP exists and is valid
    const otpData = otpStorage.get(email);
    if (!otpData) {
      return res.status(400).json({ error: 'OTP not found or expired' });
    }

    if (Date.now() > otpData.expires) {
      otpStorage.delete(email);
      return res.status(400).json({ error: 'OTP expired' });
    }

    if (otpData.otp !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    // Generate reset token
    const resetToken = jwt.sign({ userId: otpData.userId, email }, JWT_SECRET, { expiresIn: '15m' });

    // Remove OTP from storage
    otpStorage.delete(email);

    res.json({ 
      message: 'OTP verified successfully',
      resetToken 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    // Password validation
    const passwordRegex = /^(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])(?=.*[0-9])(?=.*[A-Za-z]).{6,}$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({ 
        error: 'Password must be at least 6 characters long, include at least one letter, one number, and one special character.' 
      });
    }

    // Verify reset token
    const decoded = jwt.verify(resetToken, JWT_SECRET);
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password
    await User.findByIdAndUpdate(decoded.userId, { password: hashedPassword });

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    res.status(500).json({ error: error.message });
  }
});

// Get user profile
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate('followedCommunities');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isVerified: user.isVerified,
        reputation: user.reputation,
        followedCommunities: user.followedCommunities.map(c => c._id.toString()),
        profilePicture: user.profilePicture,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Profile update route
app.put('/api/auth/profile', authenticateToken, uploadProfile.single('profilePicture'), async (req, res) => {
  try {
    const { username, password } = req.body;
    const updateData = {};

    if (username) {
      // Check if username is already taken
      const existingUser = await User.findOne({ 
        username, 
        _id: { $ne: req.user.userId } 
      });
      if (existingUser) {
        if (req.file) {
          deleteFile(req.file.path);
        }
        return res.status(400).json({ error: 'Username already taken' });
      }
      updateData.username = username;
    }

    if (password) {
      // Password validation
      const passwordRegex = /^(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])(?=.*[0-9])(?=.*[A-Za-z]).{6,}$/;
      if (!passwordRegex.test(password)) {
        if (req.file) {
          deleteFile(req.file.path);
        }
        return res.status(400).json({ 
          error: 'Password must be at least 6 characters long, include at least one letter, one number, and one special character.' 
        });
      }
      updateData.password = await bcrypt.hash(password, 10);
    }

    // Handle profile picture update
    if (req.file) {
      const currentUser = await User.findById(req.user.userId);
      
      // Delete old profile picture if exists
      if (currentUser.profilePicture && currentUser.profilePicture.path) {
        deleteFile(currentUser.profilePicture.path);
      }

      updateData.profilePicture = {
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimetype: req.file.mimetype,
        path: req.file.path
      };
    }

    const user = await User.findByIdAndUpdate(
      req.user.userId,
      updateData,
      { new: true }
    );

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isVerified: user.isVerified,
        reputation: user.reputation,
        followedCommunities: user.followedCommunities,
        profilePicture: user.profilePicture
      }
    });
  } catch (error) {
    if (req.file) {
      deleteFile(req.file.path);
    }
    res.status(500).json({ error: error.message });
  }
});

// Community Routes
app.get('/api/communities', async (req, res) => {
  try {
    const userId = req.headers.authorization ? 
      jwt.verify(req.headers.authorization.split(' ')[1], JWT_SECRET).userId : null;

    const communities = await Community.find()
      .sort({ memberCount: -1 })
      .populate('followers', 'username');

    // Add isFollowing flag for authenticated users
    const communitiesWithFollowStatus = communities.map(community => ({
      ...community.toObject(),
      isFollowing: userId ? community.followers.some(follower => follower._id.toString() === userId) : false
    }));

    res.json(communitiesWithFollowStatus);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/communities/:id/follow', authenticateToken, async (req, res) => {
  try {
    const community = await Community.findById(req.params.id);
    const user = await User.findById(req.user.userId);

    if (!community || !user) {
      return res.status(404).json({ error: 'Community or user not found' });
    }

    if (!community.followers.includes(user._id)) {
      community.followers.push(user._id);
      community.memberCount += 1;
      await community.save();

      user.followedCommunities.push(community._id);
      await user.save();
    }

    res.json({ message: 'Followed community successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/communities/:id/unfollow', authenticateToken, async (req, res) => {
  try {
    const community = await Community.findById(req.params.id);
    const user = await User.findById(req.user.userId);

    if (!community || !user) {
      return res.status(404).json({ error: 'Community or user not found' });
    }

    if (community.followers.includes(user._id)) {
      community.followers = community.followers.filter(id => !id.equals(user._id));
      community.memberCount = Math.max(0, community.memberCount - 1);
      await community.save();

      user.followedCommunities = user.followedCommunities.filter(id => !id.equals(community._id));
      await user.save();
    }

    res.json({ message: 'Unfollowed community successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Submission Routes
app.post('/api/submissions', authenticateToken, uploadSubmission.array('attachments', 10), async (req, res) => {
  try {
    const { title, content, type, communityId, context } = req.body;

    const attachments = req.files ? req.files.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      mimetype: file.mimetype,
      path: file.path,
      fileType: getFileType(file.mimetype)
    })) : [];

    const submission = new Submission({
      title,
      content,
      type,
      author: req.user.userId,
      community: communityId,
      context,
      attachments
    });

    // Perform AI analysis
    const aiAnalysis = await analyzeSubmission(submission);
    submission.aiAnalysis = aiAnalysis;

    // Calculate initial trending score
    submission.trendingScore = calculateTrendingScore(submission);

    await submission.save();

    // Update community post count
    await Community.findByIdAndUpdate(communityId, { $inc: { postCount: 1 } });

    const populatedSubmission = await Submission.findById(submission._id)
      .populate('author', 'username reputation profilePicture')
      .populate('community', 'name icon color');

    res.status(201).json(populatedSubmission);
  } catch (error) {
    // Delete uploaded files if error occurs
    if (req.files) {
      req.files.forEach(file => deleteFile(file.path));
    }
    res.status(500).json({ error: error.message });
  }
});

// Update submission
app.put('/api/submissions/:id', authenticateToken, uploadSubmission.array('attachments', 10), async (req, res) => {
  try {
    const submission = await Submission.findById(req.params.id);
    
    if (!submission) {
      if (req.files) {
        req.files.forEach(file => deleteFile(file.path));
      }
      return res.status(404).json({ error: 'Submission not found' });
    }

    // Check if user is the author
    if (submission.author.toString() !== req.user.userId) {
      if (req.files) {
        req.files.forEach(file => deleteFile(file.path));
      }
      return res.status(403).json({ error: 'You can only edit your own submissions' });
    }

    const { title, content, context, removeAttachments } = req.body;
    const updateData = { updatedAt: new Date() };

    if (title) updateData.title = title;
    if (content) updateData.content = content;
    if (context) updateData.context = context;

    // Handle attachment removal
    if (removeAttachments) {
      const attachmentsToRemove = JSON.parse(removeAttachments);
      attachmentsToRemove.forEach(filename => {
        const attachment = submission.attachments.find(att => att.filename === filename);
        if (attachment) {
          deleteFile(attachment.path);
        }
      });
      submission.attachments = submission.attachments.filter(
        att => !attachmentsToRemove.includes(att.filename)
      );
    }

    // Handle new attachments
    if (req.files && req.files.length > 0) {
      const newAttachments = req.files.map(file => ({
        filename: file.filename,
        originalName: file.originalname,
        mimetype: file.mimetype,
        path: file.path,
        fileType: getFileType(file.mimetype)
      }));
      submission.attachments.push(...newAttachments);
    }

    // Update submission
    Object.assign(submission, updateData);
    
    // Re-analyze if content changed
    if (content) {
      const aiAnalysis = await analyzeSubmission(submission);
      submission.aiAnalysis = aiAnalysis;
    }

    // Recalculate trending score
    submission.trendingScore = calculateTrendingScore(submission);

    await submission.save();

    const populatedSubmission = await Submission.findById(submission._id)
      .populate('author', 'username reputation profilePicture')
      .populate('community', 'name icon color');

    res.json(populatedSubmission);
  } catch (error) {
    if (req.files) {
      req.files.forEach(file => deleteFile(file.path));
    }
    res.status(500).json({ error: error.message });
  }
});

// Delete submission
app.delete('/api/submissions/:id', authenticateToken, async (req, res) => {
  try {
    const submission = await Submission.findById(req.params.id);
    
    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }

    // Check if user is the author
    if (submission.author.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'You can only delete your own submissions' });
    }

    // Delete associated files
    submission.attachments.forEach(attachment => {
      deleteFile(attachment.path);
    });

    // Delete associated comments and their files
    const comments = await Comment.find({ submission: req.params.id });
    comments.forEach(comment => {
      comment.attachments.forEach(attachment => {
        deleteFile(attachment.path);
      });
    });
    await Comment.deleteMany({ submission: req.params.id });

    // Delete submission
    await Submission.findByIdAndDelete(req.params.id);

    // Update community post count
    await Community.findByIdAndUpdate(submission.community, { $inc: { postCount: -1 } });

    res.json({ message: 'Submission deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/submissions', async (req, res) => {
  try {
    const { community, sort = 'recent', page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (community) {
      query.community = community;
    }

    let sortOption = { createdAt: -1 };
    if (sort === 'trending') {
      sortOption = { trendingScore: -1, createdAt: -1 };
    } else if (sort === 'dangerous') {
      sortOption = { scamScore: -1, createdAt: -1 };
    }

    const submissions = await Submission.find(query)
      .populate('author', 'username reputation profilePicture')
      .populate('community', 'name icon color')
      .sort(sortOption)
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Submission.countDocuments(query);

    res.json({
      submissions,
      pagination: {
        current: parseInt(page),
        pages: Math.ceil(total / limit),
        total
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Enhanced trending endpoint with better algorithm
app.get('/api/submissions/trending', async (req, res) => {
  try {
    const { limit = 20 } = req.query;
    
    // Get all submissions from the last 7 days for trending calculation
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const submissions = await Submission.find({
      createdAt: { $gte: sevenDaysAgo }
    })
      .populate('author', 'username reputation profilePicture')
      .populate('community', 'name icon color');

    // Recalculate trending scores for all submissions
    const submissionsWithUpdatedScores = submissions.map(submission => {
      const updatedScore = calculateTrendingScore(submission);
      submission.trendingScore = updatedScore;
      return submission;
    });

    // Sort by trending score and limit results
    const trendingSubmissions = submissionsWithUpdatedScores
      .sort((a, b) => b.trendingScore - a.trendingScore)
      .slice(0, parseInt(limit));

    // Update trending scores in database (async, don't wait)
    trendingSubmissions.forEach(async (submission) => {
      await Submission.findByIdAndUpdate(submission._id, { 
        trendingScore: submission.trendingScore 
      });
    });

    res.json(trendingSubmissions);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get submission details without incrementing view count (for voting and other operations)
app.get('/api/submissions/:id/details', async (req, res) => {
  try {
    const submission = await Submission.findById(req.params.id)
      .populate('author', 'username reputation profilePicture')
      .populate('community', 'name icon color')
      .populate('votes.legit', 'username')
      .populate('votes.scam', 'username')
      .populate('votes.unsure', 'username');

    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }

    res.json(submission);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get submission details and increment view count (for actual viewing)
app.get('/api/submissions/:id', async (req, res) => {
  try {
    const submission = await Submission.findByIdAndUpdate(
      req.params.id,
      { 
        $inc: { viewCount: 1 },
        trendingScore: 0 // Will be recalculated
      },
      { new: true }
    )
      .populate('author', 'username reputation profilePicture')
      .populate('community', 'name icon color')
      .populate('votes.legit', 'username')
      .populate('votes.scam', 'username')
      .populate('votes.unsure', 'username');

    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }

    // Recalculate trending score after view increment
    submission.trendingScore = calculateTrendingScore(submission);
    await submission.save();

    res.json(submission);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/submissions/:id/vote', authenticateToken, async (req, res) => {
  try {
    const { voteType } = req.body; // 'legit', 'scam', 'unsure'
    const submission = await Submission.findById(req.params.id);

    if (!submission) {
      return res.status(404).json({ error: 'Submission not found' });
    }

    // Remove previous votes by this user
    submission.votes.legit = submission.votes.legit.filter(id => !id.equals(req.user.userId));
    submission.votes.scam = submission.votes.scam.filter(id => !id.equals(req.user.userId));
    submission.votes.unsure = submission.votes.unsure.filter(id => !id.equals(req.user.userId));

    // Add new vote
    if (voteType && submission.votes[voteType]) {
      submission.votes[voteType].push(req.user.userId);
    }

    // Recalculate scam score
    submission.scamScore = calculateScamScore(submission.votes);
    
    // Recalculate trending score
    submission.trendingScore = calculateTrendingScore(submission);

    await submission.save();

    // Return updated submission data without incrementing view count
    const updatedSubmission = await Submission.findById(req.params.id)
      .populate('author', 'username reputation profilePicture')
      .populate('community', 'name icon color')
      .populate('votes.legit', 'username')
      .populate('votes.scam', 'username')
      .populate('votes.unsure', 'username');

    res.json({ 
      message: 'Vote recorded',
      submission: updatedSubmission
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Comment Routes
app.post('/api/submissions/:id/comments', authenticateToken, uploadComment.array('attachments', 5), async (req, res) => {
  try {
    const { content } = req.body;

    const attachments = req.files ? req.files.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      mimetype: file.mimetype,
      path: file.path,
      fileType: getFileType(file.mimetype)
    })) : [];

    const comment = new Comment({
      content,
      author: req.user.userId,
      submission: req.params.id,
      attachments
    });

    await comment.save();

    // Update submission comment count and trending score
    const submission = await Submission.findByIdAndUpdate(
      req.params.id, 
      { $inc: { commentCount: 1 } },
      { new: true }
    );
    
    if (submission) {
      submission.trendingScore = calculateTrendingScore(submission);
      await submission.save();
    }

    const populatedComment = await Comment.findById(comment._id)
      .populate('author', 'username reputation profilePicture');

    res.status(201).json(populatedComment);
  } catch (error) {
    if (req.files) {
      req.files.forEach(file => deleteFile(file.path));
    }
    res.status(500).json({ error: error.message });
  }
});

// Update comment
app.put('/api/comments/:id', authenticateToken, uploadComment.array('attachments', 5), async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.id);
    
    if (!comment) {
      if (req.files) {
        req.files.forEach(file => deleteFile(file.path));
      }
      return res.status(404).json({ error: 'Comment not found' });
    }

    // Check if user is the author
    if (comment.author.toString() !== req.user.userId) {
      if (req.files) {
        req.files.forEach(file => deleteFile(file.path));
      }
      return res.status(403).json({ error: 'You can only edit your own comments' });
    }

    const { content, removeAttachments } = req.body;
    const updateData = { updatedAt: new Date() };

    if (content) updateData.content = content;

    // Handle attachment removal
    if (removeAttachments) {
      const attachmentsToRemove = JSON.parse(removeAttachments);
      attachmentsToRemove.forEach(filename => {
        const attachment = comment.attachments.find(att => att.filename === filename);
        if (attachment) {
          deleteFile(attachment.path);
        }
      });
      comment.attachments = comment.attachments.filter(
        att => !attachmentsToRemove.includes(att.filename)
      );
    }

    // Handle new attachments
    if (req.files && req.files.length > 0) {
      const newAttachments = req.files.map(file => ({
        filename: file.filename,
        originalName: file.originalname,
        mimetype: file.mimetype,
        path: file.path,
        fileType: getFileType(file.mimetype)
      }));
      comment.attachments.push(...newAttachments);
    }

    // Update comment
    Object.assign(comment, updateData);
    await comment.save();

    const populatedComment = await Comment.findById(comment._id)
      .populate('author', 'username reputation profilePicture');

    res.json(populatedComment);
  } catch (error) {
    if (req.files) {
      req.files.forEach(file => deleteFile(file.path));
    }
    res.status(500).json({ error: error.message });
  }
});

// Delete comment
app.delete('/api/comments/:id', authenticateToken, async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.id);
    
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }

    // Check if user is the author
    if (comment.author.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'You can only delete your own comments' });
    }

    // Delete associated files
    comment.attachments.forEach(attachment => {
      deleteFile(attachment.path);
    });

    // Delete comment
    await Comment.findByIdAndDelete(req.params.id);

    // Update submission comment count and trending score
    const submission = await Submission.findByIdAndUpdate(
      comment.submission, 
      { $inc: { commentCount: -1 } },
      { new: true }
    );
    
    if (submission) {
      submission.trendingScore = calculateTrendingScore(submission);
      await submission.save();
    }

    res.json({ message: 'Comment deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/submissions/:id/comments', async (req, res) => {
  try {
    const comments = await Comment.find({ submission: req.params.id })
      .populate('author', 'username reputation profilePicture')
      .sort({ createdAt: -1 });

    res.json(comments);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Stats Routes
app.get('/api/stats', async (req, res) => {
  try {
    const totalSubmissions = await Submission.countDocuments();
    const totalUsers = await User.countDocuments();
    const totalCommunities = await Community.countDocuments();
    const totalScams = await Submission.countDocuments({ scamScore: { $gte: 70 } });

    res.json({
      totalSubmissions,
      totalUsers,
      totalCommunities,
      totalScams
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Initialize default communities on startup
mongoose.connection.once('open', () => {
  initializeDefaultCommunities();
});

// Schedule to update trending scores (runs every hour)
cron.schedule('0 * * * *', async () => {
  console.log('🔄 Updating trending scores...');
  try {
    const submissions = await Submission.find({
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } // Last 7 days
    });

    for (const submission of submissions) {
      const newScore = calculateTrendingScore(submission);
      await Submission.findByIdAndUpdate(submission._id, { 
        trendingScore: newScore 
      });
    }
    console.log(`✅ Updated trending scores for ${submissions.length} submissions`);
  } catch (error) {
    console.error('❌ Error updating trending scores:', error);
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});