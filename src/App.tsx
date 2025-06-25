import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Users, 
  TrendingUp, 
  Plus, 
  Search, 
  Filter,
  User,
  Settings,
  LogOut,
  Eye,
  EyeOff,
  MessageCircle,
  ThumbsUp,
  ThumbsDown,
  AlertCircle,
  Edit,
  Trash2,
  Upload,
  X,
  Camera,
  Play,
  Volume2,
  Download,
  Lock,
  Mail,
  KeyRound,
  ArrowLeft,
  Check,
  Moon,
  Sun,
  Pause,
  Home
} from 'lucide-react';

// Types
interface User {
  id: string;
  username: string;
  email: string;
  isVerified: boolean;
  reputation: number;
  followedCommunities: string[];
  profilePicture?: {
    filename: string;
    originalName: string;
    mimetype: string;
    path: string;
  };
  createdAt: string;
}

interface Community {
  _id: string;
  name: string;
  description: string;
  icon: string;
  color: string;
  memberCount: number;
  postCount: number;
  isFollowing?: boolean;
}

interface Attachment {
  filename: string;
  originalName: string;
  mimetype: string;
  path: string;
  fileType: 'image' | 'video' | 'audio';
}

interface Submission {
  _id: string;
  title: string;
  content: string;
  type: 'email' | 'sms' | 'call' | 'url' | 'advertisement' | 'other';
  author: {
    _id: string;
    username: string;
    reputation: number;
    profilePicture?: {
      filename: string;
      originalName: string;
      mimetype: string;
      path: string;
    };
  };
  community: {
    _id: string;
    name: string;
    icon: string;
    color: string;
  };
  context?: string;
  attachments: Attachment[];
  votes: {
    legit: string[];
    scam: string[];
    unsure: string[];
  };
  scamScore: number;
  aiAnalysis: {
    isAnalyzed: boolean;
    flaggedPatterns: string[];
    riskLevel: 'low' | 'medium' | 'high';
  };
  viewCount: number;
  commentCount: number;
  createdAt: string;
  updatedAt: string;
}

interface Comment {
  _id: string;
  content: string;
  author: {
    _id: string;
    username: string;
    reputation: number;
    profilePicture?: {
      filename: string;
      originalName: string;
      mimetype: string;
      path: string;
    };
  };
  submission: string;
  attachments: Attachment[];
  votes: {
    up: string[];
    down: string[];
  };
  createdAt: string;
  updatedAt: string;
}

interface Stats {
  totalSubmissions: number;
  totalUsers: number;
  totalCommunities: number;
  totalScams: number;
}

// API Base URL
const API_BASE = 'http://localhost:5000/api';

// Utility functions
const getAuthHeaders = () => {
  const token = localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
};

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
};

const getRiskColor = (riskLevel: string, isDark: boolean = false) => {
  const baseClasses = isDark ? 'dark:' : '';
  switch (riskLevel) {
    case 'high': return `text-red-600 bg-red-100 ${baseClasses}text-red-400 ${baseClasses}bg-red-900`;
    case 'medium': return `text-orange-600 bg-orange-100 ${baseClasses}text-orange-400 ${baseClasses}bg-orange-900`;
    default: return `text-green-600 bg-green-100 ${baseClasses}text-green-400 ${baseClasses}bg-green-900`;
  }
};

const getScamScoreColor = (score: number, isDark: boolean = false) => {
  const baseClasses = isDark ? 'dark:' : '';
  if (score >= 70) return `text-red-600 bg-red-100 ${baseClasses}text-red-400 ${baseClasses}bg-red-900`;
  if (score >= 40) return `text-orange-600 bg-orange-100 ${baseClasses}text-orange-400 ${baseClasses}bg-orange-900`;
  return `text-green-600 bg-green-100 ${baseClasses}text-green-400 ${baseClasses}bg-green-900`;
};

// Password strength checker
const checkPasswordStrength = (password: string) => {
  let strength = 0;
  const checks = {
    length: password.length >= 8,
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    number: /\d/.test(password),
    special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
  };
  
  Object.values(checks).forEach(check => check && strength++);
  
  return {
    score: strength,
    checks,
    level: strength < 2 ? 'weak' : strength < 4 ? 'medium' : 'strong'
  };
};

// Components
const PasswordInput: React.FC<{
  id: string;
  name: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  required?: boolean;
  showStrength?: boolean;
  className?: string;
}> = ({ id, name, value, onChange, placeholder, required, showStrength, className }) => {
  const [showPassword, setShowPassword] = useState(false);
  const strength = showStrength ? checkPasswordStrength(value) : null;

  return (
    <div>
      <div className="relative">
        <input
          id={id}
          name={name}
          type={showPassword ? 'text' : 'password'}
          required={required}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          className={className || "mt-1 block w-full px-3 py-2 pr-10 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"}
        />
        <button
          type="button"
          onClick={() => setShowPassword(!showPassword)}
          className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
        >
          {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
        </button>
      </div>
      
      {showStrength && value && (
        <div className="mt-2">
          <div className="flex space-x-1 mb-1">
            {[1, 2, 3, 4, 5].map(i => (
              <div
                key={i}
                className={`h-1 flex-1 rounded ${
                  i <= strength.score
                    ? strength.level === 'weak'
                      ? 'bg-red-500'
                      : strength.level === 'medium'
                      ? 'bg-orange-500'
                      : 'bg-green-500'
                    : 'bg-gray-300 dark:bg-gray-600'
                }`}
              />
            ))}
          </div>
          <p className={`text-xs ${
            strength.level === 'weak'
              ? 'text-red-600 dark:text-red-400'
              : strength.level === 'medium'
              ? 'text-orange-600 dark:text-orange-400'
              : 'text-green-600 dark:text-green-400'
          }`}>
            Password strength: {strength.level}
          </p>
        </div>
      )}
    </div>
  );
};

const ProfilePicture: React.FC<{ user: any; size?: 'sm' | 'md' | 'lg' }> = ({ user, size = 'md' }) => {
  const sizeClasses = {
    sm: 'w-8 h-8',
    md: 'w-10 h-10',
    lg: 'w-16 h-16'
  };

  if (user.profilePicture) {
    return (
      <img
        src={`http://localhost:5000/${user.profilePicture.path}`}
        alt={user.username}
        className={`${sizeClasses[size]} rounded-full object-cover border-2 border-gray-200 dark:border-gray-600 transition-transform hover:scale-105`}
      />
    );
  }

  return (
    <div className={`${sizeClasses[size]} rounded-full bg-gradient-to-br from-red-500 to-pink-600 flex items-center justify-center text-white font-semibold transition-transform hover:scale-105`}>
      {user.username.charAt(0).toUpperCase()}
    </div>
  );
};

const MediaPreview: React.FC<{ attachment: Attachment; isPreview?: boolean }> = ({ attachment, isPreview = false }) => {
  const fileUrl = `http://localhost:5000/${attachment.path}`;
  const [isPlaying, setIsPlaying] = useState(isPreview);

  if (attachment.fileType === 'image') {
    return (
      <div className="relative group overflow-hidden rounded-lg">
        <img
          src={fileUrl}
          alt={attachment.originalName}
          className={`w-full object-cover transition-transform duration-300 group-hover:scale-105 ${
            isPreview ? 'h-20' : 'h-auto max-h-96'
          }`}
        />
        {!isPreview && (
          <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
            <a
              href={fileUrl}
              download={attachment.originalName}
              className="bg-black bg-opacity-50 text-white p-2 rounded-full hover:bg-opacity-70 transition-colors"
            >
              <Download className="w-4 h-4" />
            </a>
          </div>
        )}
      </div>
    );
  }

  if (attachment.fileType === 'video') {
    return (
      <div className="relative overflow-hidden rounded-lg">
        <video
          autoPlay={isPreview}
          loop={isPreview}
          muted={isPreview}
          controls={!isPreview}
          className={`w-full object-cover transition-transform duration-300 hover:scale-105 ${
            isPreview ? 'h-20' : 'h-auto max-h-96'
          }`}
          preload="metadata"
        >
          <source src={fileUrl} type={attachment.mimetype} />
          Your browser does not support the video tag.
        </video>
        {isPreview && (
          <div className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-30">
            <Play className="w-6 h-6 text-white" />
          </div>
        )}
        {!isPreview && (
          <div className="absolute top-2 right-2">
            <a
              href={fileUrl}
              download={attachment.originalName}
              className="bg-black bg-opacity-50 text-white p-2 rounded-full hover:bg-opacity-70 transition-colors"
            >
              <Download className="w-4 h-4" />
            </a>
          </div>
        )}
      </div>
    );
  }

  if (attachment.fileType === 'audio') {
    return (
      <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg border transition-colors">
        <div className="flex items-center space-x-3 mb-3">
          <Volume2 className="w-5 h-5 text-gray-600 dark:text-gray-400" />
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{attachment.originalName}</span>
        </div>
        {!isPreview && (
          <>
            <audio controls className="w-full">
              <source src={fileUrl} type={attachment.mimetype} />
              Your browser does not support the audio tag.
            </audio>
            <div className="mt-2">
              <a
                href={fileUrl}
                download={attachment.originalName}
                className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 text-sm flex items-center space-x-1 transition-colors"
              >
                <Download className="w-4 h-4" />
                <span>Download</span>
              </a>
            </div>
          </>
        )}
      </div>
    );
  }

  return null;
};

const FileUpload: React.FC<{
  onFilesSelected: (files: FileList) => void;
  multiple?: boolean;
  accept?: string;
  maxFiles?: number;
}> = ({ onFilesSelected, multiple = true, accept = "image/*,video/*,audio/*", maxFiles = 10 }) => {
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      onFilesSelected(e.target.files);
    }
  };

  return (
    <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center hover:border-red-400 dark:hover:border-red-500 transition-colors">
      <input
        type="file"
        multiple={multiple}
        accept={accept}
        onChange={handleFileChange}
        className="hidden"
        id="file-upload"
      />
      <label htmlFor="file-upload" className="cursor-pointer">
        <Upload className="w-8 h-8 text-gray-400 dark:text-gray-500 mx-auto mb-2" />
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Click to upload files or drag and drop
        </p>
        <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">
          Images, videos, audio files (max {maxFiles} files, 100MB each)
        </p>
      </label>
    </div>
  );
};

function App() {
  // State management
  const [isDarkMode, setIsDarkMode] = useState(() => {
    const saved = localStorage.getItem('darkMode');
    return saved ? JSON.parse(saved) : false;
  });
  const [currentView, setCurrentView] = useState<'home' | 'communities' | 'trending' | 'login' | 'register' | 'forgot-password' | 'verify-otp' | 'reset-password' | 'profile' | 'create-post' | 'post-detail' | 'edit-post' | 'edit-comment'>('home');
  const [user, setUser] = useState<User | null>(null);
  const [communities, setCommunities] = useState<Community[]>([]);
  const [submissions, setSubmissions] = useState<Submission[]>([]);
  const [trendingSubmissions, setTrendingSubmissions] = useState<Submission[]>([]);
  const [selectedSubmission, setSelectedSubmission] = useState<Submission | null>(null);
  const [comments, setComments] = useState<Comment[]>([]);
  const [stats, setStats] = useState<Stats>({ totalSubmissions: 0, totalUsers: 0, totalCommunities: 0, totalScams: 0 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [communitySearchTerm, setCommunitySearchTerm] = useState('');
  const [selectedCommunity, setSelectedCommunity] = useState<string>('');
  const [sortBy, setSortBy] = useState<'recent' | 'trending' | 'dangerous'>('recent');
  
  // Form states
  const [loginForm, setLoginForm] = useState({ email: '', password: '' });
  const [registerForm, setRegisterForm] = useState({ 
    username: '', 
    email: '', 
    password: '', 
    confirmPassword: '',
    nid: '',
    profilePicture: null as File | null
  });
  const [forgotPasswordForm, setForgotPasswordForm] = useState({ email: '' });
  const [otpForm, setOtpForm] = useState({ email: '', otp: '' });
  const [resetPasswordForm, setResetPasswordForm] = useState({ 
    resetToken: '', 
    newPassword: '', 
    confirmPassword: '' 
  });
  const [profileForm, setProfileForm] = useState({
    username: '',
    password: '',
    profilePicture: null as File | null
  });
  const [postForm, setPostForm] = useState({
    title: '',
    content: '',
    type: 'other' as const,
    communityId: '',
    context: '',
    attachments: [] as File[]
  });
  const [commentForm, setCommentForm] = useState({
    content: '',
    attachments: [] as File[]
  });

  // Edit states
  const [editingPost, setEditingPost] = useState<Submission | null>(null);
  const [editingComment, setEditingComment] = useState<Comment | null>(null);
  const [editPostForm, setEditPostForm] = useState({
    title: '',
    content: '',
    context: '',
    attachments: [] as File[],
    removeAttachments: [] as string[]
  });
  const [editCommentForm, setEditCommentForm] = useState({
    content: '',
    attachments: [] as File[],
    removeAttachments: [] as string[]
  });

  // Dark mode effect
  useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('darkMode', JSON.stringify(isDarkMode));
  }, [isDarkMode]);

  // Initialize app
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      fetchUserProfile();
    }
    fetchCommunities();
    fetchSubmissions();
    fetchTrendingSubmissions();
    fetchStats();
  }, []);

  // API calls
  const fetchUserProfile = async () => {
    try {
      const response = await fetch(`${API_BASE}/auth/profile`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setUser(data.user);
      }
    } catch (error) {
      console.error('Failed to fetch user profile:', error);
    }
  };

  const fetchCommunities = async () => {
    try {
      const response = await fetch(`${API_BASE}/communities`, {
        headers: getAuthHeaders()
      });
      if (response.ok) {
        const data = await response.json();
        setCommunities(data);
      }
    } catch (error) {
      console.error('Failed to fetch communities:', error);
    }
  };

  const fetchSubmissions = async () => {
    try {
      const params = new URLSearchParams();
      if (selectedCommunity) params.append('community', selectedCommunity);
      params.append('sort', sortBy);
      
      const response = await fetch(`${API_BASE}/submissions?${params}`);
      if (response.ok) {
        const data = await response.json();
        setSubmissions(data.submissions || data);
      }
    } catch (error) {
      console.error('Failed to fetch submissions:', error);
    }
  };

  const fetchTrendingSubmissions = async () => {
    try {
      const response = await fetch(`${API_BASE}/submissions/trending`);
      if (response.ok) {
        const data = await response.json();
        setTrendingSubmissions(data);
      }
    } catch (error) {
      console.error('Failed to fetch trending submissions:', error);
    }
  };

  const fetchSubmissionDetails = async (id: string) => {
    try {
      const response = await fetch(`${API_BASE}/submissions/${id}`);
      if (response.ok) {
        const submission = await response.json();
        setSelectedSubmission(submission);
        fetchComments(id);
      }
    } catch (error) {
      console.error('Failed to fetch submission details:', error);
    }
  };

  const fetchSubmissionDetailsNoViews = async (id: string) => {
    try {
      const response = await fetch(`${API_BASE}/submissions/${id}/details`);
      if (response.ok) {
        const submission = await response.json();
        setSelectedSubmission(submission);
        return submission;
      }
    } catch (error) {
      console.error('Failed to fetch submission details:', error);
    }
  };

  const fetchComments = async (submissionId: string) => {
    try {
      const response = await fetch(`${API_BASE}/submissions/${submissionId}/comments`);
      if (response.ok) {
        const data = await response.json();
        setComments(data);
      }
    } catch (error) {
      console.error('Failed to fetch comments:', error);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await fetch(`${API_BASE}/stats`);
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  };

  // Auth functions
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginForm)
      });

      const data = await response.json();
      if (response.ok) {
        localStorage.setItem('token', data.token);
        setUser(data.user);
        setCurrentView('home');
        setSuccess('Login successful!');
        setLoginForm({ email: '', password: '' });
      } else {
        setError(data.error);
      }
    } catch (error) {
      setError('Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (registerForm.password !== registerForm.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    try {
      const formData = new FormData();
      formData.append('username', registerForm.username);
      formData.append('email', registerForm.email);
      formData.append('password', registerForm.password);
      formData.append('nid', registerForm.nid);
      if (registerForm.profilePicture) {
        formData.append('profilePicture', registerForm.profilePicture);
      }

      const response = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        body: formData
      });

      const data = await response.json();
      if (response.ok) {
        localStorage.setItem('token', data.token);
        setUser(data.user);
        setCurrentView('home');
        setSuccess('Registration successful!');
        setRegisterForm({ username: '', email: '', password: '', confirmPassword: '', nid: '', profilePicture: null });
      } else {
        setError(data.error);
      }
    } catch (error) {
      setError('Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE}/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(forgotPasswordForm)
      });

      const data = await response.json();
      if (response.ok) {
        setOtpForm({ ...otpForm, email: forgotPasswordForm.email });
        setCurrentView('verify-otp');
        setSuccess(data.message);
      } else {
        setError(data.error);
      }
    } catch (error) {
      setError('Failed to send OTP. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE}/auth/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(otpForm)
      });

      const data = await response.json();
      if (response.ok) {
        setResetPasswordForm({ ...resetPasswordForm, resetToken: data.resetToken });
        setCurrentView('reset-password');
        setSuccess(data.message);
      } else {
        setError(data.error);
      }
    } catch (error) {
      setError('OTP verification failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE}/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(resetPasswordForm)
      });

      const data = await response.json();
      if (response.ok) {
        setCurrentView('login');
        setSuccess('Password reset successful! Please login with your new password.');
        setResetPasswordForm({ resetToken: '', newPassword: '', confirmPassword: '' });
      } else {
        setError(data.error);
      }
    } catch (error) {
      setError('Password reset failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const formData = new FormData();
      if (profileForm.username) formData.append('username', profileForm.username);
      if (profileForm.password) formData.append('password', profileForm.password);
      if (profileForm.profilePicture) formData.append('profilePicture', profileForm.profilePicture);

      const response = await fetch(`${API_BASE}/auth/profile`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: formData
      });

      const data = await response.json();
      if (response.ok) {
        setUser(data.user);
        setSuccess('Profile updated successfully!');
        setProfileForm({ username: '', password: '', profilePicture: null });
      } else {
        setError(data.error);
      }
    } catch (error) {
      setError('Profile update failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setUser(null);
    setCurrentView('home');
    setSuccess('Logged out successfully!');
  };

  // Post functions
  const handleCreatePost = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const formData = new FormData();
      formData.append('title', postForm.title);
      formData.append('content', postForm.content);
      formData.append('type', postForm.type);
      formData.append('communityId', postForm.communityId);
      if (postForm.context) formData.append('context', postForm.context);
      
      postForm.attachments.forEach(file => {
        formData.append('attachments', file);
      });

      const response = await fetch(`${API_BASE}/submissions`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: formData
      });

      const data = await response.json();
      if (response.ok) {
        setCurrentView('home');
        setSuccess('Post created successfully!');
        setPostForm({ title: '', content: '', type: 'other', communityId: '', context: '', attachments: [] });
        fetchSubmissions();
        fetchTrendingSubmissions();
      } else {
        setError(data.error);
      }
    } catch (error) {
      setError('Failed to create post. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdatePost = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingPost) return;
    
    setLoading(true);
    setError('');

    try {
      const formData = new FormData();
      if (editPostForm.title) formData.append('title', editPostForm.title);
      if (editPostForm.content) formData.append('content', editPostForm.content);
      if (editPostForm.context) formData.append('context', editPostForm.context);
      if (editPostForm.removeAttachments.length > 0) {
        formData.append('removeAttachments', JSON.stringify(editPostForm.removeAttachments));
      }
      
      editPostForm.attachments.forEach(file => {
        formData.append('attachments', file);
      });

      const response = await fetch(`${API_BASE}/submissions/${editingPost._id}`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: formData
      });

      const data = await response.json();
      if (response.ok) {
        setCurrentView('post-detail');
        setSelectedSubmission(data);
        setSuccess('Post updated successfully!');
        setEditingPost(null);
        setEditPostForm({ title: '', content: '', context: '', attachments: [], removeAttachments: [] });
        fetchSubmissions();
        fetchTrendingSubmissions();
      } else {
        setError(data.error);
      }
    } catch (error) {
      setError('Failed to update post. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleDeletePost = async (postId: string) => {
    if (!confirm('Are you sure you want to delete this post?')) return;

    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/submissions/${postId}`, {
        method: 'DELETE',
        headers: getAuthHeaders()
      });

      if (response.ok) {
        setCurrentView('home');
        setSuccess('Post deleted successfully!');
        fetchSubmissions();
        fetchTrendingSubmissions();
      } else {
        const data = await response.json();
        setError(data.error);
      }
    } catch (error) {
      setError('Failed to delete post. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Comment functions
  const handleCreateComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSubmission) return;

    setLoading(true);
    setError('');

    try {
      const formData = new FormData();
      formData.append('content', commentForm.content);
      
      commentForm.attachments.forEach(file => {
        formData.append('attachments', file);
      });

      const response = await fetch(`${API_BASE}/submissions/${selectedSubmission._id}/comments`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: formData
      });

      const data = await response.json();
      if (response.ok) {
        setCommentForm({ content: '', attachments: [] });
        fetchComments(selectedSubmission._id);
        setSuccess('Comment added successfully!');
      } else {
        setError(data.error);
      }
    } catch (error) {
      setError('Failed to add comment. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingComment) return;
    
    setLoading(true);
    setError('');

    try {
      const formData = new FormData();
      if (editCommentForm.content) formData.append('content', editCommentForm.content);
      if (editCommentForm.removeAttachments.length > 0) {
        formData.append('removeAttachments', JSON.stringify(editCommentForm.removeAttachments));
      }
      
      editCommentForm.attachments.forEach(file => {
        formData.append('attachments', file);
      });

      const response = await fetch(`${API_BASE}/comments/${editingComment._id}`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: formData
      });

      const data = await response.json();
      if (response.ok) {
        setCurrentView('post-detail');
        setSuccess('Comment updated successfully!');
        setEditingComment(null);
        setEditCommentForm({ content: '', attachments: [], removeAttachments: [] });
        if (selectedSubmission) {
          fetchComments(selectedSubmission._id);
        }
      } else {
        setError(data.error);
      }
    } catch (error) {
      setError('Failed to update comment. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteComment = async (commentId: string) => {
    if (!confirm('Are you sure you want to delete this comment?')) return;

    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/comments/${commentId}`, {
        method: 'DELETE',
        headers: getAuthHeaders()
      });

      if (response.ok) {
        setSuccess('Comment deleted successfully!');
        if (selectedSubmission) {
          fetchComments(selectedSubmission._id);
        }
      } else {
        const data = await response.json();
        setError(data.error);
      }
    } catch (error) {
      setError('Failed to delete comment. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Voting functions
  const handleVote = async (submissionId: string, voteType: 'legit' | 'scam' | 'unsure') => {
    try {
      const response = await fetch(`${API_BASE}/submissions/${submissionId}/vote`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders()
        },
        body: JSON.stringify({ voteType })
      });

      if (response.ok) {
        const data = await response.json();
        setSelectedSubmission(data.submission);
        fetchSubmissions();
        fetchTrendingSubmissions();
      }
    } catch (error) {
      console.error('Failed to vote:', error);
    }
  };

  const handleFollowCommunity = async (communityId: string) => {
    try {
      const response = await fetch(`${API_BASE}/communities/${communityId}/follow`, {
        method: 'POST',
        headers: getAuthHeaders()
      });

      if (response.ok) {
        fetchCommunities();
        fetchUserProfile();
      }
    } catch (error) {
      console.error('Failed to follow community:', error);
    }
  };

  const handleUnfollowCommunity = async (communityId: string) => {
    try {
      const response = await fetch(`${API_BASE}/communities/${communityId}/unfollow`, {
        method: 'POST',
        headers: getAuthHeaders()
      });

      if (response.ok) {
        fetchCommunities();
        fetchUserProfile();
      }
    } catch (error) {
      console.error('Failed to unfollow community:', error);
    }
  };

  // Effect hooks
  useEffect(() => {
    fetchSubmissions();
  }, [selectedCommunity, sortBy]);

  useEffect(() => {
    if (success) {
      const timer = setTimeout(() => setSuccess(''), 5000);
      return () => clearTimeout(timer);
    }
  }, [success]);

  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => setError(''), 5000);
      return () => clearTimeout(timer);
    }
  }, [error]);

  // Filter submissions and communities based on search
  const filteredSubmissions = submissions.filter(submission =>
    submission.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    submission.content.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredCommunities = communities.filter(community =>
    community.name.toLowerCase().includes(communitySearchTerm.toLowerCase()) ||
    community.description.toLowerCase().includes(communitySearchTerm.toLowerCase())
  );

  // Render functions
  const renderHeader = () => (
    <header className="bg-white dark:bg-gray-900 shadow-sm border-b dark:border-gray-700 sticky top-0 z-50 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <div className="flex items-center space-x-8">
            <button
              onClick={() => setCurrentView('home')}
              className="flex items-center space-x-2 text-xl font-bold text-gray-900 dark:text-white hover:text-red-600 dark:hover:text-red-400 transition-colors"
            >
              <Shield className="w-8 h-8 text-red-600 dark:text-red-500" />
              <span>ScamAlert</span>
            </button>

            {/* Navigation Links */}
            <nav className="hidden md:flex space-x-8">
              <button
                onClick={() => setCurrentView('home')}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors ${
                  currentView === 'home' 
                    ? 'text-red-600 bg-red-50 dark:text-red-400 dark:bg-red-900/20' 
                    : 'text-gray-600 dark:text-gray-300 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20'
                }`}
              >
                <Home className="w-4 h-4" />
                <span>Home</span>
              </button>
              <button
                onClick={() => setCurrentView('communities')}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors ${
                  currentView === 'communities' 
                    ? 'text-red-600 bg-red-50 dark:text-red-400 dark:bg-red-900/20' 
                    : 'text-gray-600 dark:text-gray-300 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20'
                }`}
              >
                <Users className="w-4 h-4" />
                <span>Communities</span>
              </button>
              <button
                onClick={() => setCurrentView('trending')}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors ${
                  currentView === 'trending' 
                    ? 'text-red-600 bg-red-50 dark:text-red-400 dark:bg-red-900/20' 
                    : 'text-gray-600 dark:text-gray-300 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20'
                }`}
              >
                <TrendingUp className="w-4 h-4" />
                <span>Trending</span>
              </button>
            </nav>
          </div>

          <div className="flex items-center space-x-4">
            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            >
              {isDarkMode ? (
                <Sun className="w-5 h-5 text-yellow-500" />
              ) : (
                <Moon className="w-5 h-5 text-gray-600" />
              )}
            </button>
            
            {user ? (
              <>
                <button
                  onClick={() => setCurrentView('create-post')}
                  className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-all duration-300 flex items-center space-x-2 transform hover:scale-105"
                >
                  <Plus className="w-4 h-4" />
                  <span>Report Scam</span>
                </button>
                
                <div className="relative group">
                  <button className="flex items-center space-x-2 p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors">
                    <ProfilePicture user={user} size="sm" />
                    <span className="text-sm font-medium dark:text-white">{user.username}</span>
                  </button>
                  
                  <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-lg shadow-lg border dark:border-gray-700 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200">
                    <div className="py-1">
                      <button
                        onClick={() => setCurrentView('profile')}
                        className="flex items-center space-x-2 w-full px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                      >
                        <Settings className="w-4 h-4" />
                        <span>Profile Settings</span>
                      </button>
                      <button
                        onClick={handleLogout}
                        className="flex items-center space-x-2 w-full px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                      >
                        <LogOut className="w-4 h-4" />
                        <span>Logout</span>
                      </button>
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setCurrentView('login')}
                  className="text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white px-3 py-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                >
                  Login
                </button>
                <button
                  onClick={() => setCurrentView('register')}
                  className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-all duration-300 transform hover:scale-105"
                >
                  Sign Up
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );

  const renderNotifications = () => (
    <>
      {success && (
        <div className="fixed top-20 right-4 bg-green-500 text-white px-6 py-3 rounded-lg shadow-lg z-50 flex items-center space-x-2 animate-fade-in">
          <Check className="w-5 h-5" />
          <span>{success}</span>
        </div>
      )}
      {error && (
        <div className="fixed top-20 right-4 bg-red-500 text-white px-6 py-3 rounded-lg shadow-lg z-50 flex items-center space-x-2 animate-fade-in">
          <AlertCircle className="w-5 h-5" />
          <span>{error}</span>
        </div>
      )}
    </>
  );

  const renderHome = () => (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Hero Section */}
      <div className="bg-gradient-to-r from-red-600 to-pink-700 dark:from-red-700 dark:to-pink-800 rounded-2xl p-8 mb-8 text-white transition-colors">
        <div className="max-w-3xl">
          <h1 className="text-4xl font-bold mb-4">Protect Yourself from Scams</h1>
          <p className="text-xl mb-6 text-red-100">
            Join our community to report, identify, and stay safe from online scams and fraudulent activities.
          </p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center transform hover:scale-105 transition-transform">
              <div className="text-2xl font-bold">{stats.totalSubmissions}</div>
              <div className="text-sm text-red-200">Reports</div>
            </div>
            <div className="text-center transform hover:scale-105 transition-transform">
              <div className="text-2xl font-bold">{stats.totalUsers}</div>
              <div className="text-sm text-red-200">Users</div>
            </div>
            <div className="text-center transform hover:scale-105 transition-transform">
              <div className="text-2xl font-bold">{stats.totalCommunities}</div>
              <div className="text-sm text-red-200">Communities</div>
            </div>
            <div className="text-center transform hover:scale-105 transition-transform">
              <div className="text-2xl font-bold">{stats.totalScams}</div>
              <div className="text-sm text-red-200">Confirmed Scams</div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Sidebar */}
        <div className="lg:col-span-1">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border dark:border-gray-700 p-6 mb-6 transition-colors">
            <h3 className="text-lg font-semibold mb-4 dark:text-white">Communities</h3>
            <div className="space-y-2">
              <button
                onClick={() => setSelectedCommunity('')}
                className={`w-full text-left px-3 py-2 rounded-lg transition-colors ${
                  selectedCommunity === '' 
                    ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300' 
                    : 'hover:bg-gray-100 dark:hover:bg-gray-700 dark:text-gray-300'
                }`}
              >
                All Communities
              </button>
              {communities.slice(0, 6).map(community => (
                <div key={community._id} className="flex items-center justify-between">
                  <button
                    onClick={() => setSelectedCommunity(community._id)}
                    className={`flex-1 text-left px-3 py-2 rounded-lg transition-colors ${
                      selectedCommunity === community._id 
                        ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300' 
                        : 'hover:bg-gray-100 dark:hover:bg-gray-700'
                    }`}
                  >
                    <div className="flex items-center space-x-2">
                      <span>{community.icon}</span>
                      <div>
                        <div className="font-medium text-sm dark:text-white">{community.name}</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">{community.memberCount} members</div>
                      </div>
                    </div>
                  </button>
                  {user && (
                    <button
                      onClick={() => community.isFollowing ? 
                        handleUnfollowCommunity(community._id) : 
                        handleFollowCommunity(community._id)
                      }
                      className={`ml-2 px-2 py-1 text-xs rounded transition-all duration-300 transform hover:scale-105 ${
                        community.isFollowing 
                          ? 'bg-gray-200 text-gray-700 hover:bg-gray-300 dark:bg-gray-600 dark:text-gray-300 dark:hover:bg-gray-500' 
                          : 'bg-red-600 text-white hover:bg-red-700'
                      }`}
                    >
                      {community.isFollowing ? 'Following' : 'Follow'}
                    </button>
                  )}
                </div>
              ))}
              <button
                onClick={() => setCurrentView('communities')}
                className="w-full text-left px-3 py-2 rounded-lg text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors text-sm font-medium"
              >
                View All Communities →
              </button>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="lg:col-span-3">
          {/* Search and Filters */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border dark:border-gray-700 p-6 mb-6 transition-colors">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500 w-5 h-5" />
                <input
                  type="text"
                  placeholder="Search reports..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent dark:bg-gray-700 dark:text-white transition-colors"
                />
              </div>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as 'recent' | 'trending' | 'dangerous')}
                className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent dark:bg-gray-700 dark:text-white transition-colors"
              >
                <option value="recent">Most Recent</option>
                <option value="trending">Trending</option>
                <option value="dangerous">Most Dangerous</option>
              </select>
            </div>
          </div>

          {/* Submissions */}
          <div className="space-y-6">
            {filteredSubmissions.map(submission => (
              <div 
                key={submission._id} 
                className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border dark:border-gray-700 hover:shadow-lg transition-all duration-300 cursor-pointer transform hover:scale-[1.02]"
                onClick={() => {
                  setSelectedSubmission(submission);
                  setCurrentView('post-detail');
                  fetchSubmissionDetails(submission._id);
                }}
              >
                <div className="p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center space-x-3">
                      <ProfilePicture user={submission.author} size="md" />
                      <div>
                        <div className="font-medium text-gray-900 dark:text-white">{submission.author.username}</div>
                        <div className="text-sm text-gray-500 dark:text-gray-400">
                          {formatDate(submission.createdAt)} • {submission.community.name}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${getRiskColor(submission.aiAnalysis.riskLevel)}`}>
                        {submission.aiAnalysis.riskLevel.toUpperCase()} RISK
                      </span>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${getScamScoreColor(submission.scamScore)}`}>
                        {Math.round(submission.scamScore)}% SCAM
                      </span>
                    </div>
                  </div>

                  <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">{submission.title}</h3>
                  <p className="text-gray-700 dark:text-gray-300 mb-4 line-clamp-3">{submission.content}</p>

                  {submission.attachments.length > 0 && (
                    <div className="mb-4">
                      <div className="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-400 mb-2">
                        <Camera className="w-4 h-4" />
                        <span>{submission.attachments.length} attachment(s)</span>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                        {submission.attachments.slice(0, 3).map((attachment, index) => (
                          <div key={index} className="relative overflow-hidden rounded-lg">
                            <MediaPreview attachment={attachment} isPreview={true} />
                            {index === 2 && submission.attachments.length > 3 && (
                              <div className="absolute inset-0 bg-black bg-opacity-50 rounded-lg flex items-center justify-center text-white font-medium">
                                +{submission.attachments.length - 3}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <span className="flex items-center space-x-1 text-gray-600 dark:text-gray-400">
                        <Eye className="w-4 h-4" />
                        <span>{submission.viewCount} views</span>
                      </span>
                      <span className="flex items-center space-x-1 text-gray-600 dark:text-gray-400">
                        <MessageCircle className="w-4 h-4" />
                        <span>{submission.commentCount} comments</span>
                      </span>
                    </div>

                    {user && (
                      <div className="flex items-center space-x-2" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => handleVote(submission._id, 'legit')}
                          className={`px-3 py-1 text-xs rounded-full transition-all duration-300 transform hover:scale-105 ${
                            submission.votes.legit.includes(user.id)
                              ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'
                              : 'bg-gray-100 text-gray-600 hover:bg-green-100 hover:text-green-700 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-green-900 dark:hover:text-green-300'
                          }`}
                        >
                          <ThumbsUp className="w-3 h-3 inline mr-1" />
                          Legit ({submission.votes.legit.length})
                        </button>
                        <button
                          onClick={() => handleVote(submission._id, 'scam')}
                          className={`px-3 py-1 text-xs rounded-full transition-all duration-300 transform hover:scale-105 ${
                            submission.votes.scam.includes(user.id)
                              ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300'
                              : 'bg-gray-100 text-gray-600 hover:bg-red-100 hover:text-red-700 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-red-900 dark:hover:text-red-300'
                          }`}
                        >
                          <ThumbsDown className="w-3 h-3 inline mr-1" />
                          Scam ({submission.votes.scam.length})
                        </button>
                        <button
                          onClick={() => handleVote(submission._id, 'unsure')}
                          className={`px-3 py-1 text-xs rounded-full transition-all duration-300 transform hover:scale-105 ${
                            submission.votes.unsure.includes(user.id)
                              ? 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300'
                              : 'bg-gray-100 text-gray-600 hover:bg-orange-100 hover:text-orange-700 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-orange-900 dark:hover:text-orange-300'
                          }`}
                        >
                          <AlertCircle className="w-3 h-3 inline mr-1" />
                          Unsure ({submission.votes.unsure.length})
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}

            {filteredSubmissions.length === 0 && (
              <div className="text-center py-12">
                <AlertTriangle className="w-12 h-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No reports found</h3>
                <p className="text-gray-600 dark:text-gray-400">Try adjusting your search or filters.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );

  const renderCommunities = () => (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">Communities</h1>
        <p className="text-gray-600 dark:text-gray-400">Join communities to stay updated on specific types of scams</p>
      </div>

      {/* Search */}
      <div className="mb-8">
        <div className="relative max-w-md">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500 w-5 h-5" />
          <input
            type="text"
            placeholder="Search communities..."
            value={communitySearchTerm}
            onChange={(e) => setCommunitySearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent dark:bg-gray-700 dark:text-white transition-colors"
          />
        </div>
      </div>

      {/* Communities Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredCommunities.map(community => (
          <div 
            key={community._id}
            className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border dark:border-gray-700 p-6 hover:shadow-lg transition-all duration-300 transform hover:scale-105"
          >
            <div className="flex items-start justify-between mb-4">
              <div 
                className="w-12 h-12 rounded-lg flex items-center justify-center text-2xl"
                style={{ backgroundColor: community.color + '20', color: community.color }}
              >
                {community.icon}
              </div>
              {user && (
                <button
                  onClick={() => community.isFollowing ? 
                    handleUnfollowCommunity(community._id) : 
                    handleFollowCommunity(community._id)
                  }
                  className={`px-3 py-1 text-sm rounded-lg transition-all duration-300 transform hover:scale-105 ${
                    community.isFollowing 
                      ? 'bg-gray-200 text-gray-700 hover:bg-gray-300 dark:bg-gray-600 dark:text-gray-300 dark:hover:bg-gray-500' 
                      : 'bg-red-600 text-white hover:bg-red-700'
                  }`}
                >
                  {community.isFollowing ? 'Following' : 'Follow'}
                </button>
              )}
            </div>

            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">{community.name}</h3>
            <p className="text-gray-600 dark:text-gray-400 text-sm mb-4 line-clamp-3">{community.description}</p>

            <div className="flex items-center justify-between text-sm text-gray-500 dark:text-gray-400">
              <span className="flex items-center space-x-1">
                <Users className="w-4 h-4" />
                <span>{community.memberCount} followers</span>
              </span>
              <span className="flex items-center space-x-1">
                <MessageCircle className="w-4 h-4" />
                <span>{community.postCount} posts</span>
              </span>
            </div>
          </div>
        ))}
      </div>

      {filteredCommunities.length === 0 && (
        <div className="text-center py-12">
          <Users className="w-12 h-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No communities found</h3>
          <p className="text-gray-600 dark:text-gray-400">Try adjusting your search terms.</p>
        </div>
      )}
    </div>
  );

  const renderTrending = () => (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">Trending Scams</h1>
        <p className="text-gray-600 dark:text-gray-400">Most discussed and dangerous scams in our community</p>
      </div>

      <div className="space-y-4">
        {trendingSubmissions.map((submission, index) => (
          <div 
            key={submission._id}
            className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border dark:border-gray-700 p-6 hover:shadow-lg transition-all duration-300 cursor-pointer transform hover:scale-[1.02]"
            onClick={() => {
              setSelectedSubmission(submission);
              setCurrentView('post-detail');
              fetchSubmissionDetails(submission._id);
            }}
          >
            <div className="flex items-start space-x-4">
              {/* Ranking Number */}
              <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center font-bold text-white ${
                index === 0 ? 'bg-yellow-500' : 
                index === 1 ? 'bg-gray-400' : 
                index === 2 ? 'bg-orange-500' : 
                'bg-gray-300 dark:bg-gray-600'
              }`}>
                {index + 1}
              </div>

              {/* Community Icon */}
              <div 
                className="flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center text-lg"
                style={{ backgroundColor: submission.community.color + '20', color: submission.community.color }}
              >
                {submission.community.icon}
              </div>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-1 line-clamp-2">
                      {submission.title}
                    </h3>
                    <div className="flex items-center space-x-2 text-sm text-gray-500 dark:text-gray-400">
                      <span>by {submission.author.username}</span>
                      <span>•</span>
                      <span>{submission.community.name}</span>
                      <span>•</span>
                      <span>{formatDate(submission.createdAt)}</span>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2 flex-shrink-0">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getRiskColor(submission.aiAnalysis.riskLevel)}`}>
                      {submission.aiAnalysis.riskLevel.toUpperCase()} RISK
                    </span>
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getScamScoreColor(submission.scamScore)}`}>
                      {Math.round(submission.scamScore)}% SCAM
                    </span>
                  </div>
                </div>

                <p className="text-gray-700 dark:text-gray-300 text-sm mb-4 line-clamp-2">
                  {submission.content}
                </p>

                {/* Engagement Stats */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="flex items-center space-x-4 text-sm text-gray-600 dark:text-gray-400">
                      <div className="flex items-center space-x-1">
                        <ThumbsUp className="w-4 h-4 text-green-600" />
                        <span>{submission.votes.legit.length}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <ThumbsDown className="w-4 h-4 text-red-600" />
                        <span>{submission.votes.scam.length}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <AlertCircle className="w-4 h-4 text-orange-600" />
                        <span>{submission.votes.unsure.length}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-4 text-sm text-gray-600 dark:text-gray-400">
                    <span className="flex items-center space-x-1">
                      <Eye className="w-4 h-4" />
                      <span>{submission.viewCount}</span>
                    </span>
                    <span className="flex items-center space-x-1">
                      <MessageCircle className="w-4 h-4" />
                      <span>{submission.commentCount}</span>
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}

        {trendingSubmissions.length === 0 && (
          <div className="text-center py-12">
            <TrendingUp className="w-12 h-12 text-gray-400 dark:text-gray-500 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No trending posts yet</h3>
            <p className="text-gray-600 dark:text-gray-400">Check back later for trending scam reports.</p>
          </div>
        )}
      </div>
    </div>
  );

  const renderLogin = () => (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 transition-colors">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <Shield className="mx-auto h-12 w-12 text-red-600 dark:text-red-500" />
          <h2 className="mt-6 text-3xl font-extrabold text-gray-900 dark:text-white">Sign in to your account</h2>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleLogin}>
          <div className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Email address
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                value={loginForm.email}
                onChange={(e) => setLoginForm({ ...loginForm, email: e.target.value })}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Password
              </label>
              <PasswordInput
                id="password"
                name="password"
                value={loginForm.password}
                onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
                required
              />
            </div>
          </div>

          <div className="flex items-center justify-between">
            <button
              type="button"
              onClick={() => setCurrentView('forgot-password')}
              className="text-sm text-red-600 hover:text-red-500 dark:text-red-400 dark:hover:text-red-300 transition-colors"
            >
              Forgot your password?
            </button>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 transition-all duration-300 transform hover:scale-105"
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
          </div>

          <div className="text-center">
            <span className="text-sm text-gray-600 dark:text-gray-400">
              Don't have an account?{' '}
              <button
                type="button"
                onClick={() => setCurrentView('register')}
                className="font-medium text-red-600 hover:text-red-500 dark:text-red-400 dark:hover:text-red-300 transition-colors"
              >
                Sign up
              </button>
            </span>
          </div>
        </form>
      </div>
    </div>
  );

  const renderRegister = () => (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 transition-colors">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <Shield className="mx-auto h-12 w-12 text-red-600 dark:text-red-500" />
          <h2 className="mt-6 text-3xl font-extrabold text-gray-900 dark:text-white">Create your account</h2>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleRegister}>
          <div className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                required
                value={registerForm.username}
                onChange={(e) => setRegisterForm({ ...registerForm, username: e.target.value })}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
              />
            </div>
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Email address
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                value={registerForm.email}
                onChange={(e) => setRegisterForm({ ...registerForm, email: e.target.value })}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Password
              </label>
              <PasswordInput
                id="password"
                name="password"
                value={registerForm.password}
                onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })}
                required
                showStrength={true}
              />
            </div>
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Confirm Password
              </label>
              <PasswordInput
                id="confirmPassword"
                name="confirmPassword"
                value={registerForm.confirmPassword}
                onChange={(e) => setRegisterForm({ ...registerForm, confirmPassword: e.target.value })}
                required
              />
              {registerForm.confirmPassword && registerForm.password !== registerForm.confirmPassword && (
                <p className="mt-1 text-sm text-red-600 dark:text-red-400">Passwords do not match</p>
              )}
            </div>
            <div>
              <label htmlFor="nid" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                National ID Number
              </label>
              <input
                id="nid"
                name="nid"
                type="text"
                required
                value={registerForm.nid}
                onChange={(e) => setRegisterForm({ ...registerForm, nid: e.target.value })}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
              />
            </div>
            <div>
              <label htmlFor="profilePicture" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Profile Picture (Optional)
              </label>
              <input
                id="profilePicture"
                name="profilePicture"
                type="file"
                accept="image/*"
                onChange={(e) => setRegisterForm({ ...registerForm, profilePicture: e.target.files?.[0] || null })}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 transition-all duration-300 transform hover:scale-105"
            >
              {loading ? 'Creating account...' : 'Create account'}
            </button>
          </div>

          <div className="text-center">
            <span className="text-sm text-gray-600 dark:text-gray-400">
              Already have an account?{' '}
              <button
                type="button"
                onClick={() => setCurrentView('login')}
                className="font-medium text-red-600 hover:text-red-500 dark:text-red-400 dark:hover:text-red-300 transition-colors"
              >
                Sign in
              </button>
            </span>
          </div>
        </form>
      </div>
    </div>
  );

  const renderForgotPassword = () => (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 transition-colors">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <Lock className="mx-auto h-12 w-12 text-red-600 dark:text-red-500" />
          <h2 className="mt-6 text-3xl font-extrabold text-gray-900 dark:text-white">Forgot Password</h2>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Enter your email address and we'll send you an OTP to reset your password.
          </p>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleForgotPassword}>
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Email address
            </label>
            <input
              id="email"
              name="email"
              type="email"
              required
              value={forgotPasswordForm.email}
              onChange={(e) => setForgotPasswordForm({ ...forgotPasswordForm, email: e.target.value })}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
            />
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 transition-all duration-300 transform hover:scale-105"
            >
              <Mail className="w-4 h-4 mr-2" />
              {loading ? 'Sending OTP...' : 'Send OTP'}
            </button>
          </div>

          <div className="text-center">
            <button
              type="button"
              onClick={() => setCurrentView('login')}
              className="text-sm text-red-600 hover:text-red-500 dark:text-red-400 dark:hover:text-red-300 flex items-center justify-center space-x-1 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to login</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );

  const renderVerifyOtp = () => (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 transition-colors">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <KeyRound className="mx-auto h-12 w-12 text-red-600 dark:text-red-500" />
          <h2 className="mt-6 text-3xl font-extrabold text-gray-900 dark:text-white">Verify OTP</h2>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Enter the OTP code sent to your email. Check the terminal for the OTP.
          </p>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleVerifyOtp}>
          <div>
            <label htmlFor="otp" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              OTP Code
            </label>
            <input
              id="otp"
              name="otp"
              type="text"
              required
              maxLength={6}
              value={otpForm.otp}
              onChange={(e) => setOtpForm({ ...otpForm, otp: e.target.value })}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 text-center text-lg tracking-widest dark:bg-gray-700 dark:text-white transition-colors"
              placeholder="000000"
            />
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 transition-all duration-300 transform hover:scale-105"
            >
              {loading ? 'Verifying...' : 'Verify OTP'}
            </button>
          </div>

          <div className="text-center">
            <button
              type="button"
              onClick={() => setCurrentView('forgot-password')}
              className="text-sm text-red-600 hover:text-red-500 dark:text-red-400 dark:hover:text-red-300 flex items-center justify-center space-x-1 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to email</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );

  const renderResetPassword = () => (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 transition-colors">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <Lock className="mx-auto h-12 w-12 text-red-600 dark:text-red-500" />
          <h2 className="mt-6 text-3xl font-extrabold text-gray-900 dark:text-white">Reset Password</h2>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Enter your new password below.
          </p>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleResetPassword}>
          <div className="space-y-4">
            <div>
              <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                New Password
              </label>
              <PasswordInput
                id="newPassword"
                name="newPassword"
                value={resetPasswordForm.newPassword}
                onChange={(e) => setResetPasswordForm({ ...resetPasswordForm, newPassword: e.target.value })}
                required
                showStrength={true}
              />
            </div>
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Confirm Password
              </label>
              <PasswordInput
                id="confirmPasswordReset"
                name="confirmPasswordReset"
                value={resetPasswordForm.confirmPassword}
                onChange={(e) => setResetPasswordForm({ ...resetPasswordForm, confirmPassword: e.target.value })}
                required
              />
              {resetPasswordForm.confirmPassword && resetPasswordForm.newPassword !== resetPasswordForm.confirmPassword && (
                <p className="mt-1 text-sm text-red-600 dark:text-red-400">Passwords do not match</p>
              )}
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 transition-all duration-300 transform hover:scale-105"
            >
              {loading ? 'Resetting...' : 'Reset Password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );

  const renderProfile = () => (
    <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border dark:border-gray-700 p-6 transition-colors">
        <div className="flex items-center space-x-4 mb-6">
          <ProfilePicture user={user!} size="lg" />
          <div>
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">{user!.username}</h2>
            <p className="text-gray-600 dark:text-gray-400">{user!.email}</p>
            <div className="flex items-center space-x-4 mt-2">
              <span className="text-sm text-gray-500 dark:text-gray-400">Reputation: {user!.reputation}</span>
              <span className="text-sm text-gray-500 dark:text-gray-400">
                Joined: {formatDate(user!.createdAt)}
              </span>
            </div>
          </div>
        </div>

        <form onSubmit={handleUpdateProfile} className="space-y-6">
          <div>
            <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Username
            </label>
            <input
              id="username"
              name="username"
              type="text"
              value={profileForm.username}
              onChange={(e) => setProfileForm({ ...profileForm, username: e.target.value })}
              placeholder={user!.username}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              New Password (leave blank to keep current)
            </label>
            <PasswordInput
              id="profilePassword"
              name="profilePassword"
              value={profileForm.password}
              onChange={(e) => setProfileForm({ ...profileForm, password: e.target.value })}
              showStrength={profileForm.password.length > 0}
            />
          </div>

          <div>
            <label htmlFor="profilePicture" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Profile Picture
            </label>
            <input
              id="profilePicture"
              name="profilePicture"
              type="file"
              accept="image/*"
              onChange={(e) => setProfileForm({ ...profileForm, profilePicture: e.target.files?.[0] || null })}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
            />
          </div>

          <div className="flex space-x-4">
            <button
              type="submit"
              disabled={loading}
              className="flex-1 bg-red-600 text-white py-2 px-4 rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 disabled:opacity-50 transition-all duration-300 transform hover:scale-105"
            >
              {loading ? 'Updating...' : 'Update Profile'}
            </button>
            <button
              type="button"
              onClick={() => setCurrentView('home')}
              className="flex-1 bg-gray-300 dark:bg-gray-600 text-gray-700 dark:text-gray-300 py-2 px-4 rounded-md hover:bg-gray-400 dark:hover:bg-gray-500 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition-all duration-300"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );

  const renderCreatePost = () => (
    <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border dark:border-gray-700 p-6 transition-colors">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">Report a Scam</h2>
        
        <form onSubmit={handleCreatePost} className="space-y-6">
          <div>
            <label htmlFor="title" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Title *
            </label>
            <input
              id="title"
              name="title"
              type="text"
              required
              value={postForm.title}
              onChange={(e) => setPostForm({ ...postForm, title: e.target.value })}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
              placeholder="Brief description of the scam"
            />
          </div>

          <div>
            <label htmlFor="type" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Scam Type *
            </label>
            <select
              id="type"
              name="type"
              required
              value={postForm.type}
              onChange={(e) => setPostForm({ ...postForm, type: e.target.value as any })}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
            >
              <option value="email">Email Scam</option>
              <option value="sms">SMS/Text Scam</option>
              <option value="call">Phone Call Scam</option>
              <option value="url">Website/URL Scam</option>
              <option value="advertisement">Advertisement Scam</option>
              <option value="other">Other</option>
            </select>
          </div>

          <div>
            <label htmlFor="community" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Community *
            </label>
            <select
              id="community"
              name="community"
              required
              value={postForm.communityId}
              onChange={(e) => setPostForm({ ...postForm, communityId: e.target.value })}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
            >
              <option value="">Select a community</option>
              {communities.map(community => (
                <option key={community._id} value={community._id}>
                  {community.icon} {community.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="content" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Description *
            </label>
            <textarea
              id="content"
              name="content"
              required
              rows={6}
              value={postForm.content}
              onChange={(e) => setPostForm({ ...postForm, content: e.target.value })}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
              placeholder="Detailed description of the scam, including any messages, phone numbers, websites, etc."
            />
          </div>

          <div>
            <label htmlFor="context" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Additional Context
            </label>
            <textarea
              id="context"
              name="context"
              rows={3}
              value={postForm.context}
              onChange={(e) => setPostForm({ ...postForm, context: e.target.value })}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
              placeholder="Any additional information that might be helpful"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Attachments (Screenshots, recordings, etc.)
            </label>
            <FileUpload
              onFilesSelected={(files) => setPostForm({ ...postForm, attachments: Array.from(files) })}
              multiple={true}
              maxFiles={10}
            />
            {postForm.attachments.length > 0 && (
              <div className="mt-2">
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">Selected files:</p>
                <div className="space-y-1">
                  {postForm.attachments.map((file, index) => (
                    <div key={index} className="flex items-center justify-between bg-gray-50 dark:bg-gray-700 p-2 rounded transition-colors">
                      <span className="text-sm text-gray-700 dark:text-gray-300">{file.name}</span>
                      <button
                        type="button"
                        onClick={() => setPostForm({
                          ...postForm,
                          attachments: postForm.attachments.filter((_, i) => i !== index)
                        })}
                        className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 transition-colors"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="flex space-x-4">
            <button
              type="submit"
              disabled={loading}
              className="flex-1 bg-red-600 text-white py-2 px-4 rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 disabled:opacity-50 transition-all duration-300 transform hover:scale-105"
            >
              {loading ? 'Creating...' : 'Create Report'}
            </button>
            <button
              type="button"
              onClick={() => setCurrentView('home')}
              className="flex-1 bg-gray-300 dark:bg-gray-600 text-gray-700 dark:text-gray-300 py-2 px-4 rounded-md hover:bg-gray-400 dark:hover:bg-gray-500 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition-all duration-300"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );

  const renderEditPost = () => {
    if (!editingPost) return null;

    return (
      <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border dark:border-gray-700 p-6 transition-colors">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Edit Report</h2>
            <button
              onClick={() => {
                setCurrentView('post-detail');
                setEditingPost(null);
                setEditPostForm({ title: '', content: '', context: '', attachments: [], removeAttachments: [] });
              }}
              className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 flex items-center space-x-1 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to report</span>
            </button>
          </div>
          
          <form onSubmit={handleUpdatePost} className="space-y-6">
            <div>
              <label htmlFor="title" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Title
              </label>
              <input
                id="title"
                name="title"
                type="text"
                value={editPostForm.title}
                onChange={(e) => setEditPostForm({ ...editPostForm, title: e.target.value })}
                placeholder={editingPost.title}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
              />
            </div>

            <div>
              <label htmlFor="content" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Description
              </label>
              <textarea
                id="content"
                name="content"
                rows={6}
                value={editPostForm.content}
                onChange={(e) => setEditPostForm({ ...editPostForm, content: e.target.value })}
                placeholder={editingPost.content}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
              />
            </div>

            <div>
              <label htmlFor="context" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Additional Context
              </label>
              <textarea
                id="context"
                name="context"
                rows={3}
                value={editPostForm.context}
                onChange={(e) => setEditPostForm({ ...editPostForm, context: e.target.value })}
                placeholder={editingPost.context || 'Any additional information...'}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
              />
            </div>

            {/* Current attachments */}
            {editingPost.attachments.length > 0 && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Current Attachments
                </label>
                <div className="grid grid-cols-2 gap-4">
                  {editingPost.attachments.map((attachment, index) => (
                    <div key={index} className="relative">
                      <MediaPreview attachment={attachment} />
                      <button
                        type="button"
                        onClick={() => {
                          if (!editPostForm.removeAttachments.includes(attachment.filename)) {
                            setEditPostForm({
                              ...editPostForm,
                              removeAttachments: [...editPostForm.removeAttachments, attachment.filename]
                            });
                          }
                        }}
                        className={`absolute top-2 right-2 p-1 rounded-full transition-colors ${
                          editPostForm.removeAttachments.includes(attachment.filename)
                            ? 'bg-red-500 text-white'
                            : 'bg-black bg-opacity-50 text-white hover:bg-opacity-70'
                        }`}
                      >
                        <X className="w-4 h-4" />
                      </button>
                      {editPostForm.removeAttachments.includes(attachment.filename) && (
                        <div className="absolute inset-0 bg-red-500 bg-opacity-50 flex items-center justify-center rounded-lg">
                          <span className="text-white font-medium">Will be removed</span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* New attachments */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Add New Attachments
              </label>
              <FileUpload
                onFilesSelected={(files) => setEditPostForm({ ...editPostForm, attachments: Array.from(files) })}
                multiple={true}
                maxFiles={10}
              />
              {editPostForm.attachments.length > 0 && (
                <div className="mt-2">
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">New files to add:</p>
                  <div className="space-y-1">
                    {editPostForm.attachments.map((file, index) => (
                      <div key={index} className="flex items-center justify-between bg-gray-50 dark:bg-gray-700 p-2 rounded transition-colors">
                        <span className="text-sm text-gray-700 dark:text-gray-300">{file.name}</span>
                        <button
                          type="button"
                          onClick={() => setEditPostForm({
                            ...editPostForm,
                            attachments: editPostForm.attachments.filter((_, i) => i !== index)
                          })}
                          className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 transition-colors"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="flex space-x-4">
              <button
                type="submit"
                disabled={loading}
                className="flex-1 bg-red-600 text-white py-2 px-4 rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 disabled:opacity-50 transition-all duration-300 transform hover:scale-105"
              >
                {loading ? 'Updating...' : 'Update Report'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setCurrentView('post-detail');
                  setEditingPost(null);
                  setEditPostForm({ title: '', content: '', context: '', attachments: [], removeAttachments: [] });
                }}
                className="flex-1 bg-gray-300 dark:bg-gray-600 text-gray-700 dark:text-gray-300 py-2 px-4 rounded-md hover:bg-gray-400 dark:hover:bg-gray-500 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition-all duration-300"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  };

  const renderEditComment = () => {
    if (!editingComment) return null;

    return (
      <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border dark:border-gray-700 p-6 transition-colors">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Edit Comment</h2>
            <button
              onClick={() => {
                setCurrentView('post-detail');
                setEditingComment(null);
                setEditCommentForm({ content: '', attachments: [], removeAttachments: [] });
              }}
              className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 flex items-center space-x-1 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to report</span>
            </button>
          </div>
          
          <form onSubmit={handleUpdateComment} className="space-y-6">
            <div>
              <label htmlFor="content" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Comment
              </label>
              <textarea
                id="content"
                name="content"
                rows={4}
                value={editCommentForm.content}
                onChange={(e) => setEditCommentForm({ ...editCommentForm, content: e.target.value })}
                placeholder={editingComment.content}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-red-500 focus:border-red-500 dark:bg-gray-700 dark:text-white transition-colors"
              />
            </div>

            {/* Current attachments */}
            {editingComment.attachments.length > 0 && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Current Attachments
                </label>
                <div className="grid grid-cols-2 gap-4">
                  {editingComment.attachments.map((attachment, index) => (
                    <div key={index} className="relative">
                      <MediaPreview attachment={attachment} />
                      <button
                        type="button"
                        onClick={() => {
                          if (!editCommentForm.removeAttachments.includes(attachment.filename)) {
                            setEditCommentForm({
                              ...editCommentForm,
                              removeAttachments: [...editCommentForm.removeAttachments, attachment.filename]
                            });
                          }
                        }}
                        className={`absolute top-2 right-2 p-1 rounded-full transition-colors ${
                          editCommentForm.removeAttachments.includes(attachment.filename)
                            ? 'bg-red-500 text-white'
                            : 'bg-black bg-opacity-50 text-white hover:bg-opacity-70'
                        }`}
                      >
                        <X className="w-4 h-4" />
                      </button>
                      {editCommentForm.removeAttachments.includes(attachment.filename) && (
                        <div className="absolute inset-0 bg-red-500 bg-opacity-50 flex items-center justify-center rounded-lg">
                          <span className="text-white font-medium">Will be removed</span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* New attachments */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Add New Attachments
              </label>
              <FileUpload
                onFilesSelected={(files) => setEditCommentForm({ ...editCommentForm, attachments: Array.from(files) })}
                multiple={true}
                maxFiles={5}
              />
              {editCommentForm.attachments.length > 0 && (
                <div className="mt-2">
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">New files to add:</p>
                  <div className="space-y-1">
                    {editCommentForm.attachments.map((file, index) => (
                      <div key={index} className="flex items-center justify-between bg-gray-50 dark:bg-gray-700 p-2 rounded transition-colors">
                        <span className="text-sm text-gray-700 dark:text-gray-300">{file.name}</span>
                        <button
                          type="button"
                          onClick={() => setEditCommentForm({
                            ...editCommentForm,
                            attachments: editCommentForm.attachments.filter((_, i) => i !== index)
                          })}
                          className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 transition-colors"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="flex space-x-4">
              <button
                type="submit"
                disabled={loading}
                className="flex-1 bg-red-600 text-white py-2 px-4 rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 disabled:opacity-50 transition-all duration-300 transform hover:scale-105"
              >
                {loading ? 'Updating...' : 'Update Comment'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setCurrentView('post-detail');
                  setEditingComment(null);
                  setEditCommentForm({ content: '', attachments: [], removeAttachments: [] });
                }}
                className="flex-1 bg-gray-300 dark:bg-gray-600 text-gray-700 dark:text-gray-300 py-2 px-4 rounded-md hover:bg-gray-400 dark:hover:bg-gray-500 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition-all duration-300"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  };

  const renderPostDetail = () => {
    if (!selectedSubmission) return null;

    return (
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Back button at the top */}
        <div className="mb-6">
          <button
            onClick={() => setCurrentView('home')}
            className="flex items-center space-x-2 text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 transition-colors transform hover:scale-105"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back to reports</span>
          </button>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border dark:border-gray-700 transition-colors">
          {/* Post Header */}
          <div className="p-6 border-b dark:border-gray-700">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center space-x-3">
                <ProfilePicture user={selectedSubmission.author} size="md" />
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">{selectedSubmission.author.username}</div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">
                    {formatDate(selectedSubmission.createdAt)} • {selectedSubmission.community.name}
                  </div>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                {user && user.id === selectedSubmission.author._id && (
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => {
                        setEditingPost(selectedSubmission);
                        setEditPostForm({
                          title: '',
                          content: '',
                          context: '',
                          attachments: [],
                          removeAttachments: []
                        });
                        setCurrentView('edit-post');
                      }}
                      className="p-2 text-gray-600 dark:text-gray-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                    >
                      <Edit className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDeletePost(selectedSubmission._id)}
                      className="p-2 text-gray-600 dark:text-gray-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                )}
                <span className={`px-2 py-1 text-xs font-medium rounded-full ${getRiskColor(selectedSubmission.aiAnalysis.riskLevel)}`}>
                  {selectedSubmission.aiAnalysis.riskLevel.toUpperCase()} RISK
                </span>
                <span className={`px-2 py-1 text-xs font-medium rounded-full ${getScamScoreColor(selectedSubmission.scamScore)}`}>
                  {Math.round(selectedSubmission.scamScore)}% SCAM
                </span>
              </div>
            </div>

            <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">{selectedSubmission.title}</h1>
            <p className="text-gray-700 dark:text-gray-300 mb-4 whitespace-pre-wrap">{selectedSubmission.content}</p>

            {selectedSubmission.context && (
              <div className="bg-gray-50 dark:bg-gray-700 p-4 rounded-lg mb-4 transition-colors">
                <h4 className="font-medium text-gray-900 dark:text-white mb-2">Additional Context:</h4>
                <p className="text-gray-700 dark:text-gray-300 whitespace-pre-wrap">{selectedSubmission.context}</p>
              </div>
            )}

            {/* Attachments */}
            {selectedSubmission.attachments.length > 0 && (
              <div className="mb-6">
                <h4 className="font-medium text-gray-900 dark:text-white mb-3">Attachments ({selectedSubmission.attachments.length})</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {selectedSubmission.attachments.map((attachment, index) => (
                    <MediaPreview key={index} attachment={attachment} />
                  ))}
                </div>
              </div>
            )}

            {/* AI Analysis */}
            {selectedSubmission.aiAnalysis.isAnalyzed && (
              <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg mb-4 transition-colors">
                <h4 className="font-medium text-red-900 dark:text-red-300 mb-2">AI Analysis</h4>
                <div className="text-sm text-red-800 dark:text-red-400">
                  <p className="mb-2">Risk Level: <span className="font-medium">{selectedSubmission.aiAnalysis.riskLevel.toUpperCase()}</span></p>
                  {selectedSubmission.aiAnalysis.flaggedPatterns.length > 0 && (
                    <p>Flagged Patterns: {selectedSubmission.aiAnalysis.flaggedPatterns.length} suspicious patterns detected</p>
                  )}
                </div>
              </div>
            )}

            {/* Voting */}
            {user && (
              <div className="flex items-center space-x-4 mb-4">
                <button
                  onClick={() => handleVote(selectedSubmission._id, 'legit')}
                  className={`px-4 py-2 text-sm rounded-lg transition-all duration-300 transform hover:scale-105 ${
                    selectedSubmission.votes.legit.includes(user.id)
                      ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'
                      : 'bg-gray-100 text-gray-600 hover:bg-green-100 hover:text-green-700 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-green-900 dark:hover:text-green-300'
                  }`}
                >
                  <ThumbsUp className="w-4 h-4 inline mr-1" />
                  Legit ({selectedSubmission.votes.legit.length})
                </button>
                <button
                  onClick={() => handleVote(selectedSubmission._id, 'scam')}
                  className={`px-4 py-2 text-sm rounded-lg transition-all duration-300 transform hover:scale-105 ${
                    selectedSubmission.votes.scam.includes(user.id)
                      ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300'
                      : 'bg-gray-100 text-gray-600 hover:bg-red-100 hover:text-red-700 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-red-900 dark:hover:text-red-300'
                  }`}
                >
                  <ThumbsDown className="w-4 h-4 inline mr-1" />
                  Scam ({selectedSubmission.votes.scam.length})
                </button>
                <button
                  onClick={() => handleVote(selectedSubmission._id, 'unsure')}
                  className={`px-4 py-2 text-sm rounded-lg transition-all duration-300 transform hover:scale-105 ${
                    selectedSubmission.votes.unsure.includes(user.id)
                      ? 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300'
                      : 'bg-gray-100 text-gray-600 hover:bg-orange-100 hover:text-orange-700 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-orange-900 dark:hover:text-orange-300'
                  }`}
                >
                  <AlertCircle className="w-4 h-4 inline mr-1" />
                  Unsure ({selectedSubmission.votes.unsure.length})
                </button>
              </div>
            )}

            <div className="flex items-center space-x-4 text-sm text-gray-600 dark:text-gray-400">
              <span className="flex items-center space-x-1">
                <Eye className="w-4 h-4" />
                <span>{selectedSubmission.viewCount} views</span>
              </span>
              <span className="flex items-center space-x-1">
                <MessageCircle className="w-4 h-4" />
                <span>{selectedSubmission.commentCount} comments</span>
              </span>
            </div>
          </div>

          {/* Comments Section */}
          <div className="p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Comments ({comments.length})
            </h3>

            {/* Add Comment Form */}
            {user && (
              <form onSubmit={handleCreateComment} className="mb-6">
                <div className="flex items-start space-x-3">
                  <ProfilePicture user={user} size="sm" />
                  <div className="flex-1">
                    <textarea
                      value={commentForm.content}
                      onChange={(e) => setCommentForm({ ...commentForm, content: e.target.value })}
                      placeholder="Add a comment..."
                      rows={3}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent resize-none dark:bg-gray-700 dark:text-white transition-colors"
                      required
                    />
                    
                    {/* Comment attachments */}
                    <div className="mt-2">
                      <FileUpload
                        onFilesSelected={(files) => setCommentForm({ ...commentForm, attachments: Array.from(files) })}
                        multiple={true}
                        maxFiles={5}
                      />
                      {commentForm.attachments.length > 0 && (
                        <div className="mt-2">
                          <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">Selected files:</p>
                          <div className="space-y-1">
                            {commentForm.attachments.map((file, index) => (
                              <div key={index} className="flex items-center justify-between bg-gray-50 dark:bg-gray-700 p-2 rounded transition-colors">
                                <span className="text-sm text-gray-700 dark:text-gray-300">{file.name}</span>
                                <button
                                  type="button"
                                  onClick={() => setCommentForm({
                                    ...commentForm,
                                    attachments: commentForm.attachments.filter((_, i) => i !== index)
                                  })}
                                  className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 transition-colors"
                                >
                                  <X className="w-4 h-4" />
                                </button>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="flex justify-end mt-2">
                      <button
                        type="submit"
                        disabled={loading}
                        className="px-4 py-2 bg-red-600 text-white text-sm rounded-lg hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 disabled:opacity-50 transition-all duration-300 transform hover:scale-105"
                      >
                        {loading ? 'Posting...' : 'Post Comment'}
                      </button>
                    </div>
                  </div>
                </div>
              </form>
            )}

            {/* Comments List */}
            <div className="space-y-4">
              {comments.map(comment => (
                <div key={comment._id} className="border-l-2 border-red-200 dark:border-red-800 pl-4 transition-colors">
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center space-x-2">
                      <ProfilePicture user={comment.author} size="sm" />
                      <div>
                        <span className="font-medium text-gray-900 dark:text-white">{comment.author.username}</span>
                        <span className="text-sm text-gray-500 dark:text-gray-400 ml-2">
                          {formatDate(comment.createdAt)}
                        </span>
                      </div>
                    </div>
                    {user && user.id === comment.author._id && (
                      <div className="flex items-center space-x-1">
                        <button
                          onClick={() => {
                            setEditingComment(comment);
                            setEditCommentForm({
                              content: '',
                              attachments: [],
                              removeAttachments: []
                            });
                            setCurrentView('edit-comment');
                          }}
                          className="p-1 text-gray-600 dark:text-gray-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded transition-colors"
                        >
                          <Edit className="w-3 h-3" />
                        </button>
                        <button
                          onClick={() => handleDeleteComment(comment._id)}
                          className="p-1 text-gray-600 dark:text-gray-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded transition-colors"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    )}
                  </div>
                  <p className="text-gray-700 dark:text-gray-300 mb-2 whitespace-pre-wrap">{comment.content}</p>
                  
                  {/* Comment attachments */}
                  {comment.attachments.length > 0 && (
                    <div className="mb-2">
                      <div className="grid grid-cols-2 gap-2">
                        {comment.attachments.map((attachment, index) => (
                          <MediaPreview key={index} attachment={attachment} />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}

              {comments.length === 0 && (
                <div className="text-center py-8">
                  <MessageCircle className="w-8 h-8 text-gray-400 dark:text-gray-500 mx-auto mb-2" />
                  <p className="text-gray-600 dark:text-gray-400">No comments yet. Be the first to comment!</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Main render
  return (
    <div className={`min-h-screen transition-colors ${isDarkMode ? 'dark bg-gray-900' : 'bg-gray-50'}`}>
      {renderHeader()}
      {renderNotifications()}
      
      {currentView === 'home' && renderHome()}
      {currentView === 'communities' && renderCommunities()}
      {currentView === 'trending' && renderTrending()}
      {currentView === 'login' && renderLogin()}
      {currentView === 'register' && renderRegister()}
      {currentView === 'forgot-password' && renderForgotPassword()}
      {currentView === 'verify-otp' && renderVerifyOtp()}
      {currentView === 'reset-password' && renderResetPassword()}
      {currentView === 'profile' && renderProfile()}
      {currentView === 'create-post' && renderCreatePost()}
      {currentView === 'edit-post' && renderEditPost()}
      {currentView === 'edit-comment' && renderEditComment()}
      {currentView === 'post-detail' && renderPostDetail()}
    </div>
  );
}

export default App;