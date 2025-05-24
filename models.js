const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
  content: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  timestamp: { type: Date, default: Date.now }
});

const postSchema = new mongoose.Schema({
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  comments: [commentSchema]
});

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  posts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }]
});

const Post = mongoose.model('Post', postSchema);
const User = mongoose.model('User', userSchema);
const Comment = mongoose.model('Comment', commentSchema);

module.exports = { Post, User, Comment };