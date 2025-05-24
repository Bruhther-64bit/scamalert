const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;
const DB_NAME = "redditClone";
const DB_URI = process.env.MONGODB_URI || `mongodb://127.0.0.1:27017/${DB_NAME}`;

// Middleware setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");

// Configure Mongoose
mongoose.set("strictQuery", true);

const { Post, User, Comment } = require('./models');

// Enhanced Database Connection
async function connectToDatabase() {
  try {
    console.log("⌛ Connecting to MongoDB...");

    await mongoose.connect(DB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      retryWrites: true,
      retryReads: true,
    });

    console.log("✅ MongoDB connected successfully!");

    // Initialize collections if they don't exist
    const db = mongoose.connection.db;
    try {
      const collections = await db.listCollections().toArray();
      const collectionNames = collections.map((c) => c.name);

      if (!collectionNames.includes("posts")) {
        await db.createCollection("posts");
        console.log('📝 Created "posts" collection');
      }

      if (!collectionNames.includes("users")) {
        await db.createCollection("users");
        console.log('👥 Created "users" collection');
        await User.createIndexes(); // Ensure unique username index
      }
    } catch (collectionError) {
      console.error("⚠️ Collection initialization error:", collectionError.message);
    }
  } catch (error) {
    console.error("❌ MongoDB connection failed:", error.message);
    console.log("\nTroubleshooting Guide:");
    console.log("1. Ensure MongoDB is installed and running");
    console.log('2. Try running "mongod" in a separate terminal');
    console.log("3. Verify no other service is using port 27017");
    console.log("4. Check firewall settings if connection is blocked");
    process.exit(1);
  }
}

// Routes
app.get("/", async (req, res) => {
  try {
    let posts = await Post.find().sort({ timestamp: -1 }).limit(20)
      .populate('author')
      .populate('comments.author')
      .lean(); // Convert to plain JS objects
    
    // Ensure all posts have comments array
    posts = posts.map(post => {
      if (!post.comments) {
        post.comments = [];
      }
      return post;
    });

    res.render("home", {
      loggedIn: false,
      currentUser: null,
      posts,
      error: null,
    });
  } catch (error) {
    console.error("Error loading posts:", error);
    res.render("home", {
      loggedIn: false,
      currentUser: null,
      posts: [],
      error: "Failed to load posts",
    });
  }
});
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.render("login", {
        error: "Username and password are required",
      });
    }

    const user = await User.findOne({ username, password });
    if (!user) {
      return res.render("login", {
        error: "Invalid credentials",
      });
    }

    // Successful login
    const posts = await Post.find().sort({ timestamp: -1 }).limit(20).populate('author');
    res.render("home", {
      loggedIn: true,
      currentUser: user,
      posts,
      error: null,
    });
  } catch (error) {
    res.render("login", {
      error: "Login failed. Please try again.",
    });
  }
});

app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.render("register", {
        error: "Username and password are required",
      });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.render("register", {
        error: "Username already exists",
      });
    }

    const newUser = new User({ username, password });
    await newUser.save();
    res.redirect("/login");
  } catch (error) {
    res.render("register", {
      error: "Registration failed. Please try again.",
    });
  }
});

app.post("/posts", async (req, res) => {
  try {
    const { content, userId } = req.body;

    if (!content || content.trim() === "") {
      return res.status(400).json({
        error: "Post content cannot be empty",
      });
    }

    const newPost = new Post({ 
      content, 
      author: userId,
      comments: [] // Initialize empty comments array
    });
    
    await newPost.save();
    
    // Add post to user's posts array
    await User.findByIdAndUpdate(userId, {
      $push: { posts: newPost._id }
    });

    const populatedPost = await Post.findById(newPost._id)
      .populate('author')
      .populate('comments.author');

    res.status(201).json({
      message: "Post created successfully",
      post: populatedPost,
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to create post",
    });
  }
});

// Update Post
app.put("/posts/:id", async (req, res) => {
  try {
    const { content } = req.body;
    const postId = req.params.id;

    if (!content || content.trim() === "") {
      return res.status(400).json({
        error: "Post content cannot be empty",
      });
    }

    const updatedPost = await Post.findByIdAndUpdate(
      postId,
      { content },
      { new: true }
    ).populate('author');

    if (!updatedPost) {
      return res.status(404).json({
        error: "Post not found",
      });
    }

    res.status(200).json({
      message: "Post updated successfully",
      post: updatedPost,
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to update post",
    });
  }
});

// Delete Post
app.delete("/posts/:id", async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.body.userId;

    // Remove post from user's posts array
    await User.findByIdAndUpdate(userId, {
      $pull: { posts: postId }
    });

    // Delete the post
    const deletedPost = await Post.findByIdAndDelete(postId);

    if (!deletedPost) {
      return res.status(404).json({
        error: "Post not found",
      });
    }

    res.status(200).json({
      message: "Post deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to delete post",
    });
  }
});
// Add Comment to Post
app.post("/posts/:postId/comments", async (req, res) => {
  try {
    const { content, userId } = req.body;
    const postId = req.params.postId;

    if (!content || content.trim() === "") {
      return res.status(400).json({
        error: "Comment content cannot be empty",
      });
    }

    const newComment = {
      content,
      author: userId,
      timestamp: new Date()
    };

    const updatedPost = await Post.findByIdAndUpdate(
      postId,
      { $push: { comments: newComment } },
      { new: true }
    ).populate('author').populate('comments.author');

    if (!updatedPost) {
      return res.status(404).json({
        error: "Post not found",
      });
    }

    res.status(201).json({
      message: "Comment added successfully",
      comment: updatedPost.comments[updatedPost.comments.length - 1],
      postId: postId
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to add comment",
    });
  }
});

// Delete comment
app.delete("/posts/:postId/comments/:commentId", async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const { userId } = req.body;

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ error: "Post not found" });
    }

    const comment = post.comments.id(commentId);
    if (!comment) {
      return res.status(404).json({ error: "Comment not found" });
    }

    // Check if user is the author
    if (comment.author.toString() !== userId) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    post.comments.pull(commentId);
    await post.save();

    res.status(200).json({
      message: "Comment deleted successfully",
      postId: postId,
      commentId: commentId
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to delete comment",
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("🔥 Server Error:", err.stack);
  res.status(500).json({
    message: "Something went wrong!",
    error: err.message
  });
});
// Start the server
async function startServer() {
  try {
    await connectToDatabase();

    const server = app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${server.address().port}`);
      console.log(`📊 MongoDB URI: ${DB_URI}`);
    });

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.log(`Port ${PORT} in use, trying ${PORT + 1}...`);
        app.listen(PORT + 1);
      }
    });
  } catch (error) {
    console.error("💥 Failed to start server:", error);
    process.exit(1);
  }
}

startServer();