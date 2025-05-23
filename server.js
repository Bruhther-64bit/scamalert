const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;
const DB_NAME = "redditClone";
const DB_URI =
  process.env.MONGODB_URI || `mongodb://127.0.0.1:27017/${DB_NAME}`;

// Middleware setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");

// Configure Mongoose
mongoose.set("strictQuery", true);

// Database Schemas
const postSchema = new mongoose.Schema({
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});

// Models
const Post = mongoose.model("Post", postSchema);
const User = mongoose.model("User", userSchema);

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
      console.error(
        "⚠️ Collection initialization error:",
        collectionError.message
      );
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
    const posts = await Post.find().sort({ timestamp: -1 }).limit(20);
    res.render("home", {
      loggedIn: false,
      posts,
      error: null,
    });
  } catch (error) {
    res.render("home", {
      loggedIn: false,
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
    const posts = await Post.find().sort({ timestamp: -1 }).limit(20);
    res.render("home", {
      loggedIn: true,
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
    const { content } = req.body;

    if (!content || content.trim() === "") {
      return res.status(400).json({
        error: "Post content cannot be empty",
      });
    }

    const newPost = new Post({ content });
    await newPost.save();

    res.status(201).json({
      message: "Post created successfully",
      post: newPost,
    });
  } catch (error) {
    res.status(500).json({
      error: "Failed to create post",
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("🔥 Server Error:", err.stack);
  res.status(500).render("error", {
    message: "Something went wrong!",
  });
});

// Start the server
async function startServer() {
  try {
    await connectToDatabase();

    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
      console.log(`📊 MongoDB URI: ${DB_URI}`);
    });
  } catch (error) {
    console.error("💥 Failed to start server:", error);
    process.exit(1);
  }
}

startServer();
