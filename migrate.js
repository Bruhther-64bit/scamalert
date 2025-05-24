const mongoose = require('mongoose');
const { Post } = require('./models');

async function migrate() {
  try {
    console.log('⌛ Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/redditClone', {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    
    console.log('✅ MongoDB connected successfully!');
    
    // Add comments array to all posts that don't have it
    const result = await Post.updateMany(
      { comments: { $exists: false } },
      { $set: { comments: [] } }
    );
    
    console.log(`✅ Migrated ${result.nModified} posts`);
    process.exit(0);
  } catch (err) {
    console.error('❌ Migration failed:', err);
    process.exit(1);
  }
}

migrate();