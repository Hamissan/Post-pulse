require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const flash = require("express-flash");
const secureRandomString = require('secure-random-string');
const path = require('path');

const app = express();

// Generate a random secret key for session management
const sessionSecret = secureRandomString({ length: 32, characters: '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' });

// Middleware configuration
app.set('views', path.join(__dirname, 'views'));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || sessionSecret, // Use environment variable or generated secret
  resave: false,
  saveUninitialized: false
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
const mongoURL = "mongodb://localhost:27017/userDB";
const mongoOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true
};

mongoose.connect(mongoURL, mongoOptions)
  .then(() => console.log('Connected to MongoDB'))
  .catch(error => console.log("Error connecting to MongoDB:", error.message));

// Define schemas and models
const userSchema = new mongoose.Schema({
  username: String,
  posts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }]
});

userSchema.plugin(passportLocalMongoose);
const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser((user, cb) => cb(null, user.id));
passport.deserializeUser((id, done) => {
  User.findById(id)
    .then(user => done(null, user))
    .catch(err => done(err, null));
});

const postSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  date: { type: Date, default: Date.now },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Comment' }]
});

const Post = mongoose.model("Post", postSchema);

const commentSchema = new mongoose.Schema({
  content: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  date: { type: Date, default: Date.now },
  post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
  replies: [{
    content: String,
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    date: { type: Date, default: Date.now }
  }]
});

const Comment = mongoose.model("Comment", commentSchema);

// Routes
app.get("/", (req, res) => res.render("home", { currentUser: req.user }));

app.get('/services', (req, res) => res.render('services', { currentUser: req.user, currentPage: 'services' }));
app.get("/rewards", (req, res) => res.render("rewards", { currentUser: req.user, currentPage: 'rewards' }));
app.get("/community", (req, res) => res.render("community", { currentUser: req.user, currentPage: 'community' }));
app.get("/about", (req, res) => res.render("about", { currentUser: req.user, currentPage: "about" }));
app.get("/workshops", (req, res) => res.render("workshops", { currentUser: req.user, currentPage: "workshops" }));

app.get("/register", (req, res) => res.render("register", { currentUser: req.user }));
app.post("/register", async (req, res) => {
  try {
    const user = await User.register(new User({ username: req.body.username }), req.body.password);
    passport.authenticate("local")(req, res, () => {
      req.flash("success", "Registration successful!");
      res.redirect("/posts");
    });
  } catch (err) {
    console.error(err);
    req.flash("error", err.message);
    res.redirect("/register");
  }
});

app.get("/login", (req, res) => res.render("login", { currentUser: req.user }));
app.post("/login", passport.authenticate("local", {
  successRedirect: "/posts",
  failureRedirect: "/login",
  failureFlash: true,
}));

app.get("/logout", (req, res) => {
  req.logout(err => {
    if (err) return next(err);
    req.flash("success", "Logout successful!");
    res.redirect('/');
  });
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit", { currentUser: req.user });
  } else {
    req.flash("error", "Please login to submit a post.");
    res.redirect("/login");
  }
});

app.post("/submit", async (req, res) => {
  if (req.isAuthenticated() && req.user) {
    const newPost = new Post({
      title: req.body.title,
      content: req.body.content,
      author: req.user._id,
    });

    if (newPost.content.length > 40000) {
      req.flash("error", "Post content exceeds the maximum limit.");
      return res.redirect("/submit");
    }

    try {
      await newPost.save();
      req.user.posts.push(newPost._id);
      await req.user.save();
      req.flash("success", "Post submitted successfully!");
      res.redirect("/posts");
    } catch (err) {
      console.error(err);
      req.flash("error", "Error submitting post.");
      res.redirect("/submit");
    }
  } else {
    req.flash("error", "Please login to submit a post.");
    res.redirect("/login");
  }
});

app.get('/posts', async (req, res) => {
  try {
    if (req.isAuthenticated()) {
      const page = parseInt(req.query.page, 10) || 1; // Default to page 1
      const limit = parseInt(req.query.limit, 10) || 10; // Default to 10 posts per page
      const skip = (page - 1) * limit;

      // Fetch posts with pagination and populate author and comments
      const posts = await Post.find()
        .skip(skip)
        .limit(limit)
        .populate('author', 'username') // Ensure author is populated with username
        .populate({
          path: 'comments',
          populate: { path: 'author', select: 'username' } // Ensure comment authors are populated
        });

      // Get total number of posts for pagination
      const totalPosts = await Post.countDocuments();
      const totalPages = Math.ceil(totalPosts / limit);

      // Render posts view with pagination and user info
      res.render('posts', { posts, totalPages, currentUser: req.user });
    } else {
      req.flash("error", "Please login to view posts.");
      res.redirect("/login");
    }
  } catch (err) {
    console.error('Error fetching posts:', err);
    req.flash("error", "Error fetching posts.");
    res.status(500).send("Internal Server Error");
  }
});


app.get('/posts/:postId', async (req, res) => {
  try {
    if (req.isAuthenticated()) {
      const post = await Post.findById(req.params.postId)
        .populate('author')
        .populate({
          path: 'comments',
          populate: { path: 'author', select: 'username' }
        });

      if (!post) {
        req.flash('error', 'Post not found.');
        return res.redirect('/posts');
      }

      res.render('post', { post, currentUser: req.user });
    } else {
      req.flash('error', 'Please login to view posts.');
      res.redirect('/login');
    }
  } catch (err) {
    console.error(err);
    req.flash('error', 'Error fetching post.');
    res.redirect('/posts');
  }
});

app.get("/edit/:postId", async (req, res) => {
  try {
    if (req.isAuthenticated()) {
      const post = await Post.findById(req.params.postId);
      if (post && req.user && post.author.equals(req.user._id)) {
        res.render("edit", { post, currentUser: req.user });
      } else {
        req.flash("error", "Post not found or you are not the author.");
        res.redirect("/posts");
      }
    } else {
      req.flash("error", "Please login to edit posts.");
      res.redirect("/login");
    }
  } catch (err) {
    console.error(err);
    req.flash("error", "Error fetching post details.");
    res.redirect("/posts");
  }
});

app.post("/edit/:postId", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const post = await Post.findOne({ _id: req.params.postId, author: req.user._id });
      if (!post) {
        req.flash("error", "Post not found or you are not authorized to edit it.");
        return res.redirect("/posts");
      }

      // Update both title and content
      post.title = req.body.title;
      post.content = req.body.content;
      await post.save();

      req.flash("success", "Post updated successfully.");
      res.redirect("/posts");
    } catch (err) {
      console.error(err);
      req.flash("error", "Error updating post.");
      res.redirect(`/edit/${req.params.postId}`);
    }
  } else {
    req.flash("error", "Please login to edit posts.");
    res.redirect("/login");
  }
});

app.get("/delete/:postId", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const post = await Post.findOne({ _id: req.params.postId, author: req.user._id });
      if (!post) {
        req.flash("error", "Post not found or you are not authorized to delete it.");
        return res.redirect("/posts");
      }
      res.render("confirm-delete", { post, currentUser: req.user });
    } catch (err) {
      console.error("Error in /delete/:postId route:", err);
      req.flash("error", "Error fetching post for deletion.");
      res.redirect("/posts");
    }
  } else {
    req.flash("error", "Please login to delete posts.");
    res.redirect("/login");
  }
});



app.post("/delete/:postId", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      // Find and delete the post
      const post = await Post.findOneAndDelete({ _id: req.params.postId, author: req.user._id });
      if (!post) {
        req.flash("error", "Post not found or you are not authorized to delete it.");
        return res.redirect("/posts");
      }
      req.flash("success", "Post deleted successfully.");
      res.redirect("/posts");
    } catch (err) {
      console.error(err);
      req.flash("error", "Error deleting post.");
      res.redirect("/posts");
    }
  } else {
    req.flash("error", "Please login to delete posts.");
    res.redirect("/login");
  }
});
app.get('/confirm-delete/:postId', async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const post = await Post.findOne({ _id: req.params.postId, author: req.user._id });
      if (!post) {
        req.flash('error', 'Post not found or you are not authorized to delete it.');
        return res.redirect('/posts');
      }
      res.render('confirm-delete', { post, currentUser: req.user });
    } catch (err) {
      console.error('Error fetching post for deletion:', err);
      req.flash('error', 'Error fetching post for deletion.');
      res.redirect('/posts');
    }
  } else {
    req.flash('error', 'Please login to delete posts.');
    res.redirect('/login');
  }
});


app.post('/like/:postId', async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const post = await Post.findById(req.params.postId);
      if (!post) {
        return res.json({ success: false, message: "Post not found." });
      }

      const userIndex = post.likes.indexOf(req.user._id);
      if (userIndex > -1) {
        post.likes.splice(userIndex, 1); // Remove like
      } else {
        post.likes.push(req.user._id); // Add like
      }

      await post.save();
      res.json({ success: true, newLikeCount: post.likes.length });
    } catch (err) {
      console.error(err);
      res.json({ success: false, message: "Error liking the post." });
    }
  } else {
    res.json({ success: false, message: "User not authenticated." });
  }
});

app.post('/comments/:postId', async (req, res) => {
  try {
    if (!req.isAuthenticated()) {
      req.flash("error", "You need to be logged in to comment.");
      return res.redirect('/login');
    }

    const { postId } = req.params;
    const { comment } = req.body;

    if (!comment || !postId) {
      req.flash("error", "Comment content is required.");
      return res.redirect(`/posts`);
    }

    // Create a new Comment document
    const newComment = new Comment({
      content: comment,
      author: req.user._id,
      post: postId
    });

    await newComment.save();

    // Add the new Comment's ObjectId to the Post's comments array
    await Post.findByIdAndUpdate(postId, {
      $push: { comments: newComment._id }
    });

    req.flash("success", "Comment added successfully!");
    res.redirect('/posts');
  } catch (err) {
    console.error('Error adding comment:', err);
    req.flash("error", "Error adding comment.");
    res.redirect('/posts');
  }
});

app.post('/comments/:postId/reply/:commentId', async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const comment = await Comment.findById(req.params.commentId);
      if (!comment) {
        return res.status(404).send("Comment not found.");
      }

      const post = await Post.findById(req.params.postId);
      if (!post) {
        return res.status(404).send("Post not found.");
      }

      comment.replies.push({
        content: req.body.content,
        author: req.user._id
      });

      await comment.save();

      // Redirect to the posts page, or another relevant page
      res.redirect('/posts'); // Changed from `/posts/${req.params.postId}` to `/posts`
    } catch (err) {
      console.error(err);
      res.status(500).send("Error adding reply.");
    }
  } else {
    res.redirect("/login");
  }
});


app.use((req, res) => {
  res.status(404).render('404', { currentUser: req.user });
});

// Generic middleware for handling all routes
app.use((req, res, next) => {
  console.log("Requested URL:", req.originalUrl);
  next();
});


// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  req.flash('error', 'Something went wrong!');
  res.status(500).render('404', { currentUser: req.user });
});


// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
