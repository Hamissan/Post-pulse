// app.js

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
// console.log(sessionSecret);

// Set the views folder
app.set('views', path.join(__dirname, 'views'));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
// Serve static files from the public folder
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET, 
  resave: false,
  saveUninitialized: false
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

const mongoURL = "mongodb://localhost:27017/userDB";
const mongoOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true
};

mongoose.connect(mongoURL, mongoOptions)
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.log("Error connecting to MongoDB.", error.message);
  });

const userSchema = new mongoose.Schema({
  username: String,
  posts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }]
});

userSchema.plugin(passportLocalMongoose);
const User = new mongoose.model("User", userSchema);

module.exports = User;

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
  cb(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id)
    .then(user => {
      done(null, user);
    })
    .catch(err => {
      done(err, null);
    });
});

const postSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  date: { type: Date, default: Date.now }
});

const Post = mongoose.model("Post", postSchema);

// Discussion thread schema

// const discussionThreadSchema = new mongoose.Schema({
//   title: String,
//   content: String,
//   author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
//   date: { type: Date, default: Date.now }
// });

// const DiscussionThread = mongoose.model("DiscussionThread", discussionThreadSchema);



// ROUTES

// HOME

app.get("/", function (req, res) {
  res.render("home", { currentUser: req.user });
});

// NAV BAR ITEMS

app.get('/services', (req, res) => {
  const currentUser = req.user; // Assuming you store the user in the 'user' property of the request
  res.render('services', { currentUser, currentPage: 'services' });
});

app.get("/rewards", (req, res) =>{
  const currentUser= req.user;
  res.render("rewards", { currentUser, currentPage: 'rewards' } );
});
app.get("/community", (req, res) =>{
  const currentUser=req.user;
  res.render("community", {currentUser, currentPage: 'community'});
});
app.get("/about", (req, res) =>{
  const currentUser=req.user;
  res.render("about", {currentUser, currentPage: "about"} );
});
app.get("/workshops", (req, res) =>{
  const currentUser=req.user;
  res.render("workshops",{currentUser, currentPage:"workshops"});
});

// CREATE THREAD

app.get("/create-thread", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("create-thread", { currentUser: req.user });
  } else {
    req.flash("error", "Please login to create a new thread.");
    res.redirect("/login");
  }
});

app.post("/create-thread", function (req, res) {
  if (req.isAuthenticated()) {
    const newThread = new Thread({
      title: req.body.title,
      content: req.body.content,
      author: req.user._id,
    });

    newThread.save()
      .then(() => {
        req.flash("success", "Thread created successfully!");
        res.redirect("/community"); // Redirect to the community page or threads list
      })
      .catch(err => {
        console.error(err);
        req.flash("error", "Error creating thread.");
        res.redirect("/create-thread");
      });
  } else {
    req.flash("error", "Please login to create a new thread.");
    res.redirect("/login");
  }
});

// ... (remaining code)


// REGISTER

app.get("/register", function (req, res) {
  res.render("register", { currentUser: req.user });
});

app.post("/register", async function (req, res) {
  try {
    const user = await User.register(new User({ username: req.body.username }), req.body.password);
    passport.authenticate("local")(req, res, function () {
      req.flash("success", "Registration successful!");
      res.redirect("/posts");
    });
  } catch (err) {
    console.error(err);
    req.flash("error", err.message);
    res.redirect("/register");
  }
});

// LOGIN

app.get("/login", function (req, res) {
  res.render("login", { currentUser: req.user });
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/posts",
  failureRedirect: "/login",
  failureFlash: true,
}));

// LOGOUT

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    req.flash("success", "Logout successful!");
    res.redirect('/');
  });
});

// SUBMIT

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit", { currentUser: req.user });
  } else {
    req.flash("error", "Please login to submit a post.");
    res.redirect("/login");
  }
});

app.post("/submit", function (req, res) {
  if (req.isAuthenticated() && req.user) {
    const newPost = new Post({
      title: req.body.title,
      content: req.body.content,
      author: req.user._id,
    
    }); 

    // Check if content exceeds the character limit
    // if (newPost.content.length > 250) {
    //   req.flash("error", "Post content exceeds the maximum limit of 250 characters.");
    //   res.redirect("/submit");
    //   return;
    // }


    newPost.save()
      .then(() => {
        req.user.posts = req.user.posts || [];
        req.user.posts.push(newPost);
        return req.user.posts;
      })
      .then(() => {
        req.flash("success", "Post submitted successfully!");
        res.redirect("/posts");
      })
      .catch(err => {
        console.error(err);
        req.flash("error", "Error submitting post.");
        res.redirect("/submit");
      });
  } else {
    req.flash("error", "Please login to submit a post.");
    res.redirect("/login");
  }
});

// POSTS

app.get("/posts", async function (req, res) {
  try {
    if (req.isAuthenticated()) {

      // In the below line of code, if i remove { author: req.user._id }, all the posts will show with their respective author
      // The ".populate" method  specifies the authenticated author of the respective post

      const posts = await Post.find({ author: req.user._id }).populate('author');
      res.render("posts", { posts, currentUser: req.user });
    } else {
      req.flash("error", "Please login to view posts.");
      res.redirect("/login");
    }
  } catch (err) {
    console.error(err);
    req.flash("error", "Error fetching posts.");
    res.status(500).send("Internal Server Error");
  }
});

// EDIT POST

app.get("/edit/:postId", async function (req, res) {
  try {
    if (req.isAuthenticated()) {
      const postId = req.params.postId;

      // Find the post by ID using Promises
      const post = await Post.findById(postId).exec();

      // Check if the post exists and if the author is the authenticated user
      if (post && req.user && post.author && post.author.equals(req.user._id)) {
        res.render("edit", { post: post, currentUser: req.user });
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

app.post("/edit/:postId", async function (req, res) {
  if (req.isAuthenticated()) {
    const postId = req.params.postId;
    const newContent = req.body.content;

    try {
      const post = await Post.findOne({ _id: postId, author: req.user._id }).exec();

      if (post) {
        // Update the content of the post
        post.content = newContent;

        // Save the updated post
        await post.save();

        req.flash("success", "Post updated successfully!");
        res.redirect("/posts");
      } else {
        req.flash("error", "Post not found or you are not the author.");
        res.redirect("/posts");
      }
    } catch (err) {
      console.error(err);
      req.flash("error", "Error updating post.");
      res.redirect("/posts");
    }
  } else {
    req.flash("error", "Please login to edit posts.");
    res.redirect("/login");
  }
});

// DELETE POST

app.get("/delete/:postId", async function (req, res) {
  if (req.isAuthenticated()) {
    const postId = req.params.postId;

    try {
      const post = await Post.findOne({ _id: postId, author: req.user._id }).exec();

      if (post) {
        // Render the confirmation page before actually deleting the post
        res.render("confirm-delete", { post: post, currentUser: req.user });
      } else {
        req.flash("error", "Post not found or you are not the author.");
        res.redirect("/posts");
      }
    } catch (err) {
      console.error(err);
      req.flash("error", "Error fetching post details.");
      res.redirect("/posts");
    }
  } else {
    req.flash("error", "Please login to delete posts.");
    res.redirect("/login");
  }
});

// POST route for confirming and deleting post

app.post("/delete/:postId", async function (req, res) {
  if (req.isAuthenticated()) {
    const postId = req.params.postId;

    try {
      const post = await Post.findOneAndDelete({ _id: postId, author: req.user._id }).exec();

      if (post) {
        req.flash("success", "Post deleted successfully!");
        res.redirect("/posts");
      } else {
        req.flash("error", "Post not found or you are not the author.");
        res.redirect("/posts");
      }
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


app.listen(3000, function () {
  console.log("Server is running on port 3000.");
});
