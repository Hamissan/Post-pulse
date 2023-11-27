// app.js
require('dotenv').config();
const express = require("express");
const bodyParser= require("body-parser");
const ejs = require("ejs");
const mongoose= require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy= require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
// const postModule = require('./views/posts.ejs'); // Adjust the path accordingly


const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
  secret:process.env.SECRET_KEY,
  resave: false,
  saveUninitialized: false
}));
// initialize passport

app.use(passport.initialize());
app.use(passport.session());


const mongoURL= "mongodb://localhost:27017/userDB";
const mongoOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true
};

mongoose.connect(mongoURL,mongoOptions)
.then(() => {
    console.log('Connected to MongoDB');
})
.catch((error) => {
    console.log("Error connecting to -MongoDB.", error.message);
});

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
// store details from google  
googleId: String,
secret: String,
displayName: String,
email: String,
profileName: String,
// 
  posts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/Secret", 
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log("Google authentication Successful");
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

const postSchema = new mongoose.Schema({
    title: String,
    content: String,  // Add this line
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    date: { type: Date, default: Date.now }
  });

  const Post = mongoose.model("Post", postSchema);

app.get("/", function (req, res) {
    res.render("home", { currentUser: req.user }); // Assuming you have user information stored in req.user
});

app.get("/auth/google",passport.authenticate("google",{scope:["profile"]}));

 // the above line of code is sufficient enough to bring a pop up to the user tosign in using google
 app.get("/auth/google/Secret", 
 passport.authenticate('google', { failureRedirect: '/' }),
 function(req, res) {
   // Successful authentication, redirect home.
   res.redirect('/posts');
 });

  
  app.get("/register", function (req, res) {
    res.render("register", { currentUser: req, res});
  });
  
  app.post("/register", function (req, res) {
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/posts");
        });
      }
    });
  });
  
  app.get("/login", function (req, res) {
    res.render("login", {currentUser: req, res});
  });
  
  app.post("/login", function (req, res) {
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });
  
    req.login(user, function (err) {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/posts");
        });
      }
    });
  });
  
  app.get("/logout", function (req, res) {
    // Example with a callback function
req.logout(function(err) {
    if (err) {
        return next(err);
    }
    // Additional logic after logout
    res.redirect('/'); // Redirect to a specific page after logout
});

  });
  
  app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
      res.render("submit", { currentUser: req.user});
    } else {
      res.redirect("/login");
    }
  });
  
  app.post("/submit", function (req, res) {

    if (req.isAuthenticated() && req.user) {
      console.log(req.user);
      const newPost = new Post({
        title: req.body.title,
        content: req.body.content,
        author: req.user._id,
      });
  
      newPost.save()
        .then(() => {
          req.user.posts = req.user.posts || [];
          req.user.posts.push(newPost);
          return req.user.save();
        })
        .then(() => res.redirect("/posts"))
        .catch(err => {
          console.error(err);
          res.redirect("/submit");
        });
    } else {
      res.redirect("/login");
    }
  });
  app.get("/posts", async function (req, res) {
    try {
      const posts = await Post.find({});
      res.render("posts", { posts, currentUser: req.user });
    } catch (err) {
      console.error(err);
      res.status(500).send("Internal Server Error");
    }
  });

  app.get("/edit/:postId", async function (req, res) {
    if (req.isAuthenticated()) {
      const postId = req.params.postId;
  
      try {
        const post = await Post.findById(postId).exec();
  
        if (post && post.author && post.author.equals(req.user._id)) {
          res.render("edit", { post: post });
        } else {
          res.redirect("/posts");
        }
      } catch (err) {
        console.error(err);
        res.redirect("/posts");
      }
    } else {
      res.redirect("/login");
    }
  });
  
  
  app.post("/edit/:postId", async function (req, res) {
    if (req.isAuthenticated()) {
      const postId = req.params.postId;
      const newContent = req.body.content;
  
      try {
        const post = await Post.findById(postId).exec();
  
        if (post && post.author.equals(req.user._id)) {
          // Update the content of the post
          post.content = newContent;
  
          // Save the updated post
          await post.save();
          res.redirect("/posts");
        } else {
          res.redirect("/posts");
        }
      } catch (err) {
        console.error(err);
        res.redirect("/posts");
      }
    } else {
      res.redirect("/login");
    }
  });

  app.get("/delete/:postId", function (req, res) {
    if (req.isAuthenticated()) {
      const postId = req.params.postId;
  
      // Find the post by ID and ensure the current user is the author
      Post.findOneAndDelete({ _id: postId, author: req.user._id }, function (err, post) {
        if (!err && post) {
          res.redirect("/posts");
        } else {
          console.log(err);
          res.redirect("/posts");
        }
      });
    } else {
      res.redirect("/login");
    }
  });
  
  app.post("/delete/:postId", async function (req, res) {
    if (req.isAuthenticated()) {
      const postId = req.params.postId;
  
      try {
        const post = await Post.findById(postId).exec();
  
        if (post && post.author.equals(req.user._id)) {
          // Remove the post
          await post.deleteOne();
          res.redirect("/posts");
        } else {
          res.redirect("/posts");
        }
      } catch (err) {
        console.error(err);
        res.redirect("/posts");
      }
    } else {
      res.redirect("/login");
    }
  });
app.listen(3000, function () {
  console.log("Server is running on port 3000.");
});
