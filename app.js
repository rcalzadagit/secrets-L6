//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");


//Should be in this order


const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

// Required by express session package
app.use(session({
  secret: "Anylong string goeshere.",
  resave: false,
  saveUninitialized: false
}));
//See passportjs
app.use(passport.initialize());
app.use(passport.session());


////////////////Data/////////////////////////////////////////////////
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);
//User Schema with mongoose-encryption (npm)
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//To setup user Model
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
//Cookie creation
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
//From passportjs, update with env file info.
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/MyOAuth",
    // Solved issue on https://github.com/jaredhanson/passport-google-oauth2
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
///////////////////////////////////////////////////////////////////
// Viewwing pages
app.get("/", function(req, res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", {scope:["profile"]}));
// MyOAuth Google API
app.get("/auth/google/MyOAuth",
  passport.authenticate("google", {failureRedirect: "/login"}),
  function(req, res){
    // Successfull authentication, redirect to secrets page
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers})
      }
    }
  });
 });

 app.get("/submit", function(req, res){
   if (req.isAuthenticated()){
     res.render("submit");
   } else {
     res.redirect("/login");
   }
 });
app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, function(err, foundUser){
      if (err) {
        console.log(err);
      } else {
        if (foundUser) {
            foundUser.secret = submittedSecret;
            foundUser.save(function(){
              res.redirect("/secrets");
            });
          }
        }
    });
});

//Route called from the Logout button on the secrets page.
 app.get("/logout", function(req, res){
   //Passport Logout function
   req.logout();
   res.redirect("/");
 });

//////////////////////////////////////////////////////////////
// To get new user registration from the form
app.post("/register", function(req, res){

User.register({username: req.body.username}, req.body.password, function(err, user) {
  if (err) {
    console.log(err);
    res.redirect("/register");
} else {
  passport.authenticate("local") (req, res, function(){
    res.redirect("/secrets");
      });
    }
  });
});
/////////////////////////////////////////////////////////////
// To get Login data from Login Form page.
app.post("/login", function(req, res){

const user = new User({
  username: req.body.username,
  password: req.body.password
});
//Passport login module and Authenticate - Passport module.
req.login(user, function(err){
  if (err) {
    console.log(err);
  } else {
    passport.authenticate("local") (req, res, function(){
      res.redirect("secrets");
    });
  }
});
});



//Server connection
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}
app.listen(port, function() {
  console.log("Server has started successfully.");
});
