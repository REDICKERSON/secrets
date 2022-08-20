//jshint esversion:6
/////// REQUIRE SECTION ///////

require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

////// ENCRYPTION SECTION ///////

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

//Passport Sessions

app.use(passport.initialize());
app.use(passport.session());


////// MONGOOSE SECTION ///////

//Mongoose Connection

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

//Mongoose Schemas

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Mongoose Models

const User = new mongoose.model("User", userSchema);

/////// SERIALIZE SECTION ///////

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

//OAuth 2.0
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

/////// ROUTE SECTION ///////

//Get root route
app.get("/", function (req, res) {
    res.render("home");
});

//Get register
app.get("/register", function (req, res) {
    res.render("register");
});

//Get secrets
app.get("/secrets", function(req, res){
    User.find({"secret": {$ne:null}}, function(err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }  
    } );
});

//Post register
app.post("/register", function (req, res) {
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    })
});

//Get login
app.get("/login", function (req, res) {
    res.render("login");
});

//Post login
app.post("/login", function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

//Get logout
app.get("/logout", function(req, res){
    req.logout(function(err){
        if (err) {console.log(err);}
    });
    res.redirect("/");
});

//Get auth/google
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

//Get auth/google/secrets
app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect('/secrets');
  });

//Get submit
app.get("/submit", function(req, res){
if (req.isAuthenticated()){
    res.render("submit");
} else {
    res.redirect("/login");
}
});

//Post submit
app.post("/submit", function(req, res){
    const newSecret = req.body.secret;

    console.log(req.user);

    User.findById(req.user.id, function(err, foundUser){
        if (err) {console.log(err); return;}
        if (foundUser) {
            foundUser.secret = newSecret;
            foundUser.save(function(){
                res.redirect("secrets");
            });
        }
    });

});



/////// LISTENER SECTION ///////

app.listen(3000, function (err) {
    if (err) { console.log(err); return; }
    console.log("Server sucessfully started.");
});