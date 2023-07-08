require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy= require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({

    secret: "thisisoursecret.",
    resave: false,
    saveUninitialized: false,
    
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({

    email: String,
    password: String,
    googleId: String,
    secret: String

});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done){

    done(null, user.id);
  
});
  
passport.deserializeUser(function(user, done) {

    process.nextTick(function() {

        return done(null, user);

    });

});

passport.use(new GoogleStrategy({

    clientID:process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/google/secrets"

    },
    function(accessToken, refreshToken, profile, done) {

        User.findOrCreate({ googleId: profile.id }, function (err, user) {

        return done(err, user);

        });
    }

));

app.get("/", (req,res) => {

    res.render(("home"))

})

app.get('/google', 
    passport.authenticate('google', 
        { scope: ['profile'] }
    
));

app.get('/google/secrets',
    passport.authenticate('google', 
    { failureRedirect: '/login' }),
    function (req, res) {

        res.redirect('/secrets')

    }
);

app.get("/login", (req,res) => {

    res.render(("login"))
    
})

app.get("/register", (req,res) => {

    res.render(("register"))
    
})

app.get("/logout", (req, res) => {

    req.logout(function(err) {

        if (err) {

            console.log(err); 

        }

    });

    res.redirect('/');

})

app.get("/secrets", function(req, res) {
   
    User.find({"secret":{$ne:null}})
    .then((foundUsers) => {

      res.render("secrets",{usersWithSecrets:foundUsers});

    })
    .catch((err) => {

      console.log(err);

    })

})

app.post("/submit", (req, res) => {

    //console.log(req.user);
    User.findById(req.user)
      .then(foundUser => {

        if (foundUser) {

          foundUser.secret = req.body.secret;
          return foundUser.save();

        }
        return null;

      })
      .then(() => {

        res.redirect("/secrets");

      })
      .catch(err => {

        console.log(err);

      });

});

app.post("/register", (req,res) => {

    User.register({username: req.body.username}, req.body.password, function(err, user) {

        if (err) {

            console.log(err);
            res.redirect("/register");

        } else {

            passport.authenticate('local')(req, res, function() {

                res.redirect("/secrets");

            })

        }

    })

})

app.post("/login", (req, res) => {
    
    const user = new User({

        username: req.body.username,
        password: req.body.password

    })

    req.login(user, function(err) {

        if (err) {

            console.log(err);

        } else {

            passport.authenticate('local')(req, res, function() {

                res.redirect("/secrets");

            })

        }

    })

});

app.get("/submit", function (req, res) {

    if(req.isAuthenticated()){

        res.render("submit");

    }else{

        res.redirect("/login");

    }

});

app.listen(3000, () => {

    console.log("Server started on port 3000...")

});