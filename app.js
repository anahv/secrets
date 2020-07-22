//jshint esversion:6
require('dotenv').config()
const appName = "Secrets Level 3"
const express = require("express")
const bodyParser = require("body-parser")
const app = express()
const mongoose = require("mongoose")
// Level 3
//const md5 = require("md5")

//Level 4
//const bcrypt = require("bcrypt")
//const saltRounds = 5

// Level 5
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")

// Level 6
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate")

// EJS stuff
app.use(express.static("public"))
app.set("view engine", "ejs")

app.use(bodyParser.urlencoded({
    extended: true
}));

//Put this session stuff below the app initialisation and before mongoose connect
app.use(session({
  secret: "Any long string you would like.",
  resave: false,
  saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())

mongoose.connect("mongodb://localhost:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true
})

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
})

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

const User = new mongoose.model("User", userSchema)

passport.use(User.createStrategy());
 
// these two are passport local mongoose module and it's handy but only works for local sessions, so we have to use the passport one to have it work with social login too
//passport.serializeUser(User.serializeUser());
//passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//Level 6
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
        console.log(profile)

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function (req, res) {
    res.render("home")
})

// profile includes the email as well
app.get("/auth/google", passport.authenticate("google", {scope: ["profile"]}))

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
  });

app.get("/login", function (req, res) {
    res.render("login")
})

app.get("/register", function (req, res) {
    res.render("register")
})

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit")
        }
    else {
        res.redirect("/login")
    }
})

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret
    
    User.findById(req.user.id, function(err, foundUser) {
        if (err) {console.log(err)}
        else {
            if (foundUser) {
                foundUser.secret = submittedSecret
                foundUser.save(function() {
                    res.redirect("/secrets")
                })}
            }
        }
    )})

app.post("/register", function (req, res) {
    // LEVEL 3
    //  const hash = md5(req.body.password)

    // LEVEL 4
//    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
//        if (err) {
//            console.log(err)
//        } else {
//
//            const newUser = new User({
//                username: req.body.username,
//                password: hash
//            })
//            newUser.save(function (err) {
//                if (err) {
//                    console.log(err)
//                } else {
//                    res.render("secrets")
//                }
//            })
//        }
//    })
    
    
    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if (err) {
            console.log(err)
            res.redirect("/register")
        }
        else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets")
            })
        }
    }) 
})

// this redirection is only necessary with level 5
app.get("/secrets", function(req, res) {
//    if (req.isAuthenticated()) {
//        res.render("secrets")
//        }
//    else {
//        res.redirect("/login")
//    }
    
    User.find({"secret": {$ne: null}}, function(err, foundUsers) {
        if (err) {
            console.log(err)
        }
        else {
            res.render("secrets", {
                usersWithSecrets: foundUsers
            })
        }
    })
    
    
})

app.post("/login", function (req, res) {
    // LEVEL 3
    //    const hash = md5(req.body.password)
    // if (foundUser.password === hash)

    // LEVEL 4
//    User.findOne({
//        username: req.body.username
//    }, function (err, foundUser) {
//        if (err) {
//            console.log(err)
//        } else {
//            if (foundUser) {
//                bcrypt.compare(req.body.password, foundUser.password, function (err, result) {
//                    if (result === true) {
//                        res.render("secrets")
//                    } else {
//                        res.send("Your password is incorrect")
//                    }
//                })
//            } else {
//                res.send("Your username is incorrect")
//            }
//        }
//    })
    
    const user = new User({
        username: req.body.username, 
        password: req.body.password
    })
    
    req.login(user, function(err) {
        if (err) { console.log(err)}
        else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets")
            })
        }
    })
})

app.get("/logout", function(req, res) {
    req.logout()
    res.redirect("/")
})

let port = process.env.PORT;
if (port == null || port == "") {
    port = 3000;
}

app.listen(port, function () {
    console.log(`${appName} listening on port ${port}`)
})
