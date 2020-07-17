//jshint esversion:6
require('dotenv').config()
const appName = "Secrets"
const express = require("express")
const bodyParser = require("body-parser")
const app = express()
const mongoose = require("mongoose")
const encrypt = require('mongoose-encryption')


mongoose.connect("mongodb://localhost:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true
})

const userSchema = new mongoose.Schema({
    username: String,
    password: String
})

userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });


const User = new mongoose.model("User", userSchema)

app.use(bodyParser.urlencoded({
    extended: true
}));

// EJS stuff
app.set("view engine", "ejs")
app.use(express.static("public"))

app.get("/", function (req, res) {
    res.render("home")
})

app.get("/login", function (req, res) {
    res.render("login")
})

app.get("/register", function (req, res) {
    res.render("register")
})

app.post("/register", function (req, res) {
    const newUser = new User({
        username: req.body.username,
        password: req.body.password
    })
    newUser.save(function (err) {
        if (err) {
            console.log(err)
        } else {
            res.render("secrets")
        }
    })
})

app.post("/login", function (req, res) {
    User.findOne({
        username: req.body.username
    }, function (err, foundUser) {
        if (err) {
            console.log(err)
        } else {
            if (foundUser) {
                if (foundUser.password === req.body.password) {
                    res.render("secrets")
                }
                else {res.send("Your password is incorrect")}
            } else {
                res.send("Your username is incorrect")
            }
        }
    })
})

let port = process.env.PORT;
if (port == null || port == "") {
    port = 3000;
}

app.listen(port, function () {
    console.log(`${appName} listening on port ${port}`)
})
