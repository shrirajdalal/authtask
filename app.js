// IMPORTS
const express = require('express')
const mongoose = require('mongoose')
const { urlencoded } = require('body-parser')
const session = require('express-session')
const bcrypt = require('bcrypt');

const app = express()

// CONFIGURATION/ MIDDLEWARE
// Templating engine 
app.set('view engine', 'ejs')

// Serving static files
app.use(express.static('./public'))

// Using body-parser
app.use(urlencoded({extended:false}))

// Using express-session
app.use(session({ 
    secret: 'keyboard cat', 
    resave: true, 
    saveUninitialized: true, 
    cookie: {
        secure: false,
        maxAge: 60000
    }
}))

// DATABASE - MongoDB Atlas
// databasae url
const dburl = 'mongodb+srv://<username>:<pass>@cluster0.trcszbj.mongodb.net/<database>?retryWrites=true&w=majority'

// connection
mongoose.connect(dburl,{
    useNewUrlParser:true,
    useUnifiedTopology:true
}).then(console.log("Mongo DB Connected")).catch(err=>{
    console.log('Error connecting to Mongo DB')
})

// import user model
const User = require('./models/User')


// ROUTING
// route for /
app.get('/',(req, res)=>{
    const {isAllowedSecret, user} = req.session
    let message = ""
    if(user !== undefined) {
        message ="You can only see this if you have logged in successfully!"
    }
    res.render('home', {isAllowedSecret, user, message, login:false, home:true, register:false});
})

// route for registration form
app.get('/register', (req, res)=>{
    const {isAllowedSecret, user} = req.session
    res.render('register', {isAllowedSecret, user, login:false, home:false, register:true});
})

// route for login form
app.get('/login', (req, res)=>{
    const {isAllowedSecret, user} = req.session
    res.render('login', {isAllowedSecret, user, login:true, home:false, register:false})
})

// route for secret
app.get('/secret', (req,res)=>{
    const {isAllowedSecret, user} = req.session
    // checking if user is logged in and is authorized 
    isAllowedSecret === true && user !== undefined? res.render('secret',{isAllowedSecret, user, login:false, home:false, register:false}): res.render('notallowed', {isAllowedSecret, user, login:false, home:false, register:false})
})

// route for adding new user 
app.post('/register', (req,res)=>{
    const {username, password, reenterpassword, isAllowedSecret} = req.body
    if(password === reenterpassword){
        // hashing password and also adding a salt 
        bcrypt.hash(password, 10).then(function(hash) {
            // Store hash in your password.
            const Data = new User({
                username: username,
                password: hash,
                canAccessSecret: isAllowedSecret?true:false
            })
            Data.save().then(()=>{
                res.redirect('/login')
            }).catch(err=>console.log(err))
        });
    }else{
        res.redirect('/register')
    }
})

// route for logging in user 
app.post('/login', async (req,res)=>{
    const{username, password} = req.body

    let storedUser = await User.findOne({username: username}).exec()
    if(storedUser !== null){
        // comparing the hashed password stored in database with what user provided
        bcrypt.compare(password, storedUser.password).then(function(result) {
            // result == true
            // setting session properties
            req.session.user = storedUser.username
            req.session.isAllowedSecret = storedUser.canAccessSecret
            res.redirect('/')
        });
    }else {
        res.redirect('login')
    }
    
})

// route for logging out user
app.post('/logout', (req,res)=>{
    req.session.destroy(function(err) {
        // cannot access session here
        res.render('logout', {isAllowedSecret: false, user : undefined, login:false, home:false, register:false})
      })
})

// route for catch-all
app.get('*', (req,res)=>{
    const {isAllowedSecret, user} = req.session
    res.render('oops',{isAllowedSecret, user, login:false, home:false, register:false})
})

// SERVER
app.listen(port = 3000, (req, res)=>{
    console.log('server is running..')
})
