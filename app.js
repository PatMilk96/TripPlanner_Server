const path = require('path')
const mongoose = require('mongoose')

const express = require('express')
const bodyParser = require('body-parser')
const app = express()

const index = require('./routes')
const session = require('express-session')
const cookieParser = require('cookie-parser')
app.use(cookieParser())

app.use(express.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(express.static(path.join(__dirname, 'public')))
app.use(session({secret: 'my secret', resave: false, saveUninitialized: false}))

app.use('/', index.routes)

mongoose.set('strictQuery', true)
mongoose.connect('mongodb://127.0.0.1:27017/db3')
    .then(res => {
        console.log('Connected!');
        app.listen(3000)
    })
    .catch(err => {
        console.log('Mongoose connection error: ' + err)
    })