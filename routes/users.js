const User = require("../model/User");
const express = require('express');
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');
const router = express.Router();
const { registerValidation, loginValidation, verifyToken } = require("./validation");
const multer = require('multer');

const storage = multer.diskStorage({
    destination: function (req, file, callback) {
        callback(null, './uploads');
    },
    filename: function (req, file, callback) {
        callback(null, file.originalname);
    }
});

const upload = multer({ storage : storage }).array('file', 100);

router.get('/register', (req, res, next) => {
    res.render('register');
});

router.post('/register', async (req, res, next) => {
    // validate the user
    const { error } = registerValidation(req.body);  
    if (error) 
        return res.status(400).json({ error: error.details[0].message });

    const isUserExist = await User.findOne({ username: req.body.username });

    // throw error when username already registered
    if (isUserExist)
        return res.status(400).json({ error: "Username already exists" });

    const salt = await bcrypt.genSalt(10);
    const password = await bcrypt.hash(req.body.password, salt);

    const user = new User({
        username: req.body.username,
        password: password,
    });
    
    try {
        const savedUser = await user.save();
        res.json({ error: null, data: savedUser });
    } catch (error) {
        res.status(400).json({ error });
    }
});

router.get("/login", (req, res, next) => {
    res.render('login');
});

router.post("/login", async (req, res) => {  // validate the user
    const { error } = loginValidation(req.body);  // throw validation errors
    if (error) 
        return res.status(400).json({ error: error.details[0].message });

    const user = await User.findOne({ username: req.body.username });  // throw error when username is wrong

    if (!user) 
        return res.status(400).json({ error: "Username is wrong" });  // check for password correctness

    const validPassword = await bcrypt.compare(req.body.password, user.password);  
    if (!validPassword)
        return res.status(400).json({ error: "Password is wrong" });  

    // create token
    const token = jwt.sign({
        // payload data
            name: user.name,
            id: user._id,
        },
        process.env.TOKEN_SECRET
    );

    // res.header("auth-token", token).json({
    //     error: null,
    //     data: {
    //         token,
    //     },
    // });
    res.cookie('jwt', token, {
        httpOnly: true,
        secure: false,
        maxAge: 3600000
    }).json({
        error: null,
        data: {
            token,
        },
    });
});

router.get('/logout', (req, res, next) => {
    res.clearCookie("jwt")
    .json({
        error: null,
        data: {},
    });
});

router.get('/profile', verifyToken, (req, res, next) => {
    res.render("profile", { username: req.user.username });
});

router.post('/profile', (req, res) => {
    upload(req, res, (err) => {
        if(err) {
            return res.send("Error uploading file.");
        }
        res.send("File is uploaded");
    });
});

module.exports = router;