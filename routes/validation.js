const User = require("../model/User");
const Joi = require("@hapi/joi");
const jwt = require("jsonwebtoken");// middleware to validate token

const registerValidation = (data) => {
    const schema = Joi.object({
        username: Joi.string().max(255).required(),
        password: Joi.string().max(1024).required(),
    });
    return schema.validate(data);
};

const loginValidation = (data) => {
    const schema = Joi.object({
        username: Joi.string().max(255).required(),
        password: Joi.string().max(1024).required(),
    });
    return schema.validate(data);
};

const verifyToken = async (req, res, next) => {
    const token = req.cookies["jwt"];
    if (!token)
        return res.status(401).json({ error: "Access denied" });

    try {
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        const user = await User.findOne({ _id: verified.id });
        req.user = user;
        next(); // to continue the flow
    } catch (err) {
        res.status(400).json({ error: "Token is not valid" });
    }
};

module.exports = {
    registerValidation,
    loginValidation,
    verifyToken,
};
