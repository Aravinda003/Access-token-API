require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || "your_secret_key";
const REFRESH_SECRET_KEY = process.env.REFRESH_SECRET_KEY || "your_refresh_secret_key";

let refreshTokens = [];  // Store refresh tokens temporarily (use a database in production)

// ✅ Generate Access & Refresh Tokens
app.post('/generate-token', (req, res) => {
    const { username, role } = req.body;

    if (!username || !role) {
        return res.status(400).json({ message: "Username and role are required!" });
    }

    // JWT Payload
    const payload = { username, role };

    // Generate Access Token (expires in 1 minute)
    const accessToken = jwt.sign(payload, SECRET_KEY, { expiresIn: '1m' });

    // Generate Refresh Token (expires in 7 days)
    const refreshToken = jwt.sign(payload, REFRESH_SECRET_KEY, { expiresIn: '7d' });

    refreshTokens.push(refreshToken);  // Store refresh token

    res.json({ accessToken, refreshToken });
});

// ✅ Refresh Token Endpoint
app.post('/refresh-token', (req, res) => {
    const { token } = req.body;

    if (!token) return res.status(401).json({ message: "Refresh Token is required!" });
    if (!refreshTokens.includes(token)) return res.status(403).json({ message: "Invalid Refresh Token!" });

    // Verify Refresh Token
    jwt.verify(token, REFRESH_SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid Token!" });

        // Generate new Access Token
        const newAccessToken = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1m' });

        res.json({ accessToken: newAccessToken });
    });
});

// ✅ Protected Route (Requires Access Token)
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: "This is a protected route!", user: req.user });
});

// ✅ Middleware to Verify Access Token
function verifyToken(req, res, next) {
    const token = req.header('Authorization')?.split(" ")[1];

    if (!token) return res.status(401).json({ message: "Access Denied!" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid Token!" });
        req.user = user;
        next();
    });
}

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
