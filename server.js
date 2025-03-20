require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
 
const app = express();
app.use(express.json());
app.use(cors());

// ✅ Connect to MongoDB
mongoose
    .connect(process.env.MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
    .then(() => console.log("✅ MongoDB Connected Successfully!"))
    .catch((err) => console.error("❌ MongoDB Connection Failed:", err));

// ✅ Define User Schema
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    isAuthenticated: { type: Boolean, default: false }
});

const User = mongoose.model("User", UserSchema);

// ✅ Register User with Authentication Code
app.post("/register", async (req, res) => {
    const { username, password, authCode } = req.body;

    // Check if authCode matches the manually provided one
    if (authCode !== process.env.AUTH_CODE) {
        return res.status(400).json({ message: "❌ Invalid authentication code." });
    }

    // Check if username is already taken
    const existingUser = await User.findOne({ username });
    if (existingUser) {
        return res.status(400).json({ message: "❌ Username already taken." });
    }

    // Hash password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword, isAuthenticated: true });
    await user.save();

    res.json({ message: "✅ Registration successful!" });
});

// ✅ Login User (Using `username` Instead of `email`)
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user) {
        return res.status(400).json({ error: "❌ User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ error: "❌ Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({ token, username: user.username });
});

// ✅ Protected Route (Middleware to Verify Token)
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;

    if (!token) return res.status(401).json({ message: "❌ No token provided" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: "❌ Invalid token" });

        req.user = decoded;
        next();
    });
};

// ✅ Access Protected Route Only If Logged In
app.get("/protected", verifyToken, (req, res) => {
    res.json({ message: "✅ Access granted", user: req.user });
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
