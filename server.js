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
    .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ MongoDB Connected Successfully!"))
    .catch((err) => console.error("❌ MongoDB Connection Failed:", err));

// ✅ Define User Schema
const UserSchema = new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
});

const User = mongoose.model("User", UserSchema);

// ✅ Register User
app.post("/register", async (req, res) => {
    try {
        const { email, password, authCode } = req.body;

        if (!email || !password || !authCode) {
            return res.status(400).json({ message: "❌ All fields are required." });
        }

        if (authCode !== process.env.AUTH_CODE) {
            return res.status(400).json({ message: "❌ Invalid authentication code." });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "❌ Email already registered." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();

        res.json({ message: "✅ Registration successful!" });
    } catch (error) {
        console.error("❌ Registration error:", error);
        res.status(500).json({ message: "❌ Internal server error" });
    }
});

// ✅ Login User (Already works with email)
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: "❌ User not found" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: "❌ Invalid credentials" });
        }

        const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });

        res.json({ token, email: user.email });
    } catch (error) {
        console.error("❌ Login error:", error);
        res.status(500).json({ error: "❌ Internal server error" });
    }
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
