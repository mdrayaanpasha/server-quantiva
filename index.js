import express from "express";
import mongoose from "mongoose";
import jwt, { decode } from "jsonwebtoken";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import cors from "cors";
import axios from "axios";

dotenv.config();
const app = express();
app.use(cors())
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

import bcrypt from "bcrypt";

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String, // Hash this
  verified: { type: Boolean, default: false },
});

const SubscriptionSchema = new mongoose.Schema({
  company: { type: String, required: true, trim: true, lowercase: true },
  subscriber_email: { type: String, required: true, trim: true, lowercase: true },
}, { timestamps: true });

SubscriptionSchema.index({ company: 1, subscriber_email: 1 }, { unique: true });

const Subscription = mongoose.model("Subscription", SubscriptionSchema);





// 🔹 Middleware to Verify JWT
const verifyToken = (req, res, next) => {
  const token = req.header("Authorization");
  console.log(token)

  if (!token) return res.status(401).json({ error: "Unauthorized: No token provided" });

  try {
    const decoded = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET);
    req.user = decoded;  // Attach decoded user info to `req.user`
    next();
  } catch (err) {
    return res.status(401).json({ error: "Unauthorized: Invalid token" });
  }
};

// 🔹 Get User's Subscribed Companies
app.get("/subscriptions", verifyToken, async (req, res) => {
  try {
    const email = req.user.email;
    const subscriptions = await Subscription.find({ subscriber_email: email }).select("company -_id");

    res.json({ subscriptions: subscriptions.map(sub => sub.company) });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});


app.post("/subscribe", verifyToken, async (req, res) => {
  try {
    let { company } = req.body;
    const email = req.user.email;

    if (!company || typeof company !== "string" || company.trim().length < 2) {
      return res.status(400).json({ error: "Invalid company name" });
    }

    company = company.trim().toLowerCase();

    // Insert directly, let MongoDB handle duplicates
    const newSubscription = new Subscription({ company, subscriber_email: email });

    await newSubscription.save();
    res.json({ message: "Subscribed successfully" });

  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ error: "Already subscribed to this company" });
    }
    res.status(500).json({ error: "Server error" });
  }
});



const User = mongoose.model("User", userSchema);

const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: { user: process.env.EMAIL, pass: process.env.EMAIL_PASS },
});

app.post("/api/register", async (req, res) => {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ email });
  
    if (existingUser) return res.status(400).json({ error: "User already exists" });
  
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
  
    // Send email verification
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" });
    const verifyLink = `${process.env.FRONTEND_URL}/verify/${token}`;
  
    await transporter.sendMail({
      to: email,
      subject: "Verify Your Email",
      text: `Click here to verify: ${verifyLink}`,
    });
  
    res.json({ message: "Verification email sent" });
  });


  app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
  
    if (!user) return res.status(400).json({ error: "User not found" });
    if (!user.verified) return res.status(400).json({ error: "Email not verified" });
  
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Incorrect password" });
  
    const authToken = jwt.sign({ email: user.email, id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
  
    res.json({ message: "Login successful", token: authToken });
  });


  app.post("/api/forgot-password", async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
  
    if (!user) return res.status(400).json({ error: "User not found" });
  
    const resetToken = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: "15m" });
  
    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    await transporter.sendMail({
      to: email,
      subject: "Reset Your Password",
      text: `Click here to reset: ${resetLink}`,
    });
  
    res.json({ message: "Password reset email sent" });
  });
  app.post("/api/reset-password", async (req, res) => {
    const { token, newPassword } = req.body;
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log(decoded.email)
      const user = await User.findOne({ email: decoded.email });
  
      if (!user) return res.status(400).json({ error: "User not found" });
  
      user.password = await bcrypt.hash(newPassword, 10);
      await user.save();
  
      res.json({ message: "Password reset successful" });
    } catch (err) {
      res.status(400).json({ error: "Invalid or expired token" });
    }
  });
      


app.post("/api/verify", async (req, res) => {
    const { token } = req.body;
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findOne({ email: decoded.email });
  
      if (!user) return res.status(400).json({ message: "User not found" });
  
      if (!user.verified) {
        user.verified = true;
        await user.save();
      }
  
      // Generate a new JWT token for authentication
      const authToken = jwt.sign({ email: user.email, id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
  
      return res.json({ message: "Email verified successfully", token: authToken });
    } catch (err) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }
  });
  

  app.get("/reddit-stock-analysis", async (req, res) => {
    const apiKey = process.env.GEMINI_API_KEY;
  
    if (!apiKey) return res.status(500).send("Missing API Key");
  
    try {
      const response = await axios.post(
        "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent",
        {
          contents: [
            {
              parts: [
                {
                  text: "Summarize recent Reddit discussions on the stock market: trends, hot stocks, and sentiment. let the response be super concise and cover every important detail, use of minimalist and appropriate emojis is appreciated, but dont use lot of emojis."
                },
              ],
            },
          ],
        },
        {
          headers: { "Content-Type": "application/json" },
          params: { key: apiKey },
        }
      );
  
      const generatedText =
        response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "No response";
      res.json({ summary: generatedText });
    } catch (error) {
      console.error("Error:", error.response?.data || error.message);
      res.status(500).send("Failed to fetch data");
    }
  });


  app.get("/x-stock-analysis", async (req, res) => {
    const apiKey = process.env.GEMINI_API_KEY;
  
    if (!apiKey) return res.status(500).send("Missing API Key");
  
    try {
      const response = await axios.post(
        "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent",
        {
          contents: [
            {
              parts: [
                {
                  text: "Summarize recent x (twitter) discussions on the stock market: trends, hot stocks, and sentiment. let the response be super concise and cover every important detail, use of minimalist and appropriate emojis is appreciated,but dont use lot of emojis."
                },
              ],
            },
          ],
        },
        {
          headers: { "Content-Type": "application/json" },
          params: { key: apiKey },
        }
      );
  
      const generatedText =
        response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "No response";
      res.json({ summary: generatedText });
    } catch (error) {
      console.error("Error:", error.response?.data || error.message);
      res.status(500).send("Failed to fetch data");
    }
  });


  app.get("/wallstreet-stock-analysis", async (req, res) => {
    const apiKey = process.env.GEMINI_API_KEY;
  
    if (!apiKey) return res.status(500).send("Missing API Key");
  
    try {
      const response = await axios.post(
        "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent",
        {
          contents: [
            {
              parts: [
                {
                  text: "Summarize recent wallstreet journal discussions on the stock market: trends, hot stocks, and sentiment.let the response be super concise and cover every important detail, use of minimalist and appropriate emojis is appreciated,but dont use lot of emojis."
                },
              ],
            },
          ],
        },
        {
          headers: { "Content-Type": "application/json" },
          params: { key: apiKey },
        }
      );
  
      const generatedText =
        response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "No response";
      res.json({ summary: generatedText });
    } catch (error) {
      console.error("Error:", error.response?.data || error.message);
      res.status(500).send("Failed to fetch data");
    }
  });
  app.get("/sec-stock-analysis", async (req, res) => {
    const apiKey = process.env.GEMINI_API_KEY;
  
    if (!apiKey) return res.status(500).send("Missing API Key");
  
    try {
      const response = await axios.post(
        "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent",
        {
          contents: [
            {
              parts: [
                {
                  text: "Summarize the latest SEC filings, highlighting major stock moves, insider trades, and any unusual activity that could impact the market, let the response be super concise and cover every important detail, use of minimalist and appropriate emojis is appreciated,but dont use lot of emojis."
                },
              ],
            },
            
          ],
        },
        {
          headers: { "Content-Type": "application/json" },
          params: { key: apiKey },
        }
      );
  
      const generatedText =
        response.data?.candidates?.[0]?.content?.parts?.[0]?.text || "No response";
      res.json({ summary: generatedText });
    } catch (error) {
      console.error("Error:", error.response?.data || error.message);
      res.status(500).send("Failed to fetch data");
    }
  });



app.listen(5000, () => console.log("Server running on port 5000"));
