import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import Jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import "dotenv/config";

const app = express();
const PORT = process.env.PORT || 4001;
const URL = process.env.DB; // your connection string (mongodb+srv://...)

// Use DB name: zuppaSimulation
let client;
async function getDb() {
  if (!client) {
    client = new MongoClient(URL, { useNewUrlParser: true, useUnifiedTopology: true });
    await client.connect();
    console.log("✅ MongoDB connected");
  }
  return client.db("zuppaSimulation");
}

app.use(express.json());
app.use(cors({ origin: "*", credentials: true }));

// ------------------------ Nodemailer transporter --------------------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAILPASSWORD,
  },
});

// ------------------------ Server test route ------------------------
app.get("/", (req, res) => {
  res.send("Zuppa Server Running...");
});

// ------------------------ Register / Signup ------------------------
/*
Expected JSON (from your Python):
{
  "organization": org,
  "email": email,
  "mobile": mobile,
  "username": username,
  "password": password,
  "address": address,
  "mac": mac
}
Response:
{ success: true } or { success: false, reason: "..." }
*/
app.post("/udansignup", async (req, res) => {
  try {
    const db = await getDb();
    const collection = db.collection("signin");

    const { organization, email, mobile, username, password, address, mac } = req.body || {};

    // basic validation
    if (!organization || !email || !mobile || !username || !password || !address) {
      return res.status(400).json({ success: false, reason: "Missing required fields." });
    }

    // check existing username or email
    const existing = await collection.findOne({
      $or: [{ username: username }, { email: email }],
    });
    if (existing) {
      return res.status(409).json({ success: false, reason: "Username or email already exists." });
    }

    // hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const doc = {
      organization,
      email,
      mobile,
      username,
      passwordHash,
      address,
      mac: mac || null,
      createdAt: new Date(),
      activated: true, // set as true for now; change flow if you want admin activation
    };

    const result = await collection.insertOne(doc);

    // attempt to send welcome email (don't fail the signup if email fails)
    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Welcome to Zuppa Simulation",
      text: `Hello ${username},\n\nThank you for registering. Your account has been created.\n\nRegards,\nZuppa Team`,
    };

    transporter.sendMail(mailOptions).catch((err) => {
      console.warn("Warning: failed to send welcome email:", err);
    });

    return res.json({ success: true });
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).json({ success: false, reason: "Server error during signup." });
  }
});

// ------------------------ Login ------------------------
/*
Expected JSON (from your Python):
{ "username": username, "password": password, "mac": mac }
Response:
{ success: true, token: "...", user: {...} } or { success: false, reason: "..." }
*/
app.post("/udanlogin", async (req, res) => {
  try {
    const db = await getDb();
    const collection = db.collection("signin");

    const { username, password, mac } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ success: false, reason: "Missing username or password." });
    }

    const user = await collection.findOne({ username: username });
    if (!user) {
      return res.status(401).json({ success: false, reason: "Invalid credentials." });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(401).json({ success: false, reason: "Invalid credentials." });
    }

    // Optionally: store/update mac address on login
    if (mac) {
      try {
        await collection.updateOne({ _id: user._id }, { $set: { mac } });
      } catch (e) {
        console.warn("Failed to update mac:", e);
      }
    }

    // Create JWT
    const jwtSecret = process.env.JWTSECRET || "change_this_secret_in_env";
    const payload = {
      id: String(user._id),
      username: user.username,
      email: user.email,
    };
    const token = Jwt.sign(payload, jwtSecret, { expiresIn: "12h" });

    // Return safe user object (omit passwordHash)
    const safeUser = {
      id: String(user._id),
      username: user.username,
      email: user.email,
      organization: user.organization,
      mobile: user.mobile,
      address: user.address,
      activated: user.activated ?? true,
    };

    return res.json({ success: true, token, user: safeUser });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ success: false, reason: "Server error during login." });
  }
});

// ------------------------ (Optional) Protected test route ------------------------
app.get("/me", async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ success: false, reason: "Missing authorization header." });

  const token = auth.split(" ")[1];
  const jwtSecret = process.env.JWTSECRET || "change_this_secret_in_env";
  try {
    const payload = Jwt.verify(token, jwtSecret);
    return res.json({ success: true, payload });
  } catch (err) {
    return res.status(401).json({ success: false, reason: "Invalid token." });
  }
});

// ------------------------ Start server ------------------------
app.listen(PORT, () => {
  console.log("Listening successfully on port", PORT);
});
