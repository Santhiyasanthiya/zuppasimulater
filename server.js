// import express from "express";
// import cors from "cors";
// import { MongoClient, ObjectId } from "mongodb";
// import Jwt from "jsonwebtoken";
// import bcrypt from "bcrypt";
// import nodemailer from "nodemailer";
// import "dotenv/config";

// const app = express();
// const PORT = process.env.PORT || 4001;
// const URL = process.env.DB; // your connection string (mongodb+srv://...)

// // Use DB name: zuppaSimulation
// let client;
// async function getDb() {
//   if (!client) {
//     client = new MongoClient(URL, { useNewUrlParser: true, useUnifiedTopology: true });
//     await client.connect();
//     console.log("✅ MongoDB connected");
//   }
//   return client.db("zuppaSimulation");
// }

// app.use(express.json());
// app.use(cors({ origin: "*", credentials: true }));

// // ------------------------ Nodemailer transporter --------------------
// const transporter = nodemailer.createTransport({
//   service: "gmail",
//   auth: {
//     user: process.env.EMAIL,
//     pass: process.env.EMAILPASSWORD,
//   },
// });

// // ------------------------ Server test route ------------------------
// app.get("/", (req, res) => {
//   res.send("Zuppa Server Running...");
// });

// // ------------------------ Register / Signup ------------------------

// app.post("/udansignup", async (req, res) => {
//   try {
//     const db = await getDb();
//     const collection = db.collection("signin");

//     const { organization, email, mobile, username, password, address, mac } = req.body || {};

//     // basic validation
//     if (!organization || !email || !mobile || !username || !password || !address) {
//       return res.status(400).json({ success: false, reason: "Missing required fields." });
//     }

//     // check existing username or email
//     const existing = await collection.findOne({
//       $or: [{ username: username }, { email: email }],
//     });
//     if (existing) {
//       return res.status(409).json({ success: false, reason: "Username or email already exists." });
//     }

//     // hash password
//     const saltRounds = 10;
//     const passwordHash = await bcrypt.hash(password, saltRounds);

//     const doc = {
//       organization,
//       email,
//       mobile,
//       username,
//       passwordHash,
//       address,
//       mac: mac || null,
//       createdAt: new Date(),
//       activated: true, // set as true for now; change flow if you want admin activation
//     };

//     const result = await collection.insertOne(doc);

//     // attempt to send welcome email (don't fail the signup if email fails)
//     const mailOptions = {
//       from: process.env.EMAIL,
//       to: email,
//       subject: "Welcome to Zuppa Simulation",
//       text: `Hello ${username},\n\nThank you for registering. Your account has been created.\n\nRegards,\nZuppa Team`,
//     };

//     transporter.sendMail(mailOptions).catch((err) => {
//       console.warn("Warning: failed to send welcome email:", err);
//     });

//     return res.json({ success: true });
//   } catch (err) {
//     console.error("Signup error:", err);
//     return res.status(500).json({ success: false, reason: "Server error during signup." });
//   }
// });

// // ------------------------ Login ------------------------

// app.post("/udanlogin", async (req, res) => {
//   try {
//     const db = await getDb();
//     const collection = db.collection("signin");

//     const { username, password, mac } = req.body || {};
//     if (!username || !password) {
//       return res.status(400).json({ success: false, reason: "Missing username or password." });
//     }

//     const user = await collection.findOne({ username: username });
//     if (!user) {
//       return res.status(401).json({ success: false, reason: "Invalid credentials." });
//     }

//     const match = await bcrypt.compare(password, user.passwordHash);
//     if (!match) {
//       return res.status(401).json({ success: false, reason: "Invalid credentials." });
//     }

//     // Optionally: store/update mac address on login
//     if (mac) {
//       try {
//         await collection.updateOne({ _id: user._id }, { $set: { mac } });
//       } catch (e) {
//         console.warn("Failed to update mac:", e);
//       }
//     }

//     // Create JWT
//     const jwtSecret = process.env.JWTSECRET || "change_this_secret_in_env";
//     const payload = {
//       id: String(user._id),
//       username: user.username,
//       email: user.email,
//     };
//     const token = Jwt.sign(payload, jwtSecret, { expiresIn: "12h" });

//     // Return safe user object (omit passwordHash)
//     const safeUser = {
//       id: String(user._id),
//       username: user.username,
//       email: user.email,
//       organization: user.organization,
//       mobile: user.mobile,
//       address: user.address,
//       activated: user.activated ?? true,
//     };

//     return res.json({ success: true, token, user: safeUser });
//   } catch (err) {
//     console.error("Login error:", err);
//     return res.status(500).json({ success: false, reason: "Server error during login." });
//   }
// });

// // ------------------------ (Optional) Protected test route ------------------------
// app.get("/me", async (req, res) => {
//   const auth = req.headers.authorization;
//   if (!auth) return res.status(401).json({ success: false, reason: "Missing authorization header." });

//   const token = auth.split(" ")[1];
//   const jwtSecret = process.env.JWTSECRET || "change_this_secret_in_env";
//   try {
//     const payload = Jwt.verify(token, jwtSecret);
//     return res.json({ success: true, payload });
//   } catch (err) {
//     return res.status(401).json({ success: false, reason: "Invalid token." });
//   }
// });

// // ------------------------ Start server ------------------------
// app.listen(PORT, () => {
//   console.log("Listening successfully on port", PORT);
// });




// server.js
import express from "express";
import cors from "cors";
import path from "path";
import { MongoClient, ObjectId } from "mongodb";
import Jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import "dotenv/config";

const app = express();
const PORT = process.env.PORT || 4001;
const URL = process.env.DB; // your connection string

// ------------------------ Helpers ------------------------
function base64ToHex(b64) {
  if (!b64) return null;
  return Buffer.from(b64, "base64").toString("hex");
}

// ------------------------ DB ------------------------
let client;
async function getDb() {
  if (!client) {
    client = new MongoClient(URL, { useNewUrlParser: true, useUnifiedTopology: true });
    await client.connect();
    console.log("✅ MongoDB connected");
  }
  return client.db("zuppaSimulation");
}

// ------------------------ Middleware ------------------------
app.use(express.json());
app.use(cors({ origin: "*", credentials: true }));

// serve static files from ./public at /files/*
app.use("/files", express.static(path.join(process.cwd(), "public")));

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
      activated: true,
    };

    const result = await collection.insertOne(doc);

    // send welcome email (do not block on failure)
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

    // --- simulator info injection (only after auth) ---
    // Preferred: use explicit SIMULATOR_URL in .env for correct externally reachable URL.
    // Fallback: attempt to build from request host + port (may be inaccurate behind proxies).
    const simulatorUrl = process.env.SIMULATOR_URL || `${req.protocol}://${req.hostname}:${process.env.PORT || PORT}/files/Zuppa_Drone_Sim_V2.enc`;

    let simulatorKeyHex = null;
    try {
      if (process.env.AES_KEY_B64) {
        const b64 = process.env.AES_KEY_B64.trim();
        simulatorKeyHex = base64ToHex(b64);
      }
    } catch (e) {
      console.error("Failed to convert AES_KEY_B64 to hex:", e);
      simulatorKeyHex = null;
    }

    const resp = {
      success: true,
      token,
      user: safeUser,
    };

    // include simulator fields when available
    if (simulatorUrl) resp.simulator_url = simulatorUrl;
    if (simulatorKeyHex) resp.simulator_key_hex = simulatorKeyHex;

    return res.json(resp);
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
