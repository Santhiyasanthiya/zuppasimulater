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
const URL = process.env.DB;

// ------------------------ Helpers ------------------------
function base64ToHex(b64) {
  if (!b64) return null;
  return Buffer.from(b64, "base64").toString("hex");
}

// ------------------------ DB --------------------------------------
let client;
async function getDb() {
  if (!client) {
    client = new MongoClient(URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    await client.connect();
    console.log("✅ MongoDB connected");
  }
  return client.db("zuppaSimulation");
}

// ------------------------ Middleware ----------------------------------
app.use(express.json());
app.use(cors({ origin: "*", credentials: true }));

app.use("/files", express.static(path.join(process.cwd(), "public")));

// ------------------------ Nodemailer transporter -----------------------
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

    const { organization, email, mobile, username, password, address, mac } =
      req.body || {};

      console.log("UDDAN", organization, email, mobile, username, password, address, mac);
    // if (
    //   !organization ||
    //   !email ||
    //   !mobile ||
    //   !username ||
    //   !password ||
    //   !address
    // ) {
    //   return res
    //     .status(400)
    //     .json({ success: false, reason: "Missing required fields." });
    // }

    // const existing = await collection.findOne({
    //   $or: [{ username: username }, { email: email }],
    // });
    // if (existing) {
    //   return res
    //     .status(409)
    //     .json({ success: false, reason: "Username or email already exists." });
    // }
    // const saltRounds = 10;
    // const passwordHash = await bcrypt.hash(password, saltRounds);

    // const doc = {
    //   organization,
    //   email,
    //   mobile,
    //   username,
    //   passwordHash,
    //   address,
    //   mac: mac || null,
    //   access:false,
    //   createdAt: new Date(),
    //   activated: true,
    // };

    // const result = await collection.insertOne(doc);

    // // send welcome email (do not block on failure)
    // const mailOptions = {
    //   from: process.env.EMAIL,
    //   to: email,
    //   subject: "Welcome to Zuppa Simulation",
    //   text: `Hello ${username},\n\nThank you for registering. Your account has been created.\n\nRegards,\nZuppa Team`,
    // };

    // transporter.sendMail(mailOptions).catch((err) => {
    //   console.warn("Warning: failed to send welcome email:", err);
    // });

    // return res.json({ success: true });
  } catch (err) {
    console.error("Signup error:", err);
    return res
      .status(500)
      .json({ success: false, reason: "Server error during signup." });
  }
});

// ------------------------ Login ------------------------
app.post("/udanlogin", async (req, res) => {
  try {
    const db = await getDb();
    const collection = db.collection("signin");

    const { email, password, mac } = req.body || {};
    if (!email || !password || !mac) {
      return res
        .status(400)
        .json({ success: false, reason: "Missing email or password." });
    }

    const user = await collection.findOne({ email: email });
    if (!user) {
      return res
        .status(401)
        .json({ success: false, reason: "Invalid credentials." });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res
        .status(401)
        .json({ success: false, reason: "Invalid credentials." });
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

   const simulatorUrl =
      process.env.SIMULATOR_URL ||
      `${req.protocol}://${req.hostname}:${
        process.env.PORT || PORT
      }/files/Zuppa_Drone_Sim_V2.enc`;

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
      AES_KEY_B64: process.env.AES_KEY_B64,
      aes_key: process.env.AES_KEY_B64,
    };

    if (simulatorUrl) resp.simulator_url = simulatorUrl;
    if (simulatorKeyHex) resp.simulator_key_hex = simulatorKeyHex;

    return res.json(resp);
  } catch (err) {
    console.error("Login error:", err);
    return res
      .status(500)
      .json({ success: false, reason: "Server error during login." });
  }
});

// ------------------------ (Optional) Protected test route ------------------------
app.get("/me", async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth)
    return res
      .status(401)
      .json({ success: false, reason: "Missing authorization header." });

  const token = auth.split(" ")[1];
  const jwtSecret = process.env.JWTSECRET || "change_this_secret_in_env";
  try {
    const payload = Jwt.verify(token, jwtSecret);
    return res.json({ success: true, payload });
  } catch (err) {
    return res.status(401).json({ success: false, reason: "Invalid token." });
  }
});

// ------------------------ Get All Users (for Admin) ------------------------
app.get("/getUsers", async (req, res) => {
  try {
    const db = await getDb();
    const collection = db.collection("signin");

    const users = await collection
      .find({}, { projection: { passwordHash: 0 } })
      .toArray();

    res.json({ success: true, users });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ success: false, reason: "Error fetching users." });
  }
});

// ------------------------ Get Dashboard Counts ------------------------
app.get("/getDashboardCounts", async (req, res) => {
  try {
    const db = await getDb();
    const collection = db.collection("signin");

    const totalUsers = await collection.countDocuments();
    const totalAccess = await collection.countDocuments({ activated: true });
    const pendingAccess = await collection.countDocuments({ activated: false });

    res.json({
      success: true,
      totalUsers,
      totalAccess,
      pendingAccess,
    });
  } catch (err) {
    console.error("Error fetching dashboard counts:", err);
    res.status(500).json({ success: false, reason: "Error fetching counts" });
  }
});

// ------------------------ Update User (Admin) ------------------------
app.put("/updateUser/:id", async (req, res) => {
  try {
    const db = await getDb();
    const collection = db.collection("signin");

    const { id } = req.params;
    const updatedData = req.body;

    delete updatedData._id;

    const result = await collection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedData }
    );

    if (result.modifiedCount === 0) {
      return res
        .status(404)
        .json({ success: false, reason: "User not found or no changes." });
    }

    res.json({ success: true, message: "User updated successfully" });
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).json({ success: false, reason: "Error updating user." });
  }
});

// ------------------------ Start server ------------------------
app.listen(PORT, () => {
  console.log("Listening successfully on port", PORT);
});
