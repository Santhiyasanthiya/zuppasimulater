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

// ==================== OTP STORE (TEMPORARY) ====================
const otpStore = new Map(); // { email: { otp, expiresAt } }

// ------------------------ Server test route ------------------------
app.get("/", (req, res) => {
  res.send("Zuppa Server Running...");
});

// ------------------------ Step 1: Send OTP ------------------------
app.post("/uddansignup", async (req, res) => {
  try {
    const db = await getDb();
    const collection = db.collection("signin");

    const { organization, email, username, password, mobile, address, uddan } =
      req.body || {};

    if (
      !organization ||
      !email ||
      !username ||
      !password ||
      !mobile ||
      !address ||
      !uddan
    ) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields. Drone Simulator",
      });
    }

    // Check existing user
    const existing = await collection.findOne({
      $or: [{ email }, { uddan }],
    });
    if (existing) {
      return res
        .status(409)
        .json({ success: false, message: "Email or Uddan already exists." });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 mins

    // Store OTP + signup data temporarily
    otpStore.set(email, {
      otp,
      expiresAt,
      userData: { organization, email, username, password, mobile, address, uddan },
    });

  // Send OTP Email
const mailOptions = {
  from: process.env.EMAIL,
  to: email,
  subject: "Zuppa Simulation - Verify your Email",
  html: `
    <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #fdeae1ff; border-radius: 8px; max-width: 500px; margin: auto; box-shadow: 0 2px 6px rgba(0,0,0,0.1);">
      <h2 style="color:#ff6600; text-align:center;">Zuppa Simulation</h2>
      <p style="font-size:16px; color:#333;">Dear User,</p>
      <p style="font-size:15px; color:#333;">Your Simulation OTP is:</p>
      <h1 style="letter-spacing:4px; text-align:center; color:#000;">${otp}</h1>
      <p style="font-size:14px; color:#555;">This OTP is valid for <strong>5 minutes</strong>. Please do not share it with anyone.</p>

      <hr style="border:none; border-top:1px solid #ddd; margin:20px 0;" />

      <div style="text-align:center; font-size:13px; color:#888;">
        <p>Need help or want to explore our products?</p>
        <a href="https://shop.zuppa.io" target="_blank" style="color:#ff6600; text-decoration:none; font-weight:bold;">
         shop.zuppa.io
        </a>
        <br/>
        <p style="margin-top:10px;">&copy;2024 Zuppa Geo Navigation. All rights reserved.</p>
      </div>
    </div>
  `,
};


    await transporter.sendMail(mailOptions);

    res.json({
      success: true,
      message: "OTP sent successfully to your email.",
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ success: false, message: "Server error during signup." });
  }
});

// ------------------------ Step 2: Verify OTP & Save ------------------------
app.post("/verify-otp", async (req, res) => {
  try {
    const db = await getDb();
    const collection = db.collection("signin");

    const { organization, username, password, mobile, address, uddan , email, otp } = req.body || {};

    if (!email || !otp) {
      return res
        .status(400)
        .json({ success: false, message: "Missing email or OTP." });
    }

    const record = otpStore.get(email);
    if (!record) {
      return res
        .status(400)
        .json({ success: false, message: "OTP not found. Please resend." });
    }

    if (Date.now() > record.expiresAt) {
      otpStore.delete(email);
      return res.status(400).json({ success: false, message: "OTP expired." });
    }

    if (record.otp !== otp) {
      return res.status(401).json({ success: false, message: "Invalid OTP." });
    }

    // ✅ OTP is correct → Store user in MongoDB
   

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    const uddanHash = await bcrypt.hash(uddan, saltRounds);

    const doc = {
      organization,
      email,
      mobile,
      username,
      password: passwordHash,
      address,
      uddan: uddanHash,
      createdAt: new Date(),
      activated: false,
    };

    await collection.insertOne(doc);

    otpStore.delete(email); // cleanup after success

    return res.json({
      success: true,
      message: "OTP verified successfully. Account created!",
    });
  } catch (err) {
    console.error("OTP verify error:", err);
    res.status(500).json({ success: false, message: "Error verifying OTP." });
  }
});





// ------------------------ Login ------------------------


app.post("/uddanlogin", async (req, res) => {
  try {
    const db = await getDb();
    const collection = db.collection("signin");

    const { email, password, uddan } = req.body || {};
    if (!email || !password || !uddan) {
      return res
        .status(400)
        .json({ success: false, message: "Missing email or password." });
    }

    const user = await collection.findOne({ email: email });
    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials." });
    }

    

    const matchPassword = await bcrypt.compare(password, user.passwordHash);
    if (!matchPassword) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials." });
    }
    

const matchUddan = await bcrypt.compare(uddan, user.uddan);
    if (!matchUddan) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials." });
    }
 
   
    const resp = {
      success: true,
      message: "Login successful",
      user: {
        id: user._id,
        organization: user.organization,
        email: user.email,
        mobile: user.mobile,
        username: user.username,
        address: user.address,
        activated: user.activated,
        createdAt: user.createdAt,
      },
    };


    return res.json(resp);
  } catch (err) {
    console.error("Login error:", err);
    return res
      .status(500)
      .json({ success: false, message: "Server error during login." });
  }
});



// ------------------------ Forgot Password (Simple Version) ------------------------

app.post("/forgot-password", async (req, res) => {
  try {
    const db = await getDb();
    const collection = db.collection("signin");
    const { email } = req.body || {};

    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required." });
    }

    const user = await collection.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "No user found with this email." });
    }

    // Generate a reset token (JWT valid for 15 minutes)
    const token = Jwt.sign({ email }, process.env.JWTSECRET, { expiresIn: "5m" });

    const resetLink = `http://localhost:3000/zuppa_uddan_reset_simulater?token=${token}`;

    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Zuppa Simulation - Reset Your Password",
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #fdeae1ff; border-radius: 8px; max-width: 500px; margin: auto; box-shadow: 0 2px 6px rgba(0,0,0,0.1);">
          <h2 style="color:#ff6600; text-align:center;">Zuppa Simulation</h2>
          <p style="font-size:16px; color:#333;">Dear ${user.username || "User"},</p>
          <p style="font-size:15px; color:#333;">We received a request to reset your password.</p>
          <p style="font-size:15px; color:#333;">Click the button below to reset your password:</p>

          <div style="text-align:center; margin:20px 0;">
            <a href="${resetLink}" target="_blank" style="background:#ff6600; color:#fff; padding:10px 20px; border-radius:5px; text-decoration:none; font-weight:bold;">
              Reset Password
            </a>
          </div>

          <p style="font-size:14px; color:#555;">This link will expire in 15 minutes.</p>
          <hr style="border:none; border-top:1px solid #ddd; margin:20px 0;" />

          <div style="text-align:center; font-size:13px; color:#888;">
            <p>Need help or want to explore our products?</p>
            <a href="https://shop.zuppa.io" target="_blank" style="color:#ff6600; text-decoration:none; font-weight:bold;">
              shop.zuppa.io
            </a>
            <br/>
            <p style="margin-top:10px;">&copy; ${new Date().getFullYear()} Zuppa Geo Navigation. All rights reserved.</p>
          </div>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    return res.json({ success: true, message: "Password reset link sent to your email." });
  } catch (err) {
    console.error("Forgot Password Error:", err);
    res.status(500).json({ success: false, message: "Error sending password reset link." });
  }
});

// ------------------------ Reset Password (Simple Version) ------------------------

app.post("/reset-password", async (req, res) => {
  try {
    const db = await getDb();
    const collection = db.collection("signin");
    const { token, newPassword } = req.body || {};

    if (!token || !newPassword) {
      return res.status(400).json({ success: false, message: "Missing token or new password." });
    }

    // Verify token
    const decoded = Jwt.verify(token, process.env.JWTSECRET);
    const email = decoded.email;

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await collection.updateOne(
      { email },
      { $set: { password: passwordHash, updatedAt: new Date() } }
    );

    return res.json({ success: true, message: "Password reset successful. You can now log in." });
  } catch (err) {
    console.error("Reset Password Error:", err);
    res.status(500).json({ success: false, message: "Error resetting password." });
  }
});







// *********************** ADMIN-LOGIN ****************

// ------------------------ Admin Login ------------------------
app.post("/adminlogin", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    // Check missing fields
    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Missing email or password." });
    }

    // Predefined admin credentials
    const admins = [
      {
        email: "santhiya30032@gmail.com",
        password: "252525",
        name: "Santhiya",
      },
      { email: "zuppa@gmail.com", password: "1234", name: "Zuppa Admin" },
      { email: "ajoy@gmail.com", password: "1234", name: "Ajoy" },
    ];

    // Find matching admin
    const admin = admins.find(
      (a) => a.email === email && a.password === password
    );

    if (!admin) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid admin credentials." });
    }

    // Generate JWT token for admin
    const jwtSecret = process.env.JWTSECRET || "change_this_secret_in_env";
    const payload = {
      role: "admin",
      email: admin.email,
      name: admin.name,
    };
    const token = Jwt.sign(payload, jwtSecret, { expiresIn: "12h" });

    return res.json({
      success: true,
      message: "Admin login successful",
      token,
      admin: {
        email: admin.email,
        name: admin.name,
        role: "admin",
      },
    });
  } catch (err) {
    console.error("Admin login error:", err);
    return res
      .status(500)
      .json({ success: false, message: "Server error during admin login." });
  }
});

// ------------------------ (Optional) Protected test route ------------------------
app.get("/me", async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth)
    return res
      .status(401)
      .json({ success: false, message: "Missing authorization header." });

  const token = auth.split(" ")[1];
  const jwtSecret = process.env.JWTSECRET || "change_this_secret_in_env";
  try {
    const payload = Jwt.verify(token, jwtSecret);
    return res.json({ success: true, payload });
  } catch (err) {
    return res.status(401).json({ success: false, message: "Invalid token." });
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
    res.status(500).json({ success: false, message: "Error fetching users." });
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
    res.status(500).json({ success: false, message: "Error fetching counts" });
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
        .json({ success: false, message: "User not found or no changes." });
    }

    res.json({ success: true, message: "User updated successfully" });
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).json({ success: false, message: "Error updating user." });
  }
});

// ------------------------ Start server ------------------------
app.listen(PORT, () => {
  console.log("Listening successfully on port", PORT);
});
