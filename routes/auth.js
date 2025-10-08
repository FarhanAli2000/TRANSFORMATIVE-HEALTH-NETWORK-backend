require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const pdfParse = require("pdf-parse");
const mammoth = require("mammoth");
const User = require("../models/User");
const authMiddleware = require("../middleware/authMiddleware");
const adminMiddleware = require("../middleware/adminMiddleware");

const router = express.Router();

// ===== Admin Credentials from .env =====
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// ===== Register =====
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password)
      return res.status(400).json({ msg: "All fields are required" });

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ msg: "User already exists" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.json({ msg: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== Login =====
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // ✅ Admin login
    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
      const token = jwt.sign({ role: "admin" }, process.env.JWT_SECRET, {
        expiresIn: "2h",
      });

      return res.json({
        token,
        user: {
          role: "admin",
          name: "Admin",
          email: ADMIN_EMAIL,
        },
      });
    }

    // ✅ Normal user login
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "User does not exist" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, role: "user" },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    const resumeUploaded = !!(user.resumeText && user.photo);

    let profileImage = "/images/default-avatar.png";
    if (user.photo) {
      if (user.photo.startsWith("/9j/") || user.photo.startsWith("iVBOR")) {
        const type = user.photo.startsWith("/9j/") ? "jpeg" : "png";
        profileImage = `data:image/${type};base64,${user.photo}`;
      } else {
        profileImage = `http://localhost:5000/uploads/${user.photo}`;
      }
    }

    res.json({
      token,
      user: {
        id: user._id,
        role: "user",
        email: user.email,
        name: user.name,
        resumeUploaded,
        profileImage,
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/auth/users/:id
router.get("/users/:id", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ msg: "User not found" });

    res.json({ user });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});

// ✅ Get single user by ID (for admin)
router.get("/api/users/getUser/:id", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ msg: "User not found" });
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
});


module.exports = router;

// ===== Forgot Password =====
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: "User not found" });

    const code = Math.floor(100000 + Math.random() * 900000);

    user.resetCode = code;
    user.resetCodeExpiry = Date.now() + 30 * 1000; // 30 sec
    await user.save();

    console.log(`Send OTP ${code} to ${email}`);
    res.json({ msg: "Reset code sent to email", expiresIn: 30 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== Verify Code =====
router.post("/verify-code", async (req, res) => {
  const { email, code } = req.body;
  try {
    const user = await User.findOne({ email, resetCode: code });
    if (!user) return res.status(400).json({ msg: "Invalid code" });

    if (user.resetCodeExpiry < Date.now()) {
      return res.status(400).json({ msg: "Code expired" });
    }

    res.json({ msg: "Code verified" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== Reset Password =====
router.post("/reset-password", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: "User not found" });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    user.resetCode = null;
    user.resetCodeExpiry = null;
    await user.save();

    res.json({ msg: "Password updated successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== Upload Resume & Photo =====
const storage = multer.memoryStorage();
const upload = multer({ storage });

router.post(
  "/upload",
  authMiddleware,
  upload.fields([{ name: "resume" }, { name: "photo" }]),
  async (req, res) => {
    try {
      const resumeFile = req.files.resume?.[0];
      const photoFile = req.files.photo?.[0];

      if (!resumeFile || !photoFile) {
        return res.status(400).json({ msg: "Resume and photo are required" });
      }

      let resumeText = "";
      if (resumeFile.mimetype === "application/pdf") {
        const data = await pdfParse(resumeFile.buffer);
        resumeText = data.text;
      } else if (
        resumeFile.mimetype ===
          "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
        resumeFile.mimetype === "application/msword"
      ) {
        const data = await mammoth.extractRawText({ buffer: resumeFile.buffer });
        resumeText = data.value;
      }

      const user = await User.findByIdAndUpdate(
        req.user.id,
        {
          resumeText,
          photo: photoFile.buffer.toString("base64"),
          resumeUploaded: true,
        },
        { new: true }
      ).select("-password");

      res.json({ msg: "Resume & Photo uploaded successfully", user });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// ===== Get Profile =====
router.get("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ msg: "User not found" });

    res.json({ user });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});

// ===== Delete User =====
router.delete(
  "/admin/user/:id",
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const userId = req.params.id;

      const user = await User.findById(userId);
      if (!user) return res.status(404).json({ msg: "User not found" });

      await User.findByIdAndDelete(userId);

      res.json({ msg: "User deleted successfully" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);
// Get single user by ID (Admin)
router.get("/users/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password");
    if (!user) return res.status(404).json({ msg: "User not found" });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});






// ===== Admin Dashboard =====
router.get("/admin/dashboard", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select("name email resumeUploaded photo");

    res.json({
      msg: "Admin access granted",
      totalUsers: users.length,
      uploadedResumes: users.filter((u) => u.resumeUploaded).length,
      users,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
