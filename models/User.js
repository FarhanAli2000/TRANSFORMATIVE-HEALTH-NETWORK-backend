// models/User.js
const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetCode: String,
  resetCodeExpiry: Date,

  // Resume & Profile Info
  resumeText: String,           // Extracted resume text
  photo: String,                // Profile photo (base64 ya URL)
  resumeUploaded: {             // 👈 NEW FIELD
    type: Boolean,
    default: false,
  },
});

module.exports = mongoose.model("User", UserSchema);
