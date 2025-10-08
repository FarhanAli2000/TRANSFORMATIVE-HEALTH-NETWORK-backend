const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ msg: "No token provided" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach decoded token first
    req.user = decoded;

    if (decoded.role !== "admin") {
      return res.status(403).json({ msg: "Access denied. Admins only." });
    }

    next();
  } catch (err) {
    res.status(401).json({ msg: "Invalid or expired token" });
  }
};
