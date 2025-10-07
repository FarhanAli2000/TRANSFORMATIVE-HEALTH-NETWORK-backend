// middleware/adminMiddleware.js
module.exports = (req, res, next) => {
  try {
    if (req.user && req.user.role === "admin") {
      next();
    } else {
      return res.status(403).json({ msg: "Access denied: Admins only" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
