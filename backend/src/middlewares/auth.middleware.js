const jwt = require("jsonwebtoken");
const { User } = require("../models/authentication/User.model");
const ApiError = require("../utils/ApiError");
const { asyncHandler } = require("../utils/asyncHandler");

const verifyJWT = asyncHandler(async (req, res, next) => {
  try {
    const token = req.cookies?.token || 
                 req.header("Authorization")?.replace("Bearer ", "");
                 
    console.log("Token received:", token ? "Yes" : "No");
    console.log("Cookies:", req.cookies);
    console.log("Authorization header:", req.header("Authorization"));
    
    if (!token) {
      console.log(" No token provided");
      throw new ApiError(401, "Unauthorized request - No token provided");
    }

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    console.log(" Token decoded successfully:", decoded.id);
    
    const user = await User.findById(decoded.id).select("-password");
    if (!user) {
      console.log(" User not found for ID:", decoded.id);
      throw new ApiError(401, "Invalid access token - User not found");
    }

    console.log(" User authenticated:", user.email);
    const now = Date.now() / 1000;
    if (decoded.exp < now) {
      console.log(" Token has expired");
      throw new jwt.TokenExpiredError("Token expired", new Date(decoded.exp * 1000));
    }

    req.user = user;
    next();
  } catch (error) {
    console.log(" Auth error:", error.message);
    if (error instanceof jwt.TokenExpiredError) {
      throw new ApiError(401, "Session expired. Please login again");
    } else if (error instanceof jwt.JsonWebTokenError) {
      throw new ApiError(401, "Invalid token. Please login again");
    }
    throw new ApiError(401, error?.message || "Invalid access token");
  }
});


const checkInactivity = asyncHandler(async (req, res, next) => {
  const user = req.user;
  const now = new Date();
  const lastActive = new Date(user.lastActive);
  const hoursSinceLastActive = (now - lastActive) / (1000 * 60 * 60);

  if (hoursSinceLastActive > 2) {
    throw new ApiError(401, "Session expired due to inactivity");
  }
  
  next();
});

module.exports = { 
  verifyJWT,
  checkInactivity
};