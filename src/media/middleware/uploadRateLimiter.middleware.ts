import rateLimit from "express-rate-limit";

export const uploadRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.UPLOAD_RATE_LIMIT_PER_MINUTE || 20),
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many uploads. Please retry later.",
  },
});
