// FILE: server/index.js  (FULL REPLACEMENT)
// =======================================================
import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";

import authRoutes from "./routes/auth.route.js";
import projectRoutes from "./routes/projects.route.js";
import inviteRoutes from "./routes/invites.route.js";
import joinRoutes from "./routes/join.route.js";
import userRoutes from "./routes/user.route.js";
import { notFound, errorHandler } from "./middleware/error.js";

dotenv.config();

const MONGO_URI = process.env.MONGO_URI || process.env.MONGO;
if (!MONGO_URI) {
  console.error("Missing MONGO_URI (or MONGO) in .env");
  process.exit(1);
}
if (!process.env.JWT_SECRET) {
  console.error("Missing JWT_SECRET in .env");
  process.exit(1);
}

await mongoose.connect(MONGO_URI);
console.log("MongoDB connected");

const app = express();
app.set("trust proxy", 1);

app.use(helmet());
app.use(morgan("dev"));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

/**
 * CORS FIX:
 * - Use an explicit allowlist (supports multiple origins via comma-separated env)
 * - Return Access-Control-Allow-Origin for allowed origins
 * - Enable credentials + preflight for cookies/session auth
 */
const allowedOrigins = new Set(
  (process.env.FRONTEND_URLS || process.env.FRONTEND_URL || "http://localhost:8081")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
);

const corsOptions = {
  origin(origin, callback) {
    // Allow same-origin / server-to-server / curl (no Origin header)
    if (!origin) return callback(null, true);

    if (allowedOrigins.has(origin)) return callback(null, true);

    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
  })
);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Use first configured frontend as default for media CORS header
const primaryFrontendUrl = [...allowedOrigins][0] || "http://localhost:8081";

// ✅ Critical: allow the frontend origin to embed /uploads/* (fixes broken images/audio on web)
app.use(
  "/uploads",
  (req, res, next) => {
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");

    const origin = req.headers.origin;
    if (origin && allowedOrigins.has(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Vary", "Origin");
    } else {
      // fallback (non-browser or unknown origin)
      res.setHeader("Access-Control-Allow-Origin", primaryFrontendUrl);
      res.setHeader("Vary", "Origin");
    }

    next();
  },
  express.static(path.join(__dirname, "uploads"))
);

app.get("/health", (req, res) => res.json({ ok: true }));

app.use("/api/auth", authRoutes);
app.use("/api/projects", projectRoutes);
app.use("/api/invites", inviteRoutes);
app.use("/api/join", joinRoutes);
app.use("/api/users", userRoutes);

app.use(notFound);
app.use(errorHandler);

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
  console.log("CORS allowed origins:", [...allowedOrigins]);
});
;
