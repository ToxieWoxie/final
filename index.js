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

/**
 * ENV + STARTUP VALIDATION
 */
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";

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

/**
 * SECURITY / BASICS
 */
app.use(
  helmet({
    // If you embed uploads cross-origin, you may also need to tweak COEP/CORP in browsers,
    // but keep helmet defaults unless you know you need changes.
  })
);

app.use(morgan("dev"));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

/**
 * CORS
 *
 * Goals:
 * - Allow exact origins from FRONTEND_URLS/FRONTEND_URL
 * - Optionally allow Cloudflare Pages preview subdomains (*.pages.dev) via regex
 * - Handle preflight safely (no crashing)
 * - Never "fallback" ACAO to the backend domain
 */
function parseAllowedOrigins() {
  const raw = process.env.FRONTEND_URLS || process.env.FRONTEND_URL || "http://localhost:8081";
  const exact = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const regexes = [];

  // Optional: allow any Pages subdomain in non-prod OR if explicitly enabled
  const allowPagesWildcard =
    (process.env.ALLOW_PAGES_WILDCARD || "").toLowerCase() === "true" || !IS_PROD;

  if (allowPagesWildcard) {
    regexes.push(/^https:\/\/.*\.pages\.dev$/);
  }

  // Optional: allow localhost on any port in dev
  if (!IS_PROD) {
    regexes.push(/^http:\/\/localhost:\d+$/);
    regexes.push(/^http:\/\/127\.0\.0\.1:\d+$/);
  }

  return { exact: new Set(exact), regexes, raw };
}

const { exact: allowedOrigins, regexes: allowedOriginRegexes, raw: allowedOriginsRaw } =
  parseAllowedOrigins();

function isOriginAllowed(origin) {
  if (!origin) return true; // server-to-server/curl
  if (allowedOrigins.has(origin)) return true;
  return allowedOriginRegexes.some((re) => re.test(origin));
}

if (IS_PROD) {
  // In prod, fail fast if they accidentally configured only the backend domain.
  // This catches the exact issue you hit earlier.
  const backendHost = process.env.PUBLIC_BACKEND_ORIGIN?.trim();
  if (!process.env.FRONTEND_URLS && !process.env.FRONTEND_URL) {
    console.error("Missing FRONTEND_URLS or FRONTEND_URL in production. Refusing to start.");
    process.exit(1);
  }
  if (backendHost && allowedOrigins.has(backendHost)) {
    console.warn(
      `Warning: allowed origins contains PUBLIC_BACKEND_ORIGIN (${backendHost}). This is usually a misconfig.`
    );
  }
}

const corsOptions = {
  origin(origin, cb) {
    if (isOriginAllowed(origin)) return cb(null, true);
    return cb(null, false); // do not throw; prevents 500s for blocked origins
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 204,
  preflightContinue: false,
};

// Apply CORS before routes
app.use(cors(corsOptions));

// Preflight for all routes (path-to-regexp safe)
app.options(/.*/, cors(corsOptions));

// Always vary by Origin when an Origin header exists (prevents cache poisoning)
app.use((req, res, next) => {
  if (req.headers.origin) res.setHeader("Vary", "Origin");
  next();
});

/**
 * RATE LIMIT
 */
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * STATIC UPLOADS
 *
 * Critical fix: do NOT set a fallback Access-Control-Allow-Origin.
 * If origin isn't allowed, don't emit ACAO at all.
 */
app.use(
  "/uploads",
  (req, res, next) => {
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
    res.setHeader("Accept-Ranges", "bytes");

    const origin = req.headers.origin;
    if (origin && isOriginAllowed(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
      res.setHeader("Vary", "Origin");
    }

    // Optional preflight for some media fetches
    if (req.method === "OPTIONS") {
      if (origin && isOriginAllowed(origin)) {
        res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Range,Content-Type,Authorization");
        return res.sendStatus(204);
      }
      return res.sendStatus(403);
    }

    next();
  },
  express.static(path.join(__dirname, "uploads"))
);

app.get("/health", (req, res) => res.json({ ok: true, env: NODE_ENV }));

/**
 * API ROUTES
 */
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
  console.log("NODE_ENV:", NODE_ENV);
  console.log("CORS allowed origins (raw):", allowedOriginsRaw);
  console.log("CORS allowed origins (exact):", [...allowedOrigins]);
  console.log("CORS wildcard pages.dev:", (!IS_PROD || (process.env.ALLOW_PAGES_WILDCARD || "").toLowerCase() === "true"));
});
