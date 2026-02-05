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


// Helmet defaults CORP=same-origin. We'll override CORP for /uploads below.
app.use(helmet());

app.use(morgan("dev"));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

const frontendUrl = process.env.FRONTEND_URL || "http://localhost:8081";

app.use(cors({ credentials: true, origin: true }));


app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
  })
);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ✅ Critical: allow the frontend origin to embed /uploads/* (fixes broken images/audio on web)
app.use(
  "/uploads",
  (req, res, next) => {
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
    // Helpful when the browser fetches media with CORS (Audio() / metadata / etc.)
    res.setHeader("Access-Control-Allow-Origin", frontendUrl);
    res.setHeader("Vary", "Origin");
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
});
