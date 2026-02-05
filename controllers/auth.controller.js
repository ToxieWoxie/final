// FILE: server/controllers/auth.controller.js  (FULL REPLACEMENT)
// =======================================================
import bcrypt from "bcryptjs";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";

import { User } from "../models/user.model.js";
import { signJwt } from "../utils/jwt.js";
import { jsonError, pick } from "../utils/http.js";

function headerValue(req, name) {
  const v = req?.headers?.[name];
  return Array.isArray(v) ? v[0] : v;
}

function isHttpsRequest(req) {
  if (req?.secure) return true;

  const xfProto = String(headerValue(req, "x-forwarded-proto") || "")
    .split(",")[0]
    .trim()
    .toLowerCase();

  return xfProto === "https";
}

/**
 * Cookie auth:
 * - http://localhost => secure=false, sameSite=lax
 * - https (prod)     => secure=true,  sameSite=none
 *
 * Optional env overrides:
 * - COOKIE_SECURE=true/false
 * - COOKIE_SAMESITE=none/lax/strict
 * - COOKIE_DOMAIN=.example.com
 * - COOKIE_NAME=token
 */
function cookieOptions(req) {
  const inferredSecure = isHttpsRequest(req);

  const secure =
    process.env.COOKIE_SECURE != null
      ? String(process.env.COOKIE_SECURE).toLowerCase() === "true"
      : inferredSecure;

  const sameSite =
    process.env.COOKIE_SAMESITE != null
      ? String(process.env.COOKIE_SAMESITE).toLowerCase()
      : secure
        ? "none"
        : "lax";

  const domain = process.env.COOKIE_DOMAIN ? String(process.env.COOKIE_DOMAIN) : undefined;

  return {
    httpOnly: true,
    secure,
    sameSite,
    path: "/",
    maxAge: 1000 * 60 * 60 * 24 * 7,
    ...(domain ? { domain } : {}),
  };
}

function cookieName() {
  return process.env.COOKIE_NAME ? String(process.env.COOKIE_NAME) : "token";
}

function issueSession(req, res, user) {
  const token = signJwt(
    { sub: String(user._id), email: user.email },
    process.env.JWT_SECRET,
    process.env.JWT_EXPIRES_IN || "7d"
  );

  res.cookie(cookieName(), token, cookieOptions(req));
}

function clearAuthCookies(req, res) {
  const opts = cookieOptions(req);

  const clearOpts = {
    httpOnly: true,
    secure: opts.secure,
    sameSite: opts.sameSite,
    path: opts.path,
    ...(opts.domain ? { domain: opts.domain } : {}),
  };

  res.clearCookie(cookieName(), clearOpts);

  // Optional legacy names (safe even if unused)
  res.clearCookie("token", clearOpts);
  res.clearCookie("auth_token", clearOpts);
  res.clearCookie("access_token", clearOpts);
  res.clearCookie("refresh_token", clearOpts);
}

export async function register(req, res) {
  const { email, password, username } = req.body || {};
  if (!email || !password || !username) {
    return jsonError(res, 400, "bad_request", "Email, password, and username are required.");
  }

  const normalizedEmail = String(email).toLowerCase().trim();
  const normalizedUsername = String(username).trim();
  const usernameLower = normalizedUsername.toLowerCase();

  const existing = await User.findOne({ email: normalizedEmail });
  if (existing) return jsonError(res, 409, "email_taken", "An account with this email already exists.");

  const existingUsername = await User.findOne({ usernameLower });
  if (existingUsername) return jsonError(res, 409, "username_taken", "Username is already taken.");

  const passwordHash = await bcrypt.hash(String(password), 12);

  const user = await User.create({
    email: normalizedEmail,
    username: normalizedUsername,
    usernameLower,
    passwordHash,
  });

  issueSession(req, res, user);
  return res.json({ user: user.toAuthJSON() });
}

export async function login(req, res) {
  const { email, password } = req.body || {};
  if (!email || !password) return jsonError(res, 400, "bad_request", "Email and password are required.");

  const normalizedEmail = String(email).toLowerCase().trim();

  // ✅ CRITICAL FIX:
  // If your schema sets `passwordHash: { select: false }`, this ensures it is returned.
  const user = await User.findOne({ email: normalizedEmail }).select("+passwordHash");

  if (!user) return jsonError(res, 401, "invalid_credentials", "Invalid email or password.");

  // ✅ Fail loudly if model/schema is misconfigured (prevents endless 401 confusion)
  if (!user.passwordHash) {
    return jsonError(
      res,
      500,
      "server_misconfig",
      "User record has no passwordHash. Check your User schema field name and/or select:false configuration."
    );
  }

  const ok = await bcrypt.compare(String(password), user.passwordHash);
  if (!ok) return jsonError(res, 401, "invalid_credentials", "Invalid email or password.");

  issueSession(req, res, user);
  return res.json({ user: user.toAuthJSON() });
}

export async function logout(req, res) {
  clearAuthCookies(req, res);
  return res.json({ ok: true });
}

export async function me(req, res) {
  if (!req.auth?.sub) return res.json({ user: null });

  const user = await User.findById(req.auth.sub);
  if (!user) return res.json({ user: null });

  return res.json({ user: user.toAuthJSON() });
}

export async function updateProfile(req, res) {
  const user = await User.findById(req.auth.sub);
  if (!user) return jsonError(res, 401, "unauthorized", "Not authenticated.");

  const updates = pick(req.body || {}, ["username", "bio", "avatarUrl"]);
  if (typeof updates.username === "string") updates.username = updates.username.trim();

  if (typeof updates.username === "string" && updates.username) {
    const nextLower = String(updates.username).toLowerCase();
    const conflict = await User.findOne({ usernameLower: nextLower, _id: { $ne: user._id } });
    if (conflict) return jsonError(res, 409, "username_taken", "Username is already taken.");
    updates.usernameLower = nextLower;
  }

  Object.assign(user, updates);
  await user.save();

  return res.json({ user: user.toAuthJSON() });
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const storage = multer.diskStorage({
  destination: path.join(__dirname, "..", "uploads"),
  filename: (req, file, cb) => {
    const safe = String(file.originalname || "upload").replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, `${Date.now()}_${safe}`);
  },
});

export const avatarUpload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
});

export async function uploadAvatar(req, res) {
  const user = await User.findById(req.auth.sub);
  if (!user) return jsonError(res, 401, "unauthorized", "Not authenticated.");
  if (!req.file) return jsonError(res, 400, "bad_request", "No file uploaded.");

  const url = `/uploads/${req.file.filename}`;
  user.avatarUrl = url;
  await user.save();

  return res.json({ url });
}

