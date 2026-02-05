// FILE: server/middleware/auth.js  (FULL REPLACEMENT)
// =======================================================
import { verifyJwt } from "../utils/jwt.js";
import { jsonError } from "../utils/http.js";

function cookieName() {
  return process.env.COOKIE_NAME ? String(process.env.COOKIE_NAME) : "token";
}

function readBearerToken(req) {
  const auth = req.headers.authorization;
  if (!auth || typeof auth !== "string") return undefined;
  if (!auth.startsWith("Bearer ")) return undefined;
  return auth.slice(7).trim() || undefined;
}

function readCookieToken(req) {
  const primary = cookieName();
  return (
    req.cookies?.[primary] ||
    req.cookies?.token || // legacy
    req.cookies?.auth_token || // legacy
    req.cookies?.access_token || // legacy
    req.cookies?.refresh_token // legacy (not ideal but harmless)
  );
}

/**
 * Factory so you can do:
 *   requireAuth()           -> strict 401 on missing/invalid
 *   requireAuth.optional()  -> attaches req.auth if valid, otherwise continues with req.auth undefined
 */
export function requireAuth(req, res, next) {
  const token = readCookieToken(req) || readBearerToken(req);

  if (!token) return jsonError(res, 401, "unauthorized", "Not authenticated.");

  try {
    req.auth = verifyJwt(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return jsonError(res, 401, "unauthorized", "Invalid or expired session.");
  }
}

requireAuth.optional = (req, res, next) => {
  const token = readCookieToken(req) || readBearerToken(req);

  if (!token) {
    req.auth = undefined;
    return next();
  }

  try {
    req.auth = verifyJwt(token, process.env.JWT_SECRET);
  } catch {
    req.auth = undefined;
  }

  return next();
};
