// FILE: server/routes/auth.route.js  (FULL REPLACEMENT)
// =======================================================
import express from "express";
import { requireAuth } from "../middleware/auth.js";
import {
  register,
  login,
  logout,
  me,
  updateProfile,
  avatarUpload,
  uploadAvatar,
} from "../controllers/auth.controller.js";

const router = express.Router();

/**
 * Optional auth:
 * - If no token cookie -> { user: null }
 * - If token exists but is invalid/expired -> { user: null } (prevents frontend breakage)
 *
 * NOTE: If requireAuth writes the 401 response directly (instead of next(err)),
 * you must implement optional mode inside requireAuth to truly guarantee { user: null }.
 */
const optionalAuth = (req, res, next) => {
  const token = req.cookies?.token || req.cookies?.auth_token;
  if (!token) return res.json({ user: null });

  // If requireAuth errors via next(err), we can downgrade to { user: null }.
  // If requireAuth sends a response directly, we can't intercept from here.
  try {
    return requireAuth(req, res, (err) => {
      if (err) return res.json({ user: null });
      return next();
    });
  } catch {
    return res.json({ user: null });
  }
};

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);

router.get("/me", requireAuth.optional, me);


router.patch("/profile", requireAuth, updateProfile);
router.post("/avatar", requireAuth, avatarUpload.single("avatar"), uploadAvatar);

export default router;
