import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, verifyRefreshToken, signAccessToken, signRefreshToken } from '../utils/jwt';
import { isRefreshTokenActive, revokeRefreshToken, registerRefreshToken, revokeAllOnCompromise } from '../services/token.service';
import { COOKIE_SECURE, COOKIE_DOMAIN } from '../config/env';
import { v4 as uuidv4 } from 'uuid';
import { asyncHandler } from '../utils/asyncHandler';
import { apiError } from '../utils/apiError';


export const authMiddleware = asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
  const access = req.cookies.accessToken;
  const refresh = req.cookies.refreshToken;

  if (!access && !refresh) {
    throw new apiError(401, 'unauthorized');
  }
  if (access) {
    try {
      const payload = verifyAccessToken(access);
      req.user = { id: payload.userId };
      return next();
    } catch {

    }
  }

  if (!refresh) throw new apiError(401, 'unauthorized');

  try {
    const payload = verifyRefreshToken(refresh);
    const active = await isRefreshTokenActive(payload.userId, payload.jti);
    if (!active) {
      res.clearCookie("accessToken", {
        httpOnly: true,
        secure: COOKIE_SECURE,
        sameSite: "lax",
        domain: COOKIE_DOMAIN,
        path: "/",
      });
      res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: COOKIE_SECURE,
        sameSite: "lax",
        domain: COOKIE_DOMAIN,
        path: "/",
      });
      throw new apiError(401, "refresh revoked");
    }

    await revokeRefreshToken(payload.userId, payload.jti);
    const newJti = uuidv4();
    const newRefresh = signRefreshToken({ userId: payload.userId, jti: newJti });
    await registerRefreshToken(payload.userId, newJti);
    const newAccess = signAccessToken({ userId: payload.userId });

    res.cookie("accessToken", newAccess, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: "none",
      maxAge: 15 * 60 * 1000,
      domain: COOKIE_DOMAIN,
      path: "/",
    });
    res.cookie("refreshToken", newRefresh, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      domain: COOKIE_DOMAIN,
      path: "/",
    });

    req.user = { id: payload.userId };
    return next();
  } catch {
    throw new apiError(401, "Invalid or expired refresh token");
  }
});