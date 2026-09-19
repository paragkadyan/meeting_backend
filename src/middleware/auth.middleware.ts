import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, verifyRefreshToken, signAccessToken, signRefreshToken, getTokenMaxAge } from '../utils/jwt';
import { rotateRefreshToken } from '../services/token.service';
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
    } catch (error) {
      // Access token expired or invalid, proceed to refresh token rotation
    }
  }

  if (!refresh) throw new apiError(401, 'unauthorized');

  try {
    const payload = verifyRefreshToken(refresh);
    const newJti = uuidv4();
    const newRefresh = signRefreshToken({ userId: payload.userId, jti: newJti });
    const newAccess = signAccessToken({ userId: payload.userId });
    const rotated = await rotateRefreshToken(payload.userId, payload.jti, newJti, newRefresh);
    if (!rotated) throw new apiError(401, "refresh revoked");

    res.cookie("accessToken", newAccess, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: "none",
      maxAge: getTokenMaxAge(newAccess),
      // domain: COOKIE_DOMAIN,
      path: "/",
    });
    res.cookie("refreshToken", newRefresh, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: "none",
      maxAge: getTokenMaxAge(newRefresh),
      // domain: COOKIE_DOMAIN,
      path: "/",
    });

    req.user = { id: payload.userId };
    return next();
  } catch (error) {
    throw new apiError(401, "Invalid or expired refresh token");
  }
});
