import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, verifyRefreshToken, signAccessToken, signRefreshToken } from '../utils/jwt';
import { rotateRefreshToken } from '../services/token.service';
import { v4 as uuidv4 } from 'uuid';
import { asyncHandler } from '../utils/asyncHandler';
import { apiError } from '../utils/apiError';
import { getBearerToken, isMobileClient, setSessionCookies } from '../utils/session';


export const authMiddleware = asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
  // Mobile clients authenticate with a Bearer access token only. On expiry
  // they get a 401 and call /auth/refresh themselves; there is no implicit
  // rotation here, which would invalidate the refresh token the app stores.
  if (isMobileClient(req)) {
    const bearer = getBearerToken(req);
    if (!bearer) throw new apiError(401, 'unauthorized');
    const payload = verifyAccessToken(bearer);
    req.user = { id: payload.userId };
    return next();
  }

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

    setSessionCookies(res, newAccess, newRefresh);

    req.user = { id: payload.userId };
    return next();
  } catch (error) {
    throw new apiError(401, "Invalid or expired refresh token");
  }
});
