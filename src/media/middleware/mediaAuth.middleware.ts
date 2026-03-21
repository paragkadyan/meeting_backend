import { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../../utils/jwt";
import { apiError } from "../../utils/apiError";

export function mediaAuthMiddleware(req: Request, _res: Response, next: NextFunction) {
  const header = req.header("authorization");
  const bearerToken = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
  const cookieToken = req.cookies?.accessToken as string | undefined;

  const token = bearerToken || cookieToken;
  if (!token) {
    throw new apiError(401, "Unauthorized: no access token");
  }

  const payload = verifyAccessToken(token);
  req.user = { id: payload.userId };
  next();
}
