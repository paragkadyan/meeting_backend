import { CookieOptions, Request, Response } from 'express';
import { COOKIE_SECURE } from '../config/env';
import { getTokenMaxAge } from './jwt';

/**
 * Two client types share the auth endpoints:
 *  - Web: tokens live in httpOnly cookies (unchanged behaviour).
 *  - Mobile (sends `X-Client-Platform: mobile`): native apps can't use the
 *    cookie jar reliably, so tokens travel in the response body and come back
 *    as `Authorization: Bearer` (access) or in the request body (refresh).
 */
const readHeader = (req: Request, name: string): string | undefined => {
  const value = req.headers?.[name];
  return Array.isArray(value) ? value[0] : value;
};

export const isMobileClient = (req: Request): boolean =>
  readHeader(req, 'x-client-platform')?.trim().toLowerCase() === 'mobile';

export const getBearerToken = (req: Request): string | undefined => {
  const header = readHeader(req, 'authorization');
  if (!header?.startsWith('Bearer ')) return undefined;
  return header.slice(7).trim() || undefined;
};

const baseCookieOptions: CookieOptions = {
  httpOnly: true,
  secure: COOKIE_SECURE,
  sameSite: 'none',
  path: '/',
};

export function setSessionCookies(res: Response, accessToken: string, refreshToken: string) {
  res.cookie('accessToken', accessToken, { ...baseCookieOptions, maxAge: getTokenMaxAge(accessToken) });
  res.cookie('refreshToken', refreshToken, { ...baseCookieOptions, maxAge: getTokenMaxAge(refreshToken) });
}

/** Clearing must use the same attributes as setting, or browsers ignore it. */
export function clearSessionCookies(res: Response) {
  res.clearCookie('accessToken', baseCookieOptions);
  res.clearCookie('refreshToken', baseCookieOptions);
}

/**
 * Hands a newly issued session to the client in the form it can use.
 * Returns extra fields to spread into the response `data`: the refresh token
 * for mobile clients, nothing for web (it's in the cookie instead).
 */
export function deliverSession(
  req: Request,
  res: Response,
  tokens: { accessToken: string; refreshToken: string },
): { refreshToken?: string } {
  if (isMobileClient(req)) {
    return { refreshToken: tokens.refreshToken };
  }
  setSessionCookies(res, tokens.accessToken, tokens.refreshToken);
  return {};
}

/** Refresh token from the body for mobile clients, from the cookie for web. */
export function getRefreshTokenFromRequest(req: Request): string | undefined {
  const token = isMobileClient(req) ? req.body?.refreshToken : req.cookies?.refreshToken;
  return typeof token === 'string' && token ? token : undefined;
}
