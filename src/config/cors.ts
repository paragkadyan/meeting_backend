import { CorsOptions } from 'cors';
import { CORS_ORIGINS, FRONTEND_ORIGIN } from './env';

/**
 * Browser origins allowed to call the API with credentials.
 *
 * - FRONTEND_ORIGIN (the main web app) is always allowed. It's also used for
 *   links in emails, so it stays a single URL.
 * - CORS_ORIGINS adds more, comma-separated: www/staging domains, the Vite
 *   dev server, Expo web (http://localhost:8081), etc.
 *
 * Native mobile apps don't send an Origin header and aren't subject to CORS,
 * so they need no entry here.
 *
 * Deliberately not supported: "*" (can't be combined with cookies) and "null"
 * (sent by sandboxed iframes on any site as well as by file:// pages).
 */
const normalize = (origin: string) => origin.trim().replace(/\/+$/, '');

export const allowedOrigins = new Set(
  [FRONTEND_ORIGIN, ...(CORS_ORIGINS ?? '').split(',')]
    .filter((o): o is string => typeof o === 'string')
    .map(normalize)
    .filter((o) => o.length > 0 && o !== '*' && o !== 'null'),
);

/** No Origin header means a non-browser client (mobile app, server, curl). */
export const isOriginAllowed = (origin: string | undefined): boolean =>
  !origin || allowedOrigins.has(normalize(origin));

const originCheck = (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) =>
  callback(null, isOriginAllowed(origin));

export const corsOptions: CorsOptions = {
  origin: originCheck,
  credentials: true,
};

/** Same policy for Socket.IO's HTTP handshake. */
export const socketCorsOptions = {
  origin: originCheck,
  credentials: true,
};
