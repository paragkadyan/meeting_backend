import { verifyAccessToken, verifyRefreshToken } from "../utils/jwt";
import { Socket } from "socket.io";

export const socketAuth = async (socket: Socket, next: (err?: Error) => void) => {
  try {
    const raw = socket.handshake.headers.cookie;
    if (!raw) return next(new Error("No cookies"));

    const cookies: Record<string, string> = {};
    raw.split(';').forEach(pair => {
      const [name, ...valueParts] = pair.trim().split('=');
      cookies[name] = valueParts.join('=');
    });

    const accessToken = cookies.accessToken;
    const refreshToken = cookies.refreshToken;

    if (!accessToken && !refreshToken) {
      return next(new Error("No tokens provided"));
    }

    // Try access token first
    if (accessToken) {
      try {
        const decoded = verifyAccessToken(accessToken);
        socket.data.user = { id: decoded.userId };
        return next();
      } catch (error) {
        // Access token expired, try refresh token
      }
    }

    // Fallback to refresh token
    if (refreshToken) {
      try {
        const decoded = verifyRefreshToken(refreshToken);
        socket.data.user = { id: decoded.userId };
        return next();
      } catch (error) {
        return next(new Error("Invalid or expired tokens"));
      }
    }

    next(new Error("Unauthorized"));
  } catch (error) {
    next(new Error("Authentication failed"));
  }
};
