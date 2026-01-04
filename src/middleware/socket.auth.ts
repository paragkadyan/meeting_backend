import cookie from "cookie";
import { verifyAccessToken } from "../utils/jwt";
import { Socket } from "socket.io";

export const socketAuth = (socket: Socket, next: (err?: Error) => void) => {
  try {
    const raw = socket.handshake.headers.cookie;
    if (!raw) return next(new Error("No cookies"));

    const cookies = cookie.parse(raw);
    const token = cookies.accessToken;
    if (!token) return next(new Error("No access token"));

    const decoded = verifyAccessToken(token);

    socket.data.user = { id: decoded.userId };
    next();
  } catch {
    next(new Error("Unauthorized"));
  }
};
