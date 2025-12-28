import { Socket } from "socket.io";
import { verifyAccessToken } from "../utils/jwt";

export const socketAuth = (socket: Socket, next: (err?: Error) => void) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error("Unauthorized: No token provided"));
    }
    const decoded = verifyAccessToken(token);
    socket.data.userId = decoded.userId;
    return next();
  } catch (err) {
    return next(new Error("Unauthorized: Invalid token"));
  }
};

