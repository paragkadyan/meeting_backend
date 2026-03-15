import { Server } from "socket.io";
import { createAdapter } from "@socket.io/redis-adapter";
import { redis } from "../db/redis";
import { handlePresence } from "./presence";
import { handleRooms } from "./room";
import { handleMessages } from "./message";
import { handleOfflineSync } from "./offline";
import { socketAuth } from "../middleware/socket.auth";

export const initSocket = async (httpServer: import("http").Server) => {
  const io = new Server(httpServer, {
    cors: {
      origin: process.env.FRONTEND_ORIGIN,
      credentials: true,
    },
  });

  console.log("Socket.io initialized");
  const pub = redis;
  const sub = redis.duplicate();
  if (!sub.isOpen) {
    await sub.connect();
  }
  io.adapter(createAdapter(pub, sub));

  io.use(socketAuth);

  io.on("connection", (socket) => {
    const userId = socket.data.user.id;
    console.log(`Socket connected: ${socket.id}, user: ${userId}`);
    socket.join(`user:${userId}`);
    
    handlePresence(userId, socket);
    handleRooms(socket);
    handleMessages(io, socket);
    handleOfflineSync(socket);
  });

  process.on("SIGINT", async () => {
    await pub.quit();
    await sub.quit();
    io.close();
    process.exit(0);
  });

  return io;
};
