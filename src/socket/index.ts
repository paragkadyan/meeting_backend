import { Server } from "socket.io";
import { createAdapter } from "@socket.io/redis-adapter";
import { redis } from "../db/redis";
import { handlePresence } from "./presence";
import { handleRooms } from "./room";
import { handleMessages } from "./message";
import { handleOfflineSync } from "./offline";
import { socketAuth } from "../middleware/socket.auth";
import { socketCorsOptions } from "../config/cors";
import { prunePresence } from "./presenceJanitor";
import { handleCallEvents } from "./call";

let ioInstance: Server | null = null;

export const getIO = (): Server => {
  if (!ioInstance) {
    throw new Error('Socket.io not initialized');
  }
  return ioInstance;
};

export const initSocket = async (httpServer: import("http").Server) => {
  const io = new Server(httpServer, {
    cors: socketCorsOptions,
  });

  ioInstance = io;

  console.log("Socket.io initialized");
  const pub = redis;
  const sub = redis.duplicate();
  if (!sub.isOpen) {
    await sub.connect();
  }
  io.adapter(createAdapter(pub, sub));

  io.use(socketAuth);

  // Clear presence left behind by a previous process (crash/restart). Delayed
  // so the adapter is ready; failures are logged and harmless.
  setTimeout(() => {
    prunePresence(io).catch((error) => console.error("Presence cleanup failed:", error));
  }, 3000);

  io.on("connection", (socket) => {
    const userId = socket.data.user.id;
    console.log(`Socket connected: ${socket.id}, user: ${userId}`);
    socket.join(`user:${userId}`);
    
    handlePresence(userId, socket);
    handleRooms(socket);
    handleMessages(io, socket);
    handleOfflineSync(socket);
    handleCallEvents(socket);
  });

  process.on("SIGINT", async () => {
    await pub.quit();
    await sub.quit();
    io.close();
    process.exit(0);
  });

  return io;
};
