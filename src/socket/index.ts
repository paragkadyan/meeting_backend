import { Server } from "socket.io";
import { createAdapter } from "@socket.io/redis-adapter";
import { redis } from "../db/redis";
import { handleDisconnect, handlePresence } from "./presence";
import { handleRooms } from "./room";
import { handleMessages } from "./message";
import { handleOfflineSync } from "./offline";
import { socketAuth } from "../middleware/socket.auth";

export const initSocket = (httpServer: import("http").Server) => {
  const io = new Server(httpServer, {
    cors: {
      origin: process.env.CLIENT_URL,
      credentials: true,
    },
  });

  console.log("Socket.io initialized");
  // const pub = redis;
  // const sub = redis.duplicate();

  // io.adapter(createAdapter(pub, sub));

  //io.use(socketAuth);

  io.on("connection", (socket) => {
    const userId = socket.data.userId;
    console.log(`Socket connected: ${socket.id}, user: ${userId}`);


    socket.on("joinConvo", async ({ convoId }) => { 
      socket.join(`room:${convoId}`); 
      console.log(`User ${userId} joined room:${convoId}`); 
    });
    
    socket.on("leaveConvo", async ({ convoId }) => { 
      socket.leave(`room:${convoId}`); 
      console.log(`User ${userId} left room:${convoId}`); 
    });

    socket.broadcast.emit("userJoined", { 
      socketId: socket.id, 
      message: `${socket.id} joined the chat` 
    });

  //   socket.on("message", (data) => {
  //   console.log("📨 Message from", socket.id, ":", data);
    
  //   const cleanText = (data.text || data).toString().trim();
  //   socket.broadcast.emit("message", cleanText);
  //   socket.broadcast.emit("message", {
  //     from: socket.id,
  //     text: data.text || data,
  //     timestamp: new Date().toISOString()
  //   });
  // });
    

    handlePresence(userId, socket);
    handleRooms(socket);
    handleMessages(io, socket);
    handleOfflineSync(socket);

    socket.on("disconnect", (reason) => {
      console.log(`Socket disconnected: ${socket.id}, reason: ${reason}`);
      handleDisconnect(userId, socket);
    });
  });

  // process.on("SIGINT", async () => {
  //   await pub.quit();
  //   await sub.quit();
  //   io.close();
  //   process.exit(0);
  // });

  return io;
};
