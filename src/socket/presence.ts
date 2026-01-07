import { redis } from "../db/redis";
import { Socket } from "socket.io";

const ONLINE_TTL = 60;

export const handlePresence = async (userId: string, socket: Socket) => {
  await redis.sAdd(`user:sockets:${userId}`, socket.id);

  await redis.set(`user:online:${userId}`, "1", { EX: ONLINE_TTL });

  socket.on("heartbeat", async () => {
    await redis.set(`user:online:${userId}`, "1", { EX: ONLINE_TTL });
  });

  socket.on("disconnect", async () => {
    await handleDisconnect(userId, socket);
  });
};

const handleDisconnect = async (userId: string, socket: Socket) => {
  await redis.sRem(`user:sockets:${userId}`, socket.id);

  const remainingSockets = await redis.sCard(`user:sockets:${userId}`);
  if (remainingSockets === 0) {
    await redis.del(`user:online:${userId}`);
    await redis.del(`user:sockets:${userId}`);
    await redis.set(`user:lastSeen:${userId}`, Date.now().toString());
  }
};
