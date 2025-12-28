import { redis } from "../db/redis";

export const handlePresence = async (userId: string, socket: any) => {
  await redis.sAdd(`user:sockets:${userId}`, socket.id);
  await redis.set(`user:online:${userId}`, "1");
};

export const handleDisconnect = (userId: string, socket: any) => {
  socket.on("disconnect", async () => {
    await redis.sRem(`user:sockets:${userId}`, socket.id);

    const count = await redis.sCard(`user:sockets:${userId}`);
    if (count === 0) {
      await redis.del(`user:online:${userId}`);
    }
  });
};
