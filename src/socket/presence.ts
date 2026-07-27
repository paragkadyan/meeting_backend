import { redis } from "../db/redis";
import { Socket } from "socket.io";
import { getActiveConversationIds, removeActiveConversationViewer } from './activeConversation';

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
  const userSocketsKey = `user:sockets:${userId}`;

  // Snapshot active conversations before releasing this socket. The helper removes
  // only this socket from each conversation and only clears user/conversation indexes
  // when no other socket remains for the same user and conversation.
  const activeConvos = await getActiveConversationIds(userId);
  await Promise.all(
    activeConvos.map((convoId) => removeActiveConversationViewer(userId, convoId, socket.id))
  );

  const socketResults = await redis
    .multi()
    .sRem(userSocketsKey, socket.id)
    .sCard(userSocketsKey)
    .exec();

  const remainingSockets = Number(socketResults?.[1] ?? 0);
  if (remainingSockets === 0) {
    await redis
      .multi()
      .del(`user:online:${userId}`)
      .del(userSocketsKey)
      .set(`user:lastSeen:${userId}`, Date.now().toString())
      .exec();
  }
};
