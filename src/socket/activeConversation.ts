import { redis } from '../db/redis';

const activeConvosKey = (userId: string) => `user:${userId}:activeConvos`;
const activeViewersKey = (convoId: string) => `convo:${convoId}:activeViewers`;
const activeViewerSocketsKey = (convoId: string, userId: string) => `convo:${convoId}:activeViewerSockets:${userId}`;

const getCardinalityFromExecResult = (result: unknown): number => {
  if (typeof result === 'number') {
    return result;
  }

  if (Array.isArray(result) && typeof result[1] === 'number') {
    return result[1];
  }

  return 0;
};

export const addActiveConversationViewer = async (userId: string, convoId: string, socketId: string) => {
  // Keep all three indexes in sync in one round trip. The socket-level set preserves
  // correctness for multiple tabs/devices because the user remains an active viewer
  // while at least one socket is viewing this conversation.
  await redis
    .multi()
    .sAdd(activeViewerSocketsKey(convoId, userId), socketId)
    .sAdd(activeViewersKey(convoId), userId)
    .sAdd(activeConvosKey(userId), convoId)
    .exec();
};

export const removeActiveConversationViewer = async (userId: string, convoId: string, socketId: string) => {
  const socketKey = activeViewerSocketsKey(convoId, userId);
  const userActiveConvosKey = activeConvosKey(userId);

  // Remove only the disconnecting/leaving socket first, then inspect the remaining
  // socket count before removing the user-level active viewer indexes.
  const socketResults = await redis
    .multi()
    .sRem(socketKey, socketId)
    .sCard(socketKey)
    .exec();

  const activeSocketCount = getCardinalityFromExecResult(socketResults?.[1]);
  if (activeSocketCount > 0) {
    return;
  }

  // No sockets for this user remain in this conversation, so remove the derived
  // conversation/user indexes together and check whether the user's active set is empty.
  const cleanupResults = await redis
    .multi()
    .del(socketKey)
    .sRem(activeViewersKey(convoId), userId)
    .sRem(userActiveConvosKey, convoId)
    .sCard(userActiveConvosKey)
    .exec();

  const activeConvoCount = getCardinalityFromExecResult(cleanupResults?.[3]);
  if (activeConvoCount === 0) {
    // Redis usually removes empty sets automatically; DEL is kept as a final cleanup
    // guard and only runs after verifying there are no active conversations left.
    await redis.del(userActiveConvosKey);
  }
};

export const getActiveConversationIds = async (userId: string) => redis.sMembers(activeConvosKey(userId));
