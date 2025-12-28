import { Socket } from 'socket.io';
import { cassandra } from '../db/cassa';
import { redis } from '../db/redis';

export const handleOfflineSync = async (socket: Socket) => {
  const userId = socket.data.user.id;

  // Sync missed messages
  socket.on('syncMessages', async ({ convoId, lastKnownMessageId }) => {
    const bucket = Math.floor(Date.now() / (24 * 60 * 60 * 1000));
    
    const messages = await cassandra.execute(
      `SELECT * FROM messages 
       WHERE convoID = ? AND bucket = ? AND messageID > ?
       ORDER BY messageID ASC`,
      [convoId, bucket, lastKnownMessageId],
      { prepare: true }
    );

    // Get unread count
    const unreadCount = await redis.get(`unread:${userId}:${convoId}`) || 0;
    
    socket.emit('syncedMessages', {
      convoId,
      messages: messages.rows,
      unreadCount: parseInt(unreadCount)
    });
  });

  // Sync conversation list
  socket.on('syncConversations', async () => {
    const convos = await redis.hgetall(`user:${userId}:conversations`);
    socket.emit('syncedConversations', { conversations: Object.entries(convos) });
  });
};

