import { Socket, Server } from 'socket.io';
import { cassandra } from '../db/cassa';
import { redis } from '../db/redis';

export const handleMessages = async (io: Server, socket: Socket) => {
  const userId = socket.data.user.id;

  socket.on('sendMessage', async ({ convoId, content, messageType = 'text' }) => {
    try {
      // 1. Save to Cassandra
      const bucket = Math.floor(Date.now() / (24 * 60 * 60 * 1000));
      const message = await cassandra.execute(
        `INSERT INTO messages (convoID, bucket, messageID, senderID, content, messageType, createdAt)
         VALUES (?, ?, now(), ?, ?, ?, now()) RETURNING *`,
        [convoId, bucket, userId, content, messageType],
        { prepare: true }
      );

      const messageId = message.rows[0].messageid;

      // 2. Update conversation metadata (for all participants)
      const participants = await redis.smembers(`convo:${convoId}:participants`);
      for (const participantId of participants) {
        if (participantId !== userId) {
          // Increment unread count
          await redis.incr(`unread:${participantId}:${convoId}`);
        }
        
        // Update last message
        await redis.hset(`user:${participantId}:conversations`, convoId, {
          lastMessage: content,
          lastMessageAt: Date.now(),
          lastMessageSender: userId
        });
      }

      // 3. Broadcast to room (except sender)
      socket.to(`room:${convoId}`).emit('message', {
        messageId: messageId.toString(),
        convoId,
        senderId: userId,
        content,
        messageType,
        createdAt: new Date().toISOString()
      });

    } catch (error) {
      socket.emit('error', { message: 'Failed to send message' });
      console.error('Message error:', error);
    }
  });

  // Mark messages as read
  socket.on('markRead', async ({ convoId, lastMessageId }) => {
    await redis.del(`unread:${userId}:${convoId}`);
    socket.to(`room:${convoId}`).emit('messagesRead', { 
      userId, 
      convoId, 
      lastMessageId 
    });
  });
};
