import { Socket, Server } from 'socket.io';
import { types } from 'cassandra-driver';
import { cassandra } from '../db/cassa';
import { redis } from '../db/redis';

export const handleMessages = async (io: Server, socket: Socket) => {
  const userId = socket.data.user.id;

  socket.on('sendMessage', async ({ convoId, content, messageType = 'text' }) => {
    try {
      const messageId = types.TimeUuid.now();
      const bucket = Math.floor(Date.now() / (24 * 60 * 60 * 1000));
      await cassandra.execute(
        `INSERT INTO messages (convoID, bucket, messageID, senderID, content, messageType, attachments, replyToMessageID)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING messageID`,
        [convoId, bucket, messageId, userId, content, messageType, [], null],
        { prepare: true }
      );

      await cassandra.execute(
        `UPDATE conversations SET lastMessageID = ?, WHERE convoID = ? AND userID = ?`,
        [messageId, convoId, userId],
        { prepare: true }
      );

      await cassandra.execute(
        `UPDATE conversations_by_user SET lastMessage = ?, lastMessageSenderID = ?, WHERE convoID = ? AND userID = ?`,
        [content, userId, convoId, userId],
        { prepare: true }
      );

      const message = {
        convoId,
        messageId,
        senderId: userId,
        content,
        messageType,
        attachments: [],
        replyToMessageID: null,
        createdAt: new Date().toISOString(),
      };

      const participants = await redis.smembers(`convo:${convoId}:participants`);
      if (!participants || !Array.isArray(participants)) {
        return;
      }
      for (const participantId of participants) {
        if (participantId === userId) continue;
        const unreadCount = await redis.hincrby(`unread:${participantId}:${convoId}`, 'count', 1);
        const lastMessage = await redis.hset(`user:${participantId}:conversations`, convoId, 
          JSON.stringify({ lastMessage: content, lastMessageAt: Date.now(), lastMessageSender: userId }));
          socket.to(`user:${participantId}`).emit('unreadUpdated', {
            convoId,
            unreadCount
          });
      }

      socket.to(`room:${convoId}`).emit('newMessage', message);
      socket.emit('messageSent');  

    } catch (error) {
      socket.emit('error', { message: 'Failed to send message' });
      console.error('Message error:', error);
    }
  });


  socket.on('markRead', async ({ convoId, lastMessageId }) => {
    try {
      await redis.del(`unread:${userId}:${convoId}`);
      socket.to(`room:${convoId}`).emit('messagesRead', { 
      userId, 
      convoId, 
      lastMessageId 
    });
    } catch (error) {
      console.error('Mark read error:', error);
      socket.emit('error', { message: 'Failed to mark messages as read' });
    }
  });
};
