import { Socket, Server } from 'socket.io';
import { types } from 'cassandra-driver';
import { cassandra } from '../db/cassa';
import { redis } from '../db/redis';
import { prisma } from '../db/post';

export const handleMessages = async (io: Server, socket: Socket) => {
  const userId = socket.data.user.id;

  socket.on('sendMessage', async ({ convoId, content, messageType = 'text' }) => {
    try {
      const messageId = types.TimeUuid.now();
      const bucket = Math.floor(Date.now() / (24 * 60 * 60 * 1000));
      await cassandra.execute(
        `INSERT INTO messages (
          convoID, bucket, messageID, senderID, content, messageType, attachments, replyToMessageID
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [convoId, bucket, messageId, userId, content, messageType, [], null],
        { prepare: true }
      );


      await prisma.conversationByUser.updateMany({
        where: { convoId },
        data: {
          lastMessage: content,
          lastMessageSenderId: userId,
          lastMessageAt: new Date(),
        },
      });

      await prisma.conversationByUser.updateMany({
        where: { convoId, userId: { not: userId } },
        data: {
          unreadCount: { increment: 1 },
        },
      });

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

      const participants = await redis.sMembers(`convo:${convoId}:participants`);
      if (!participants || !Array.isArray(participants)) {
        return;
      }

      for (const participantId of participants) {
        if (participantId === userId) continue;

        // 1️⃣ UNREAD COUNTER (HASH)
        const unreadKey = `unread:${participantId}:${convoId}`;
        const unreadType = await redis.type(unreadKey);
        if (unreadType !== 'none' && unreadType !== 'hash') {
          await redis.del(unreadKey);
        }
        await redis.hSetNX(unreadKey, 'count', '0');
        const unreadCount = await redis.hIncrBy(unreadKey, 'count', 1);

        // 3️⃣ CONVERSATION META (HASH)
        const metaKey = `user:${participantId}:convo:meta`;
        const metaType = await redis.type(metaKey);
        if (metaType !== 'none' && metaType !== 'hash') {
          await redis.del(metaKey);
        }
        await redis.hSet(
          metaKey,
          convoId,
          JSON.stringify({
            lastMessage: content,
            lastMessageAt: Date.now(),
            lastMessageSender: userId,
          })
        );

        socket.to(`user:${participantId}`).emit('unreadUpdated', {
          convoId,
          unreadCount,
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
