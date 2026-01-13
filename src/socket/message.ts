import { Socket, Server } from 'socket.io';
import { types } from 'cassandra-driver';
import { cassandra } from '../db/cassa';
import { redis } from '../db/redis';
import { prisma } from '../db/post';

export const handleMessages = async (io: Server, socket: Socket) => {
  const userId = socket.data.user.id;

  socket.on('sendMessage', async ({ convoId, content, messageType = 'text', attachments = [], replyToMessageID = null }) => {
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
        bucket,
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

        const unreadKey = `unread:${participantId}:${convoId}`;
        await redis.hSetNX(unreadKey, 'count', '0');
        const unreadCount = await redis.hIncrBy(unreadKey, 'count', 1);

        const metaKey = `user:${participantId}:convo:meta`;
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
      //io.to(`user:${userId}`).emit('newMessage', message);
      socket.emit('messageSent');

    } catch (error) {
      socket.emit('error', { message: 'Failed to send message' });
      console.error('Message error:', error);
    }
  });

  socket.on('messageReaction', async ({ convoId, messageId, reaction }) => {
    try {
      io.to(`room:${convoId}`).emit('messageReaction', {
        convoId,
        messageId,
        userId,
        reaction,
      });

       const existing = await cassandra.execute(
        `
        SELECT reaction FROM message_reactions
        WHERE convoID = ?
          AND messageID = ?
          AND userID = ?
        `,
        [convoId, messageId, userId],
        { prepare: true }
      );
      if (existing.rowLength === 0) {
        await cassandra.execute(
          `
          INSERT INTO message_reactions
          (convoID, messageID, userID, reaction, reactedAt)
          VALUES (?, ?, ?, ?, toTimestamp(now()))
          `,
          [convoId, messageId, userId, reaction],
          { prepare: true }
        );
      } else {
        const oldReaction = existing.first().reaction;

        if (oldReaction === reaction) {
          await cassandra.execute(
            `
            DELETE FROM message_reactions
            WHERE convoID = ?
              AND messageID = ?
              AND userID = ?
            `,
            [convoId, messageId, userId],
            { prepare: true }
          );
        } else {
          await cassandra.execute(
            `
            UPDATE message_reactions
            SET reaction = ?, reactedAt = toTimestamp(now())
            WHERE convoID = ?
              AND messageID = ?
              AND userID = ?
            `,
            [reaction, convoId, messageId, userId],
            { prepare: true }
          );
        }
      }
    } catch (error) {
        console.error('Reaction error:', error);
        socket.emit('error', { message: 'Failed to react to message' });
      }
  });

  socket.on('markRead', async ({ convoId, lastMessageId }) => {
    try {
      await redis.del(`unread:${userId}:${convoId}`);
      await prisma.conversationByUser.update({ where: { userId_convoId: { userId, convoId } }, data: { unreadCount: 0, lastOpenedAt: new Date() }, });
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

  socket.on('typing', ({ convoId, isTyping }) => {
    socket.to(`room:${convoId}`).emit('typing', {
      userId,
      convoId,
      isTyping,
    });
  });

  socket.on('stopTyping', ({ convoId }) => {
    socket.to(`room:${convoId}`).emit('typing', {
      userId,
      convoId,
      isTyping: false,
    });
  });

  socket.on('editMessage', async ({ convoId, messageId, newContent, bucket }) => {
    try {
      await cassandra.execute(
        `
        UPDATE messages
        SET content = ?, isEdited = true, editedAt = toTimestamp(now())
        WHERE convoID = ? AND bucket = ? AND messageID = ?
        `,
        [newContent,convoId, bucket, messageId],
        { prepare: true }
      );
      io.to(`room:${convoId}`).emit('messageEdited', {
        convoId,
        messageId,
        newContent,
      });
    } catch (error) {
      console.error('Edit message error:', error);
      socket.emit('error', { message: 'Failed to edit message' });
    }
  });

  socket.on('deleteMessage', async ({ convoId, messageId, bucket }) => {
    try {
      await cassandra.execute(
        `
        UPDATE messages
        SET isDeleted = true, deletedAt = toTimestamp(now())
        WHERE convoID = ? AND bucket = ? AND messageID = ?
        `,
        [convoId, bucket, messageId],
        { prepare: true }
      );
      io.to(`room:${convoId}`).emit('messageDeleted', {
        convoId,
        messageId,
      });
    } catch (error) {
      console.error('Delete message error:', error);
      socket.emit('error', { message: 'Failed to delete message' });
    }
  });


};
