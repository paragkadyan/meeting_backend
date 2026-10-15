import { Socket, Server } from 'socket.io';
import { types } from 'cassandra-driver';
import { cassandra } from '../db/cassa';
import { redis } from '../db/redis';
import { prisma } from '../db/post';
import { createAndDeliverMessage } from '../services/message.service';
import { getParticipantIds, hasConversationAccess, isActiveParticipant } from '../utils/conversationAccess';

// Matches the web client's edit window (MessageBubble isWithinEditWindow),
// plus a minute of grace for clock skew and slow submits.
const EDIT_WINDOW_MS = 16 * 60 * 1000;

/** Loads the fields needed to authorize an edit/delete. Null if not found. */
const getMessageForAction = async (convoId: string, bucket: number, messageId: string) => {
  const result = await cassandra.execute(
    // messageID is selected for its embedded timestamp (edit window check).
    `SELECT messageID, senderID, messageType, isDeleted FROM messages WHERE convoID = ? AND bucket = ? AND messageID = ?`,
    [convoId, bucket, messageId],
    { prepare: true }
  );
  return result.first() ?? null;
};

export const handleMessages = async (io: Server, socket: Socket) => {
  const userId = socket.data.user.id;

  socket.on('sendMessage', async ({ convoId, content, messageType = 'text', attachments = [], replyToMessageID = null, replyToMessageContent = null, replyToMessageType = null, replyToMessageSenderID = null, systemType = null, actorId: _clientActorId = null, targetUserId = null }) => {
    try {
      const normalizedContent = typeof content === 'string' ? content : '';
      const normalizedAttachments = Array.isArray(attachments)
        ? attachments
            .map((attachment) => String(attachment ?? '').trim())
            .filter((attachment) => attachment.length > 0)
        : [];

      if (!normalizedContent.trim() && normalizedAttachments.length === 0 && messageType !== 'system') {
        socket.emit('error', { message: 'Message content or attachments are required' });
        return;
      }

      // Call history entries are written by the server when a call ends (call.service).
      if (messageType === 'call') {
        socket.emit('error', { message: 'Invalid message type' });
        return;
      }

      if (!(await isActiveParticipant(convoId, userId))) {
        socket.emit('error', { message: 'You are not a member of this conversation' });
        return;
      }

      // System notices ("X left", "X added Y") are posted by clients. The actor is
      // always the sender, and only group admins may announce adds/removals.
      const isSystem = messageType === 'system';
      const actorId = isSystem ? userId : null;
      if (isSystem && (systemType === 'user_added' || systemType === 'user_kicked')) {
        const role = await prisma.conversationParticipant.findUnique({
          where: { convoId_userId: { convoId, userId } },
          select: { role: true },
        });
        if (role?.role !== 'admin') {
          socket.emit('error', { message: 'Only group admins can post that notice' });
          return;
        }
      }

      const participants = await getParticipantIds(convoId);

      if (participants.length === 2) {
        const otherUserId = participants.find((id: string) => id !== userId);

        if (otherUserId) {
          const [iBlocked, theyBlocked] = await Promise.all([
            redis.sIsMember(`blocked:${userId}`, otherUserId),
            redis.sIsMember(`blocked:${otherUserId}`, userId),
          ]);

          if (iBlocked || theyBlocked) {
            socket.emit("error", {
              message: "Cannot send message. User is blocked."
            });
            return;
          }
        }
      }
      const uniqueParticipants = Array.from(new Set(participants.map((p) => String(p))));
      const others = uniqueParticipants.filter((id) => id !== userId);
      await createAndDeliverMessage(
        io,
        {
          convoId,
          senderId: userId,
          content: normalizedContent,
          messageType,
          attachments: normalizedAttachments,
          replyToMessageID,
          replyToMessageContent,
          replyToMessageType,
          replyToMessageSenderID,
          systemType,
          actorId,
          targetUserId,
        },
        {
          participantIds: uniqueParticipants,
          unreadUserIds: others,
          liveUnreadUserIds: uniqueParticipants,
          pushUserIds: others,
          excludeSocketId: socket.id,
        }
      );

      socket.emit('messageSent');

    } catch (error) {
      socket.emit('error', { message: 'Failed to send message' });
      console.error('Message error:', error);
    }
  });

  socket.on('messageReaction', async ({ convoId, messageId, reaction }) => {
    try {
      if (!(await isActiveParticipant(convoId, userId))) {
        socket.emit('error', { message: 'You are not a member of this conversation' });
        return;
      }

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
      // Ex-members may still open old group history, so this needs read access only.
      if (!(await hasConversationAccess(convoId, userId))) return;

      await redis.del(`unread:${userId}:${convoId}`);
      if (lastMessageId) {
        await redis.set(`conv:${convoId}:user:${userId}:lastRead`, String(lastMessageId));
      }
      await prisma.conversationByUser.update({ where: { userId_convoId: { userId, convoId } }, data: { unreadCount: 0, lastOpenedAt: new Date() }, });
      socket.to(`room:${convoId}`).emit('messagesRead', {
        userId,
        convoId,
        lastMessageId
      });
      const insertQuery = `
        INSERT INTO message_reads (convoID, messageID, userID, readAt)
        VALUES (?, ?, ?, ?)
        IF NOT EXISTS;
      `;

      await cassandra.execute(
        insertQuery,
        [convoId, lastMessageId, userId, new Date()],
        { prepare: true }
      );
    } catch (error) {
      console.error('Mark read error:', error);
      socket.emit('error', { message: 'Failed to mark messages as read' });
    }
  });

  // Typing fires on every keystroke, so instead of a DB lookup, only relay
  // from sockets that joined the room (joinRoom verifies membership).
  socket.on('typing', ({ convoId, isTyping }) => {
    if (!socket.rooms.has(`room:${convoId}`)) return;
    socket.to(`room:${convoId}`).emit('typing', {
      userId,
      convoId,
      isTyping,
    });
  });

  socket.on('stopTyping', ({ convoId }) => {
    if (!socket.rooms.has(`room:${convoId}`)) return;
    socket.to(`room:${convoId}`).emit('typing', {
      userId,
      convoId,
      isTyping: false,
    });
  });

  socket.on('editMessage', async ({ convoId, messageId, newContent, bucket }) => {
    try {
      if (typeof newContent !== 'string' || !newContent.trim()) {
        socket.emit('error', { message: 'Message content is required' });
        return;
      }
      if (!(await isActiveParticipant(convoId, userId))) {
        socket.emit('error', { message: 'You are not a member of this conversation' });
        return;
      }

      // Without this check anyone could rewrite anyone's message. It also stops
      // a wrong bucket from upserting a ghost row (Cassandra UPDATE inserts).
      const target = await getMessageForAction(convoId, bucket, messageId);
      const sentAt = target?.messageid?.getDate?.() as Date | undefined;
      if (
        !target ||
        target.isdeleted ||
        String(target.senderid) !== userId ||
        target.messagetype !== 'text' ||
        !sentAt ||
        Date.now() - sentAt.getTime() > EDIT_WINDOW_MS
      ) {
        socket.emit('error', { message: 'You can only edit your own text messages within 15 minutes' });
        return;
      }

      await cassandra.execute(
        `
        UPDATE messages
        SET content = ?, isEdited = true, editedAt = toTimestamp(now())
        WHERE convoID = ? AND bucket = ? AND messageID = ?
        `,
        [newContent, convoId, bucket, messageId],
        { prepare: true }
      );

      const isLast = await prisma.conversationByUser.count({
        where: {
          convoId,
          lastMessageId: messageId
        }
      });

      if (isLast > 0) {
        await prisma.conversationByUser.updateMany({
          where: { convoId },
          data: {
            lastMessage: newContent
          }
        });
      }

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
      if (!(await isActiveParticipant(convoId, userId))) {
        socket.emit('error', { message: 'You are not a member of this conversation' });
        return;
      }

      const target = await getMessageForAction(convoId, bucket, messageId);
      if (!target || target.isdeleted || String(target.senderid) !== userId) {
        socket.emit('error', { message: 'You can only delete your own messages' });
        return;
      }

      await cassandra.execute(
        `
        UPDATE messages
        SET isDeleted = true, deletedAt = toTimestamp(now())
        WHERE convoID = ? AND bucket = ? AND messageID = ?
        `,
        [convoId, bucket, messageId],
        { prepare: true }
      );

      const isLast = await prisma.conversationByUser.findFirst({
        where: {
          convoId,
          lastMessageId: messageId
        }
      });

      if (isLast) {
        const result = await cassandra.execute(
          `
          SELECT messageID, content, senderID, isDeleted
          FROM messages
          WHERE convoID = ? AND bucket = ?
          ORDER BY messageID DESC
          LIMIT 20
          `,
          [convoId, bucket],
          { prepare: true }
        );

        const prevMessage = result.rows.find(
          (row) => row.messageid !== messageId && !row.isdeleted
        );

        await prisma.conversationByUser.updateMany({
          where: { convoId },
          data: {
            lastMessage: prevMessage?.content || null,
            lastMessageSenderId: prevMessage?.senderid || null,
            lastMessageAt: prevMessage
              ? new Date(prevMessage.messageid.getDate?.() || Date.now())
              : null,
            lastMessageId: prevMessage?.messageid || null
          }
        });
      }
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
