import { Server } from 'socket.io';
import { types } from 'cassandra-driver';
import { cassandra } from '../db/cassa';
import { redis } from '../db/redis';
import { prisma } from '../db/post';
import { logger } from '../logger/logger';
import { pushNotificationService } from './pushNotification.service';

export interface NewMessage {
  convoId: string;
  senderId: string;
  content: string;
  messageType: string;
  attachments?: string[];
  replyToMessageID?: string | null;
  replyToMessageContent?: string | null;
  replyToMessageType?: string | null;
  replyToMessageSenderID?: string | null;
  systemType?: string | null;
  actorId?: string | null;
  targetUserId?: string | null;
}

export interface DeliveryOptions {
  /** Everyone in the conversation; each gets the `newMessage` event. */
  participantIds: string[];
  /** Whose stored unread count goes up (Postgres conversation state). */
  unreadUserIds: string[];
  /** Whose live unread counter goes up (Redis, sent as `unreadUpdated`). */
  liveUnreadUserIds: string[];
  /** Who may get a push notification (skipped while they are viewing the chat). */
  pushUserIds: string[];
  /** The sender's own socket, which is told via `messageSent` instead of `unreadUpdated`. */
  excludeSocketId?: string;
}

/**
 * Stores a message and delivers it: chat-list preview, unread counts, the
 * `newMessage` event and push notifications. Shared by user messages
 * (socket `sendMessage`) and server-generated ones (call history).
 */
export async function createAndDeliverMessage(io: Server, message: NewMessage, options: DeliveryOptions) {
  const attachments = message.attachments ?? [];
  const messageId = types.TimeUuid.now();
  const bucket = Math.floor(Date.now() / (24 * 60 * 60 * 1000));

  await cassandra.execute(
    `INSERT INTO messages (
      convoID, bucket, messageID, senderID, content, messageType, attachments, replyToMessageID, replyToMessageContent, replyToMessageType, replyToMessageSenderID, systemType, actorID, targetUserID
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      message.convoId,
      bucket,
      messageId,
      message.senderId,
      message.content,
      message.messageType,
      attachments,
      message.replyToMessageID ?? null,
      message.replyToMessageContent ?? null,
      message.replyToMessageType ?? null,
      message.replyToMessageSenderID ?? null,
      message.systemType ?? null,
      message.actorId ?? null,
      message.targetUserId ?? null,
    ],
    { prepare: true }
  );

  const conversationPreview = message.content.trim() || (attachments.length > 0 ? message.messageType : '');

  // leftAt: null skips people who left the group: a new message (even the
  // "X left" notice racing the leave request) must not bring it back for them.
  // A chat someone merely deleted (leftAt still null) does reappear, as intended.
  await prisma.conversationByUser.updateMany({
    where: { convoId: message.convoId, leftAt: null },
    data: {
      lastMessage: conversationPreview,
      lastMessageSenderId: message.senderId,
      lastMessageAt: new Date(),
      lastMessageId: messageId.toString(),
      isActive: true,
    },
  });

  if (options.unreadUserIds.length > 0) {
    await prisma.conversationByUser.updateMany({
      where: { convoId: message.convoId, userId: { in: options.unreadUserIds }, leftAt: null },
      data: { unreadCount: { increment: 1 } },
    });
  }

  const delivered = {
    ...message,
    attachments,
    replyToMessageID: message.replyToMessageID ?? null,
    replyToMessageContent: message.replyToMessageContent ?? null,
    replyToMessageType: message.replyToMessageType ?? null,
    replyToMessageSenderID: message.replyToMessageSenderID ?? null,
    systemType: message.systemType ?? null,
    actorId: message.actorId ?? null,
    targetUserId: message.targetUserId ?? null,
    messageId: messageId.toString(),
    bucket,
    createdAt: new Date().toISOString(),
  };

  const liveUnread = new Set(options.liveUnreadUserIds);
  const pushTargets = new Set(options.pushUserIds);
  const pushTasks: Promise<void>[] = [];

  for (const participantId of Array.from(new Set(options.participantIds.map(String)))) {
    io.to(`user:${participantId}`).emit('newMessage', delivered);

    await redis.hSet(
      `user:${participantId}:convo:meta`,
      message.convoId,
      JSON.stringify({
        lastMessage: conversationPreview,
        lastMessageAt: Date.now(),
        lastMessageSender: message.senderId,
      })
    );

    if (liveUnread.has(participantId)) {
      const unreadKey = `unread:${participantId}:${message.convoId}`;
      await redis.hSetNX(unreadKey, 'count', '0');
      const unreadCount = await redis.hIncrBy(unreadKey, 'count', 1);
      const target = io.to(`user:${participantId}`);
      (options.excludeSocketId ? target.except(options.excludeSocketId) : target).emit('unreadUpdated', {
        convoId: message.convoId,
        unreadCount,
      });
    }

    if (pushTargets.has(participantId)) {
      const [isOnline, isActivelyViewing] = await Promise.all([
        redis.exists(`user:online:${participantId}`),
        redis.sIsMember(`convo:${message.convoId}:activeViewers`, participantId),
      ]);
      if (!isOnline || !isActivelyViewing) {
        pushTasks.push(pushNotificationService.sendNewMessageNotification(participantId, { convoId: message.convoId }));
      }
    }
  }

  if (pushTasks.length > 0) {
    Promise.allSettled(pushTasks).then((results) => {
      const failed = results.filter((result) => result.status === 'rejected').length;
      if (failed > 0) {
        logger.warn('One or more push notification tasks failed after message creation', { failed, total: results.length });
      }
    });
  }

  return delivered;
}
