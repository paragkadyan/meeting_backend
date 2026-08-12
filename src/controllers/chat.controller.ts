import { cassandra } from "../db/cassa";
import { asyncHandler } from "../utils/asyncHandler";
import { apiResponse } from "../utils/apiResponse";
import { apiError } from "../utils/apiError";
import { v4 as uuidv4 } from "uuid";
import { redis } from "../db/redis";
import { prisma } from '../db/post';
import { getIO } from '../socket/index';
import { replaceGroupAvatar } from '../services/minioAsset.service';
import { types } from "cassandra-driver";

export const createDirectChat = asyncHandler(async (req, res) => {
  const { participants, creatorID } = req.body;

  if (!Array.isArray(participants)) {
    throw new apiError(400, "Participants must be an array");
  }

  if (!participants.includes(creatorID)) {
    throw new apiError(400, "Creator must be a participant");
  }

  // =========================
  // SELF CHAT
  // =========================
  const isSelfChat =
    participants.length === 1 ||
    (participants.length === 2 &&
      participants[0] === creatorID &&
      participants[1] === creatorID);

  if (isSelfChat) {
    const result = await prisma.$transaction(async (tx) => {
      // Check if self-chat already exists
      const existing = await tx.conversation.findFirst({
        where: {
          type: "self",
          creatorId: creatorID,
          participants: {
            some: {
              userId: creatorID,
            },
          },
        },
        select: {
          id: true,
        },
      });

      if (existing) {
        return {
          convoId: existing.id,
          existed: true,
        };
      }

      const conversation = await tx.conversation.create({
        data: {
          type: "self",
          creator: {
            connect: {
              id: creatorID,
            },
          },
        },
      });

      // Only ONE participant row
      await tx.conversationParticipant.create({
        data: {
          convoId: conversation.id,
          userId: creatorID,
          role: "member",
        },
      });

      await tx.conversationByUser.create({
        data: {
          userId: creatorID,
          convoId: conversation.id,
          convoType: "self",
          isActive: true,
          unreadCount: 0,
        },
      });

      return {
        convoId: conversation.id,
        existed: false,
      };
    });

    await redis.sAdd(
      `convo:${result.convoId}:participants`,
      creatorID
    );

    return res.status(result.existed ? 200 : 201).json(
      new apiResponse(
        result.existed ? 200 : 201,
        { convoId: result.convoId },
        result.existed
          ? "Self chat already exists"
          : "Self chat created successfully"
      )
    );
  }

  // =========================
  // NORMAL DIRECT CHAT
  // =========================

  if (participants.length !== 2) {
    throw new apiError(
      400,
      "Direct chat must have exactly 2 participants"
    );
  }

  const [u1, u2] = [...participants].sort();
  const pairKey = `${u1}_${u2}`;

  const isBlocked = await prisma.userBlock.findFirst({
    where: {
      OR: [
        {
          blockerId: u1,
          blockedId: u2,
        },
        {
          blockerId: u2,
          blockedId: u1,
        },
      ],
    },
  });

  if (isBlocked) {
    throw new Error("Cannot send message. User is blocked.");
  }

  const result = await prisma.$transaction(async (tx) => {
    const existing = await tx.directChatLookup.findUnique({
      where: {
        pairKey,
      },
    });

    if (existing) {
      return {
        convoId: existing.convoId,
        existed: true,
      };
    }

    const conversation = await tx.conversation.create({
      data: {
        type: "direct",
        creator: {
          connect: {
            id: creatorID,
          },
        },
      },
    });

    await tx.conversationParticipant.createMany({
      data: participants.map((userId) => ({
        convoId: conversation.id,
        userId,
        role: "member",
      })),
    });

    await tx.conversationByUser.createMany({
      data: participants.map((userId) => ({
        userId,
        convoId: conversation.id,
        convoType: "direct",
        isActive: true,
        unreadCount: 0,
      })),
    });

    await tx.directChatLookup.create({
      data: {
        pairKey,
        convoId: conversation.id,
      },
    });

    return {
      convoId: conversation.id,
      existed: false,
    };
  });

  if (result.existed) {
    return res.status(200).json(
      new apiResponse(
        200,
        { convoId: result.convoId },
        "Direct chat already exists"
      )
    );
  }

  await redis.sAdd(
    `convo:${result.convoId}:participants`,
    participants
  );

  return res.status(201).json(
    new apiResponse(
      201,
      { convoId: result.convoId },
      "Conversation created successfully"
    )
  );
});

export const createGroupChat = asyncHandler(async (req, res) => {
  const {
    groupName,
    description,
  } = req.body;

  // Parse participants if it's a JSON string (from FormData)
  let participants = req.body.participants;
  if (typeof participants === 'string') {
    try {
      participants = JSON.parse(participants);
    } catch (error) {
      throw new apiError(400, "Invalid participants format");
    }
  }

  const avatarFile = req.file;

  const creatorID = req.user!.id;

  if (!groupName || !Array.isArray(participants)) {
    throw new apiError(400, "Invalid group chat data");
  }

  const blockRelations = await prisma.userBlock.findMany({
    where: {
      OR: [
        {
          blockerId: req.user!.id,
          blockedId: { in: participants }
        },
        {
          blockerId: { in: participants },
          blockedId: req.user!.id
        }
      ]
    },
    select: {
      blockerId: true,
      blockedId: true
    }
  });

  const blockedSet = new Set<string>();

  blockRelations.forEach((b) => {
    if (b.blockerId === req.user!.id) {
      blockedSet.add(b.blockedId); // you blocked them
    } else {
      blockedSet.add(b.blockerId); // they blocked you
    }
  });

  const validParticipants = participants.filter(
    (id) => !blockedSet.has(id)
  );

  if (validParticipants.length !== participants.length) {
    throw new apiError(400, "Cannot add blocked users to group");
  }

  const uniqueParticipants = Array.from(
    new Set([...validParticipants, creatorID])
  );

  if (uniqueParticipants.length < 2) {
    throw new apiError(400, "Group chat must have at least 2 participants");
  }

  const conversation = await prisma.$transaction(async (tx) => {
    const convo = await tx.conversation.create({
      data: {
        type: "group",
        name: groupName,
        creatorId: creatorID,
        description: description ?? null,
      },
    });
    await tx.conversationParticipant.createMany({
      data: uniqueParticipants.map((userId) => ({
        convoId: convo.id,
        userId,
        role: userId === creatorID ? "admin" : "member",
      })),
    });
    await tx.conversationByUser.createMany({
      data: uniqueParticipants.map((userId) => ({
        userId,
        convoId: convo.id,
        convoType: "group",
        isActive: true,
        unreadCount: 0,
      })),
    });

    return convo;
  });

  if (avatarFile) {
    const avatarURL = await replaceGroupAvatar(conversation.id, avatarFile);
    await prisma.conversation.update({
      where: { id: conversation.id },
      data: { avatarURL },
    });
  }

  await redis.sAdd(
    `convo:${conversation.id}:participants`,
    uniqueParticipants
  );

  return res.status(201).json(
    new apiResponse(
      201,
      { convoId: conversation.id },
      "Group conversation created successfully"
    )
  );
});

type ConversationDTO = {
  convoId: string;
  convoName: string | null;
  convoType: string | null;
  lastMessage: string | null;
  lastMessageSenderId: string | null;
  lastMessageAt: Date | null;
  unreadCount: number;
  lastOpenedAt: Date | null;
  isPinned: boolean;
  isArchived: boolean;
  participants?: { userId: string; isBlocked: boolean }[];
  isBlocked: boolean;
  isActive: boolean;
  leftAt: Date | null;
  name: string | null;
  avatarURL: string | null;
  description: string | null;
  creatorId: string | null;
  adminIds: string[];
};

const normalizeUserIds = (input: unknown): string[] => {
  if (!Array.isArray(input) || input.length === 0) {
    throw new apiError(400, "No user IDs provided");
  }

  const userIds = input
    .map((entry) => {
      if (typeof entry === "string") {
        return entry.trim();
      }

      if (entry && typeof entry === "object" && "userId" in entry) {
        const { userId } = entry as { userId?: unknown };
        return typeof userId === "string" ? userId.trim() : "";
      }

      return "";
    })
    .filter((id): id is string => id.length > 0);

  if (userIds.length === 0) {
    throw new apiError(400, "No valid user IDs provided");
  }

  return [...new Set(userIds)];
};

export const getConversations = asyncHandler(async (req, res) => {
  const userId = req.user!.id;

  const blockedRelations = await prisma.userBlock.findMany({
    where: {
      OR: [
        { blockerId: userId },
        { blockedId: userId }
      ]
    },
    select: {
      blockerId: true,
      blockedId: true
    }
  });

  const blockedUserIds = new Set<string>();

  blockedRelations.forEach((b: { blockerId: string; blockedId: string; }) => {
    if (b.blockerId === userId) {
      blockedUserIds.add(b.blockedId);
    } else {
      blockedUserIds.add(b.blockerId);
    }
  });



  const rows = await prisma.conversationByUser.findMany({
    where: { userId },
    orderBy: [
      { isPinned: "desc" },
      { lastMessageAt: "desc" },
    ],
    select: {
      convoId: true,
      convoName: true,
      convoType: true,
      lastMessage: true,
      lastMessageSenderId: true,
      lastMessageAt: true,
      unreadCount: true,
      lastOpenedAt: true,
      isPinned: true,
      isArchived: true,
      isActive: true,
      leftAt: true,


      conversation: {
        select: {
          participants: {
            select: {
              userId: true,
              role: true,
            },
          },
          name: true,
          avatarURL: true,
          description: true,
          creatorId: true,
        },
      },
    },
  });

  const conversations: ConversationDTO[] = rows.map((r) => {
    const allParticipants = r.conversation?.participants ?? [];
    const participants = allParticipants
      .filter((p) => p.userId !== userId)
      .map((p) => ({
        userId: p.userId,
        isBlocked: blockedUserIds.has(p.userId),
      }));
    const adminIds = allParticipants
      .filter((p) => p.role === "admin")
      .map((p) => p.userId);

    const convoIsBlocked =
      r.convoType === "direct" &&
      participants.some((p) => p.isBlocked);

    return {
      convoId: r.convoId,
      convoName: convoIsBlocked ? "Blocked User" : r.convoName,
      convoType: r.convoType,
      lastMessage: r.lastMessage,
      lastMessageSenderId: r.lastMessageSenderId,
      lastMessageAt: r.lastMessageAt,
      unreadCount: r.unreadCount,
      lastOpenedAt: r.lastOpenedAt,
      isPinned: r.isPinned,
      isArchived: r.isArchived,
      participants,
      isBlocked: convoIsBlocked,

      isActive: r.isActive,
      leftAt: r.leftAt,

      name: convoIsBlocked ? "Blocked User" : r.conversation?.name ?? null,
      // CRITICAL FIX: Only return avatarURL for groups, not direct chats
      // Direct chats should use profileURL from User table
      avatarURL: convoIsBlocked ? null : (r.convoType === "group" ? r.conversation?.avatarURL ?? null : null),
      description: convoIsBlocked ? null : r.conversation?.description ?? null,
      creatorId: convoIsBlocked ? null : r.conversation?.creatorId ?? null,
      adminIds: convoIsBlocked ? [] : adminIds,
    };
  });
  return res
    .status(200)
    .json(new apiResponse(200, conversations, "Conversations fetched"));
});


const markmessagesAsRead = async (convoId: string, userId: string, messageIds: string[]) => {
  try {
    const queries = messageIds.map((messageId) => ({
      query: `
        INSERT INTO message_reads (convoID, messageID, userID, readAt)
        VALUES (?, ?, ?, ?)
      `,
      params: [convoId, messageId, userId, new Date()],
    }));
    await Promise.all(queries.map(async (q) => {
      await cassandra.execute(q.query, q.params, { prepare: true });
    }));
    await redis.set(`convo:${convoId}:user:${userId}:unreadCount`, '0');
    await prisma.conversationByUser.updateMany({
      where: {
        convoId,
        userId,
      },
      data: { unreadCount: 0 },
    });
  } catch (error) {
    throw new apiError(500, "Failed to mark messages as read");
  }
}

const getMessageReactions = async (
  convoId: string,
  messageIds: any[]
) => {
  if (messageIds.length === 0) {
    return new Map<string, Record<string, string[]>>();
  }

  const result = await cassandra.execute(
    `
    SELECT messageID, userID, reaction
    FROM message_reactions
    WHERE convoID = ?
      AND messageID IN ?;
    `,
    [convoId, messageIds],
    { prepare: true }
  );

  const reactionMap = new Map<string, Record<string, string[]>>();

  for (const row of result.rows) {
    const messageId = row.messageid.toString();

    if (!reactionMap.has(messageId)) {
      reactionMap.set(messageId, {});
    }

    const reactions = reactionMap.get(messageId)!;

    if (!reactions[row.reaction]) {
      reactions[row.reaction] = [];
    }

    reactions[row.reaction].push(row.userid.toString());
  }

  return reactionMap;
};

export const getMessages = asyncHandler(async (req, res) => {
  const { convoId } = req.body;
  const unreadCount = await redis.get(`convo:${convoId}:user:${req.user!.id}:unreadCount`);
  const unread = Number(unreadCount) || 0;
  const limit = Math.min(Math.max(unread + 10, 30), 100);

  if (!convoId) {
    throw new apiError(400, "convoId is required");
  }

  // Get this user's chat deletion boundary.
  const convoState = await prisma.conversationByUser.findUnique({
    where: {
      userId_convoId: {
        userId: req.user!.id,
        convoId,
      },
    },
    select: {
      deletedMessageId: true,
    },
  });

  const deletedMessageId = convoState?.deletedMessageId ?? null;

  const dayMs = 24 * 60 * 60 * 1000;
  const nowBucket = Math.floor(Date.now() / dayMs);

  const msgs: any[] = [];
  const lookbackDays = Math.max(1, Number(req.query.lookbackDays) || 30);

  let deletedMessageBucket: number | null = null;

  // Determine the bucket containing the deletion boundary.
  if (deletedMessageId) {
    const deletedMessageTime = types.TimeUuid.fromString(deletedMessageId).getDate();
    deletedMessageBucket = Math.floor(deletedMessageTime.getTime() / dayMs);
  }

  for (let i = 0; i < lookbackDays && msgs.length < limit; i++) {
    const bucket = nowBucket - i;

    if (bucket < 0) break;

    // If this entire bucket is older than the deletion boundary,
    // don't fetch it at all.
    if (
      deletedMessageBucket !== null &&
      bucket < deletedMessageBucket
    ) {
      break;
    }

    const remaining = limit - msgs.length;

    let result;

    // For the bucket containing deletedMessageId, only fetch messages
    // newer than the deletion boundary.
    if (
      deletedMessageId &&
      bucket === deletedMessageBucket
    ) {
      const query = `
        SELECT convoID, bucket, messageID, senderID, content, messageType, attachments,
               isEdited, editedAt, isDeleted, deletedAt, replyToMessageID,
               toTimestamp(messageID) AS createdat, systemType, actorID, targetUserID
        FROM messages
        WHERE convoID = ?
          AND bucket = ?
          AND messageID > ?
        LIMIT ?;
      `;

      result = await cassandra.execute(
        query,
        [
          convoId,
          bucket,
          types.TimeUuid.fromString(deletedMessageId),
          remaining,
        ],
        { prepare: true }
      );
    } else {
      const query = `
        SELECT convoID, bucket, messageID, senderID, content, messageType, attachments,
               isEdited, editedAt, isDeleted, deletedAt, replyToMessageID,
               toTimestamp(messageID) AS createdat, systemType, actorID, targetUserID
        FROM messages
        WHERE convoID = ?
          AND bucket = ?
        LIMIT ?;
      `;

      result = await cassandra.execute(
        query,
        [convoId, bucket, remaining],
        { prepare: true }
      );
    }

    for (const row of result.rows) {
      if (!row.isdeleted) {
        msgs.push(row);

        if (msgs.length === limit) break;
      }
    }
  }

  msgs.sort((a, b) => {
    return b.messageid.getDate().getTime() - a.messageid.getDate().getTime();
  });

  const messageIds = msgs.map(msg => msg.messageid);

  const reactionMap = await getMessageReactions(
    convoId,
    messageIds
  );

  const messages = msgs.map((msg) => ({
    messageId: msg.messageid.toString(),
    convoId: msg.convoid.toString(),
    senderId: msg.senderid.toString(),
    content: msg.content,
    bucket: msg.bucket,
    messageType: msg.messagetype,
    attachments: msg.attachments,
    replyToMessageId: msg.replytomessageid,
    isEdited: msg.isedited,
    editedAt: msg.editedat,
    isDeleted: msg.isdeleted,
    deletedAt: msg.deletedat,
    createdAt: msg.createdat,
    reactions: reactionMap.get(msg.messageid.toString()) || {},
    systemType: msg.systemtype,
    actorId: msg.actorid ? msg.actorid.toString() : null,
    targetUserId: msg.targetuserid ? msg.targetuserid.toString() : null,
  }));

  const messagesToRead = msgs
    .filter(msg => msg.senderid && msg.senderid.toString() !== req.user!.id.toString())
    .map(msg => msg.messageid.toString());

  if (Number(unreadCount) > 0) {
    await markmessagesAsRead(convoId, req.user!.id, messagesToRead);
  }

  return res.status(200).json(
    new apiResponse(200, messages, "Messages fetched")
  );
});


export const getUsersBatch = asyncHandler(async (req, res) => {
  const userIds = normalizeUserIds(req.body?.userIds);

  const result = await prisma.user.findMany({
    where: {
      id: { in: userIds },
    },
    select: {
      id: true,
      name: true,
      lname: true,
      profileURL: true,
      email: true,
      mobileNumber: true,
    },
  });

  if (result.length === 0) {
    throw new apiError(404, "No users found");
  }

  return res.status(200).json(
    new apiResponse(200, result, "User profiles fetched")
  );
});


export const userLastSeen = asyncHandler(async (req, res) => {
  const userIds = normalizeUserIds(req.body?.userIds);

  const keys = userIds.map((id: string) => `user:lastSeen:${id}`);
  const values = await redis.mGet(keys);

  const data = userIds.reduce<Record<string, string | null>>(
    (acc, userId, index) => {
      const value = values[index];
      acc[userId] = value ? new Date(Number(value)).toISOString() : null;
      return acc;
    },
    {}
  );

  return res.status(200).json(
    new apiResponse(200, data, "User last seen fetched")
  );
});

export const getOlderMessages = asyncHandler(async (req, res) => {
  const { convoId, lastMessageId, lastBucket } = req.body;
  const limit = Math.min(Number(req.query.limit) || 20, 100);

  if (!convoId || !lastMessageId || lastBucket === undefined) {
    return res
      .status(400)
      .json(new apiResponse(400, null, "Missing pagination params"));
  }

  // Get the user's delete cutoff for this conversation
  const convoState = await prisma.conversationByUser.findUnique({
    where: {
      userId_convoId: {
        userId: req.user!.id,
        convoId,
      },
    },
    select: {
      deletedMessageId: true,
    },
  });

  const deletedMessageId = convoState?.deletedMessageId || null;

  const messages: any[] = [];

  let bucket = Number(lastBucket);
  let remaining = limit;

  const MAX_BUCKET_SCAN = 5;
  let scannedBuckets = 0;

  const FETCH_MULTIPLIER = 2;

  const sameBucketQuery = `
    SELECT convoID, bucket, messageID, senderID, content, messageType,
           attachments, isEdited, editedAt, isDeleted, deletedAt,
           replyToMessageID, toTimestamp(messageID) AS createdAt,
           systemType, actorID, targetUserID
    FROM messages
    WHERE convoID = ?
      AND bucket = ?
      AND messageID < ?
    LIMIT ?;
  `;

  const olderBucketQuery = `
    SELECT convoID, bucket, messageID, senderID, content, messageType,
           attachments, isEdited, editedAt, isDeleted, deletedAt,
           replyToMessageID, toTimestamp(messageID) AS createdAt,
           systemType, actorID, targetUserID
    FROM messages
    WHERE convoID = ?
      AND bucket = ?
    LIMIT ?;
  `;

  const sameBucketResult = await cassandra.execute(
    sameBucketQuery,
    [
      convoId,
      bucket,
      lastMessageId,
      remaining * FETCH_MULTIPLIER,
    ],
    { prepare: true }
  );

  for (const row of sameBucketResult.rows) {

    // Hide messages that existed before the user deleted the chat
    if (
      !row.isdeleted &&
      (!deletedMessageId ||
        row.messageid.toString() > deletedMessageId)
    ) {
      messages.push(row);
      remaining--;
    }

    if (remaining === 0) break;
  }

  while (
    remaining > 0 &&
    bucket > 0 &&
    scannedBuckets < MAX_BUCKET_SCAN
  ) {
    bucket--;
    scannedBuckets++;

    const olderResult = await cassandra.execute(
      olderBucketQuery,
      [
        convoId,
        bucket,
        remaining * FETCH_MULTIPLIER,
      ],
      { prepare: true }
    );

    if (olderResult.rows.length === 0) continue;

    for (const row of olderResult.rows) {

      // Hide messages that existed before the user deleted the chat
      if (
        !row.isdeleted &&
        (!deletedMessageId ||
          row.messageid.toString() > deletedMessageId)
      ) {
        messages.push(row);
        remaining--;
      }

      if (remaining === 0) break;
    }
  }

  if (messages.length === 0) {
    return res.status(200).json(
      new apiResponse(200, [], "Older messages fetched")
    );
  }

  // Get reactions for all fetched messages
  const messageIds = messages.map(
    (msg) => msg.messageid
  );

  const reactionMap = await getMessageReactions(
    convoId,
    messageIds
  );

  // Format response
  const formattedMessages = messages.map((msg) => ({
    messageId: msg.messageid.toString(),
    convoId: msg.convoid.toString(),
    senderId: msg.senderid.toString(),
    content: msg.content,
    bucket: msg.bucket,
    messageType: msg.messagetype,
    attachments: msg.attachments,
    replyToMessageId: msg.replytomessageid,
    isEdited: msg.isedited,
    editedAt: msg.editedat,
    isDeleted: msg.isdeleted,
    deletedAt: msg.deletedat,
    createdAt: msg.createdat,

    reactions:
      reactionMap.get(msg.messageid.toString()) || {},

    systemType: msg.systemtype,
    actorId: msg.actorid
      ? msg.actorid.toString()
      : null,
    targetUserId: msg.targetuserid
      ? msg.targetuserid.toString()
      : null,
  }));

  return res.status(200).json(
    new apiResponse(
      200,
      formattedMessages,
      "Older messages fetched"
    )
  );
});

export const getNewerMessages = asyncHandler(async (req, res) => {
  const { convoId, lastMessageId, lastBucket } = req.body;
  const limit = Math.min(Number(req.query.limit) || 20, 100);

  if (!convoId || !lastMessageId || lastBucket === undefined) {
    return res
      .status(400)
      .json(new apiResponse(400, null, "Missing pagination params"));
  }

  // Get this user's chat deletion point
  const convoState = await prisma.conversationByUser.findUnique({
    where: {
      userId_convoId: {
        userId: req.user!.id,
        convoId,
      },
    },
    select: {
      deletedMessageId: true,
    },
  });

  const deletedMessageId = convoState?.deletedMessageId ?? null;

  const messages: any[] = [];

  let bucket = Number(lastBucket);
  let remaining = limit;

  const MAX_BUCKET_SCAN = 5;
  let scannedBuckets = 0;
  const FETCH_MULTIPLIER = 2;

  // Messages newer than lastMessageId in the same bucket
  const sameBucketQuery = `
    SELECT convoID, bucket, messageID, senderID, content, messageType,
           attachments, isEdited, editedAt, isDeleted, deletedAt,
           replyToMessageID, toTimestamp(messageID) AS createdAt,
           systemType, actorID, targetUserID
    FROM messages
    WHERE convoID = ?
      AND bucket = ?
      AND messageID > ?
    LIMIT ?;
  `;

  // Messages from newer buckets
  const newerBucketQuery = `
    SELECT convoID, bucket, messageID, senderID, content, messageType,
           attachments, isEdited, editedAt, isDeleted, deletedAt,
           replyToMessageID, toTimestamp(messageID) AS createdAt,
           systemType, actorID, targetUserID
    FROM messages
    WHERE convoID = ?
      AND bucket = ?
    LIMIT ?;
  `;

  // 1. Get newer messages from the same bucket
  const sameBucketResult = await cassandra.execute(
    sameBucketQuery,
    [
      convoId,
      bucket,
      lastMessageId,
      remaining * FETCH_MULTIPLIER,
    ],
    { prepare: true }
  );

  for (const row of sameBucketResult.rows) {
    if (row.isdeleted) continue;

    // If user deleted the chat, don't return messages
    // at or before their deletion point.
    if (
      deletedMessageId &&
      row.messageid.toString() <= deletedMessageId
    ) {
      continue;
    }

    messages.push(row);
    remaining--;

    if (remaining === 0) break;
  }

  // 2. Move into newer buckets if required
  while (
    remaining > 0 &&
    scannedBuckets < MAX_BUCKET_SCAN
  ) {
    bucket++;
    scannedBuckets++;

    const newerResult = await cassandra.execute(
      newerBucketQuery,
      [
        convoId,
        bucket,
        remaining * FETCH_MULTIPLIER,
      ],
      { prepare: true }
    );

    if (newerResult.rows.length === 0) {
      continue;
    }

    for (const row of newerResult.rows) {
      if (row.isdeleted) continue;

      // Apply the same per-user deletion cutoff.
      if (
        deletedMessageId &&
        row.messageid.toString() <= deletedMessageId
      ) {
        continue;
      }

      messages.push(row);
      remaining--;

      if (remaining === 0) break;
    }
  }

  if (messages.length === 0) {
    return res.status(200).json(
      new apiResponse(200, [], "Newer messages fetched")
    );
  }

  // 3. Get reactions
  const messageIds = messages.map(
    (msg) => msg.messageid
  );

  const reactionMap = await getMessageReactions(
    convoId,
    messageIds
  );

  // 4. Format response
  const formattedMessages = messages.map((msg) => ({
    messageId: msg.messageid.toString(),
    convoId: msg.convoid.toString(),
    senderId: msg.senderid.toString(),
    content: msg.content,
    bucket: msg.bucket,
    messageType: msg.messagetype,
    attachments: msg.attachments,
    replyToMessageId: msg.replytomessageid,
    isEdited: msg.isedited,
    editedAt: msg.editedat,
    isDeleted: msg.isdeleted,
    deletedAt: msg.deletedat,
    createdAt: msg.createdat,

    reactions:
      reactionMap.get(msg.messageid.toString()) || {},

    systemType: msg.systemtype,

    actorId: msg.actorid
      ? msg.actorid.toString()
      : null,

    targetUserId: msg.targetuserid
      ? msg.targetuserid.toString()
      : null,
  }));

  return res.status(200).json(
    new apiResponse(
      200,
      formattedMessages,
      "Newer messages fetched"
    )
  );
});

export const getMessagesAround = asyncHandler(async (req, res) => {
  const { convoId, messageId } = req.body;

  const limit = Math.min(Number(req.query.limit) || 15, 50);
  const before = Math.floor(limit / 2);
  const after = limit - before - 1;

  if (!convoId || !messageId) {
    throw new apiError(400, "convoId and messageId are required");
  }

  /*
   * Check whether this user deleted the conversation.
   *
   * If deletedAt exists, messages before that point are no longer
   * part of this user's visible chat history.
   */
  const convoState = await prisma.conversationByUser.findUnique({
    where: {
      userId_convoId: {
        userId: req.user!.id,
        convoId,
      },
    },
    select: {
      deletedAt: true,
    },
  });

  /*
   * TIMEUUID -> timestamp
   *
   * We need the target message timestamp so we can determine
   * whether it existed before the user's deletion point.
   */
  let targetDate: Date;

  try {
    targetDate = types.TimeUuid.fromString(messageId).getDate();
  } catch {
    throw new apiError(400, "Invalid messageId");
  }

  /*
   * If the chat was deleted for this user and the target message
   * existed before/on the deletion point, don't allow jumping to it.
   */
  if (
    convoState?.deletedAt &&
    targetDate.getTime() <= convoState.deletedAt.getTime()
  ) {
    throw new apiError(
      404,
      "Message not found"
    );
  }

  const dayMs = 24 * 60 * 60 * 1000;
  const targetBucket = Math.floor(
    targetDate.getTime() / dayMs
  );

  const beforeQuery = `
    SELECT convoID, bucket, messageID, senderID, content,
           messageType, attachments, isEdited, editedAt,
           isDeleted, deletedAt, replyToMessageID,
           toTimestamp(messageID) AS createdAt,
           systemType, actorID, targetUserID
    FROM messages
    WHERE convoID = ?
      AND bucket = ?
      AND messageID < ?
    LIMIT ?;
  `;

  const afterQuery = `
    SELECT convoID, bucket, messageID, senderID, content,
           messageType, attachments, isEdited, editedAt,
           isDeleted, deletedAt, replyToMessageID,
           toTimestamp(messageID) AS createdAt,
           systemType, actorID, targetUserID
    FROM messages
    WHERE convoID = ?
      AND bucket = ?
      AND messageID > ?
    LIMIT ?;
  `;

  const targetQuery = `
    SELECT convoID, bucket, messageID, senderID, content,
           messageType, attachments, isEdited, editedAt,
           isDeleted, deletedAt, replyToMessageID,
           toTimestamp(messageID) AS createdAt,
           systemType, actorID, targetUserID
    FROM messages
    WHERE convoID = ?
      AND bucket = ?
      AND messageID = ?
    LIMIT 1;
  `;

  const [targetResult, beforeResult, afterResult] =
    await Promise.all([
      cassandra.execute(
        targetQuery,
        [convoId, targetBucket, messageId],
        { prepare: true }
      ),

      cassandra.execute(
        beforeQuery,
        [convoId, targetBucket, messageId, before * 2],
        { prepare: true }
      ),

      cassandra.execute(
        afterQuery,
        [convoId, targetBucket, messageId, after * 2],
        { prepare: true }
      ),
    ]);

  if (targetResult.rowLength === 0) {
    throw new apiError(404, "Message not found");
  }

  const beforeMessages = beforeResult.rows
    .filter((row) => !row.isdeleted)
    .filter(
      (row) =>
        !convoState?.deletedAt ||
        row.createdat > convoState.deletedAt
    )
    .slice(-before);

  const targetMessage = targetResult.rows[0];

  const afterMessages = afterResult.rows
    .filter((row) => !row.isdeleted)
    .filter(
      (row) =>
        !convoState?.deletedAt ||
        row.createdat > convoState.deletedAt
    )
    .slice(0, after);

  const messages = [
    ...beforeMessages,
    targetMessage,
    ...afterMessages,
  ];

  messages.sort(
    (a, b) =>
      a.messageid.getDate().getTime() -
      b.messageid.getDate().getTime()
  );

  const messageIds = messages.map(
    (msg) => msg.messageid
  );

  const reactionMap = await getMessageReactions(
    convoId,
    messageIds
  );

  const formattedMessages = messages.map((msg) => ({
    messageId: msg.messageid.toString(),
    convoId: msg.convoid.toString(),
    senderId: msg.senderid.toString(),
    content: msg.content,
    bucket: msg.bucket,
    messageType: msg.messagetype,
    attachments: msg.attachments,
    replyToMessageId: msg.replytomessageid,
    isEdited: msg.isedited,
    editedAt: msg.editedat,
    isDeleted: msg.isdeleted,
    deletedAt: msg.deletedat,
    createdAt: msg.createdat,
    reactions:
      reactionMap.get(msg.messageid.toString()) || {},
    systemType: msg.systemtype,
    actorId: msg.actorid
      ? msg.actorid.toString()
      : null,
    targetUserId: msg.targetuserid
      ? msg.targetuserid.toString()
      : null,
  }));

  return res.status(200).json(
    new apiResponse(
      200,
      {
        messages: formattedMessages,
        targetMessageId: messageId,
        targetBucket,
      },
      "Messages around target message fetched"
    )
  );
});

export const groupUpdate = asyncHandler(async (req, res) => {
  const { convoId, groupName, description } = req.body;
  const avatarFile = req.file;
  if (!convoId) {
    throw new apiError(400, "convoId is required");
  }
  const convo = await prisma.conversation.findUnique({
    where: { id: convoId },
  });
  if (!convo || convo.type !== "group") {
    throw new apiError(404, "Group conversation not found");
  }
  const userId = req.user!.id;

  const participant = await prisma.conversationParticipant.findUnique({
    where: {
      convoId_userId: {
        convoId,
        userId,
      },
    },
  });
  if (!participant || participant.role !== "admin") {
    throw new apiError(403, "Only group admins can update group details");
  }

  const updateData: any = {};
  if (groupName !== undefined) updateData.name = groupName;
  if (avatarFile) updateData.avatarURL = await replaceGroupAvatar(convoId, avatarFile, convo.avatarURL);
  if (req.body.avatarURL !== undefined && !avatarFile) {
    throw new apiError(400, 'Upload group avatars as multipart file field "avatar"');
  }
  if (description !== undefined) updateData.description = description;

  const updatedConvo = await prisma.conversation.update({
    where: { id: convoId },
    data: updateData,
    select: {
      name: true,
      avatarURL: true,
      description: true
    }
  });

  try {
    const io = getIO();
    io.to(`room:${convoId}`).emit('roomUpdated', {
      convoId,
      groupName: updatedConvo.name,
      avatarURL: updatedConvo.avatarURL,
      description: updatedConvo.description
    });
  } catch (error) {
    console.error('Failed to emit socket event:', error);
  }

  return res.status(200).json(
    new apiResponse(200, {
      convoId,
      name: updatedConvo.name,
      avatarURL: updatedConvo.avatarURL,
      description: updatedConvo.description
    }, "Group updated successfully")
  );
});

export const updateConversationPreferences = asyncHandler(async (req, res) => {
  const { convoId, isArchived, isPinned } = req.body;
  const userId = req.user!.id;

  if (!convoId) {
    throw new apiError(400, "convoId is required");
  }

  if (isArchived === undefined && isPinned === undefined) {
    throw new apiError(400, "At least one of isArchived or isPinned is required");
  }

  const updateData: { isArchived?: boolean; isPinned?: boolean } = {};

  if (isArchived !== undefined) {
    if (typeof isArchived !== "boolean") {
      throw new apiError(400, "isArchived must be a boolean");
    }
    updateData.isArchived = isArchived;
  }

  if (isPinned !== undefined) {
    if (typeof isPinned !== "boolean") {
      throw new apiError(400, "isPinned must be a boolean");
    }
    updateData.isPinned = isPinned;
  }

  const conversationByUser = await prisma.conversationByUser.findUnique({
    where: {
      userId_convoId: { userId, convoId }
    },
    select: {
      userId: true,
      convoId: true
    }
  });

  if (!conversationByUser) {
    throw new apiError(404, "Conversation not found for this user");
  }

  const updatedConversation = await prisma.conversationByUser.update({
    where: {
      userId_convoId: { userId, convoId }
    },
    data: updateData,
    select: {
      convoId: true,
      isArchived: true,
      isPinned: true
    }
  });

  return res.status(200).json(
    new apiResponse(200, updatedConversation, "Conversation preferences updated successfully")
  );
});

export const groupLeaveByUser = asyncHandler(async (req, res) => {
  const { convoId } = req.body;
  const userId = req.user!.id;

  if (!convoId) {
    return res.status(400).json({ message: "convoId is required" });
  }
  const convo = await prisma.conversation.findUnique({
    where: { id: convoId },
    select: { type: true }
  });

  if (!convo) {
    return res.status(404).json({ message: "Conversation not found" });
  }

  if (convo.type !== "group") {
    return res.status(400).json({ message: "Cannot leave direct chat" });
  }

  const participant = await prisma.conversationParticipant.findUnique({
    where: {
      convoId_userId: { convoId, userId }
    }
  });

  if (participant?.role === "admin") {
    throw new apiError(403, "Group admins cannot leave the group. Please assign another admin before leaving.");
  }

  if (!participant) {
    return res.status(400).json({ message: "Not a group member" });
  }

  await prisma.$transaction([
    prisma.conversationParticipant.delete({
      where: {
        convoId_userId: { convoId, userId }
      }
    }),

    prisma.conversationByUser.update({
      where: {
        userId_convoId: { userId, convoId }
      },
      data: {
        isActive: false,
        leftAt: new Date()
      }
    })
  ]);
  await redis.sRem(`convo:${convoId}:participants`, userId);

  return res.status(200).json(
    new apiResponse(200, { convoId }, "Left group successfully")
  );
});

export const addNewUsersToGroup = asyncHandler(async (req, res) => {
  const { convoId, newUserIds } = req.body;
  const userId = req.user!.id;

  if (!convoId || !Array.isArray(newUserIds) || newUserIds.length === 0) {
    throw new apiError(400, "Invalid request data");
  }

  const convo = await prisma.conversation.findUnique({
    where: { id: convoId },
  });

  if (!convo || convo.type !== "group") {
    throw new apiError(404, "Group conversation not found");
  }

  const participant = await prisma.conversationParticipant.findUnique({
    where: {
      convoId_userId: {
        convoId,
        userId,
      },
    },
  });
  if (!participant || participant.role !== "admin") {
    throw new apiError(403, "Only group admins can add members");
  }

  const blockRelations = await prisma.userBlock.findMany({
    where: {
      OR: [
        {
          blockerId: req.user!.id,
          blockedId: { in: newUserIds }
        },
        {
          blockerId: { in: newUserIds },
          blockedId: req.user!.id
        }
      ]
    },
    select: {
      blockerId: true,
      blockedId: true
    }
  });

  const blockedSet = new Set<string>();

  blockRelations.forEach((b) => {
    if (b.blockerId === req.user!.id) {
      blockedSet.add(b.blockedId);
    } else {
      blockedSet.add(b.blockerId);
    }
  });

  const validParticipants = newUserIds.filter(
    (id) => !blockedSet.has(id)
  );

  if (validParticipants.length !== newUserIds.length) {
    throw new apiError(400, "Cannot add blocked users to group");
  }

  const convoUsers = await prisma.conversationByUser.findMany({
    where: { convoId },
    select: { userId: true, isActive: true },
  });

  const existingParticipants = await prisma.conversationParticipant.findMany({
    where: { convoId },
    select: { userId: true },
  });

  const convoUserMap = new Map(
    convoUsers.map(u => [u.userId, u])
  );

  const activeParticipantIds = new Set(
    existingParticipants.map(p => p.userId)
  );

  const usersToCreate: string[] = [];
  const usersToReactivate: string[] = [];

  for (const id of validParticipants) {
    if (activeParticipantIds.has(id)) continue;

    const convoUser = convoUserMap.get(id);

    if (convoUser && !convoUser.isActive) {
      usersToReactivate.push(id);
    } else if (!convoUser) {
      usersToCreate.push(id);
    }
  }

  if (!usersToCreate.length && !usersToReactivate.length) {
    return res.status(200).json(
      new apiResponse(200, null, "Users already in group")
    );
  }

  await prisma.$transaction(async (tx) => {

    if (usersToReactivate.length) {
      await tx.conversationParticipant.createMany({
        data: usersToReactivate.map(id => ({
          convoId,
          userId: id,
          role: "member",
        })),
      });

      await tx.conversationByUser.updateMany({
        where: {
          convoId,
          userId: { in: usersToReactivate },
        },
        data: {
          isActive: true,
          leftAt: null,
        },
      });
    }

    if (usersToCreate.length) {
      await tx.conversationParticipant.createMany({
        data: usersToCreate.map(id => ({
          convoId,
          userId: id,
          role: "member",
        })),
      });

      await tx.conversationByUser.createMany({
        data: usersToCreate.map(id => ({
          userId: id,
          convoId,
          convoType: "group",
          isActive: true,
          unreadCount: 0,
        })),
      });
    }
  });

  await redis.sAdd(
    `convo:${convoId}:participants`,
    [...usersToCreate, ...usersToReactivate]
  );

  return res.status(200).json(
    new apiResponse(200, { usersAdded: [...usersToCreate, ...usersToReactivate] }, "Users added to group")
  );
});

export const kickUserFromGroup = asyncHandler(async (req, res) => {
  const { convoId, userIdToKick } = req.body;
  const userId = req.user!.id;
  if (!convoId || !userIdToKick) {
    throw new apiError(400, "Invalid request data");
  }
  const convo = await prisma.conversation.findUnique({
    where: { id: convoId },
  });
  if (!convo || convo.type !== "group") {
    throw new apiError(404, "Group conversation not found");
  }
  const participant = await prisma.conversationParticipant.findUnique({
    where: {
      convoId_userId: {
        convoId,
        userId,
      },
    },
  });
  if (!participant || participant.role !== "admin") {
    throw new apiError(403, "Only group admins can remove members");
  }
  const userToKick = await prisma.conversationParticipant.findUnique({
    where: {
      convoId_userId: {
        convoId,
        userId: userIdToKick,
      },
    },
  })
  if (!userToKick) {
    throw new apiError(404, "User to kick not found in group");
  }
  if (userToKick.role === "admin") {
    throw new apiError(403, "Cannot kick admin");
  }
  await prisma.$transaction([
    prisma.conversationParticipant.delete({
      where: {
        convoId_userId: { convoId, userId: userIdToKick }
      }
    }),
    prisma.conversationByUser.update({
      where: {
        userId_convoId: { userId: userIdToKick, convoId }
      },
      data: {
        isActive: false,
        leftAt: new Date()
      }
    })
  ]);
  await redis.sRem(`convo:${convoId}:participants`, userIdToKick);
  return res.status(200).json(
    new apiResponse(200, { userIdKicked: userIdToKick }, "User kicked from group")
  );
});

export const getMessageReadReceipts = asyncHandler(async (req, res) => {
  const { messageId } = req.body;
  const { convoId } = req.body;

  if (!messageId || !convoId) {
    throw new apiError(400, "messageId and convoId are required");
  }

  const query = `
    SELECT userID, readAt
    FROM message_reads
    WHERE convoID = ? AND messageID = ?
  `;

  const result = await cassandra.execute(
    query,
    [convoId, messageId],
    { prepare: true }
  );

  const readReceipts = result.rows.map(row => ({
    userId: row.userid,
    readAt: row.readat
  }));

  return res.status(200).json(
    new apiResponse(200, readReceipts, "Message read receipts fetched")
  );
});


export const lastReadMessageByUser = asyncHandler(async (req, res) => {
  const { convoId, userIds } = req.body;
  if (!convoId || !Array.isArray(userIds) || userIds.length === 0) {
    throw new apiError(400, "convoId and userIds are required");
  }
  const lastReadMap: Record<string, string | null> = {};

  await Promise.all(userIds.map(async (userId: string) => {
    const lastReadMessageId = await redis.get(`conv:${convoId}:user:${userId}:lastRead`);
    lastReadMap[userId] = lastReadMessageId;
  }));
  return res.status(200).json(
    new apiResponse(200, lastReadMap, "Last read messages fetched")
  );
});

export const assignAdminRole = asyncHandler(async (req, res) => {
  const { convoId, userIdToPromote } = req.body;
  const userId = req.user!.id;
  if (!convoId || !userIdToPromote) {
    throw new apiError(400, "Invalid request data");
  }
  const convo = await prisma.conversation.findUnique({
    where: { id: convoId },
  });
  if (!convo || convo.type !== "group") {
    throw new apiError(404, "Group conversation not found");
  }
  const participant = await prisma.conversationParticipant.findUnique({
    where: {
      convoId_userId: {
        convoId,
        userId,
      },
    },
  });
  if (!participant || participant.role !== "admin") {
    throw new apiError(403, "Only group admins can assign admin role");
  }
  const userToPromote = await prisma.conversationParticipant.findUnique({
    where: {
      convoId_userId: {
        convoId,
        userId: userIdToPromote,
      },
    },
  });
  if (!userToPromote) {
    throw new apiError(404, "User to promote not found in group");
  }
  if (userToPromote.role === "admin") {
    throw new apiError(400, "User is already an admin");
  }
  await prisma.conversationParticipant.update({
    where: {
      convoId_userId: { convoId, userId: userIdToPromote }
    },
    data: {
      role: "admin"
    }
  });
  return res.status(200).json(
    new apiResponse(200, { userIdPromoted: userIdToPromote }, "User promoted to admin")
  );
});

export const removeAdminRole = asyncHandler(async (req, res) => {
  const { convoId, userIdToDemote, userIdToPromote } = req.body;
  const userId = req.user!.id;

  if (!convoId || !userIdToDemote || !userIdToPromote) {
    throw new apiError(400, "convoId, userIdToDemote, and userIdToPromote are required");
  }

  if (userIdToDemote === userIdToPromote) {
    throw new apiError(400, "Replacement admin must be a different user");
  }

  const convo = await prisma.conversation.findUnique({
    where: { id: convoId },
  });
  if (!convo || convo.type !== "group") {
    throw new apiError(404, "Group conversation not found");
  }

  const actingParticipant = await prisma.conversationParticipant.findUnique({
    where: {
      convoId_userId: {
        convoId,
        userId,
      },
    },
  });
  if (!actingParticipant || actingParticipant.role !== "admin") {
    throw new apiError(403, "Only group admins can remove admin role");
  }

  const [userToDemoteParticipant, userToPromoteParticipant] = await Promise.all([
    prisma.conversationParticipant.findUnique({
      where: {
        convoId_userId: {
          convoId,
          userId: userIdToDemote,
        },
      },
    }),
    prisma.conversationParticipant.findUnique({
      where: {
        convoId_userId: {
          convoId,
          userId: userIdToPromote,
        },
      },
    }),
  ]);

  if (!userToDemoteParticipant) {
    throw new apiError(404, "Admin to demote not found in group");
  }
  if (userToDemoteParticipant.role !== "admin") {
    throw new apiError(400, "Selected user is not an admin");
  }
  if (!userToPromoteParticipant) {
    throw new apiError(404, "Replacement user not found in group");
  }
  if (userToPromoteParticipant.role === "admin") {
    throw new apiError(400, "Replacement user is already an admin");
  }

  await prisma.$transaction([
    prisma.conversationParticipant.update({
      where: {
        convoId_userId: { convoId, userId: userIdToDemote },
      },
      data: {
        role: "member",
      },
    }),
    prisma.conversationParticipant.update({
      where: {
        convoId_userId: { convoId, userId: userIdToPromote },
      },
      data: {
        role: "admin",
      },
    }),
  ]);

  return res.status(200).json(
    new apiResponse(
      200,
      { userIdDemoted: userIdToDemote, userIdPromoted: userIdToPromote },
      "Admin role transferred successfully"
    )
  );
});

export const groupLeaveByAdmin = asyncHandler(async (req, res) => {
  const { convoId } = req.body;
  const userId = req.user!.id;
  if (!convoId) {
    throw new apiError(400, "convoId is required");
  }
  const convo = await prisma.conversation.findUnique({
    where: { id: convoId },
    select: { type: true }
  });
  if (!convo) {
    throw new apiError(404, "Conversation not found");
  }
  if (convo.type !== "group") {
    throw new apiError(400, "Cannot leave direct chat");
  }
  const participant = await prisma.conversationParticipant.findUnique({
    where: {
      convoId_userId: {
        convoId,
        userId
      }
    }
  });
  if (!participant) {
    throw new apiError(404, "Participant not found");
  }
  if (participant.role !== "admin") {
    throw new apiError(403, "You are not group admin");
  }
  const otherParticipants = await prisma.conversationParticipant.findMany({
    where: {
      convoId,
      userId: { not: userId }
    },
    select: { userId: true, role: true }
  });
  const hasOtherUsers = otherParticipants.length > 0;
  const hasOtherAdmin = otherParticipants.some(p => p.role === "admin");

  if (hasOtherUsers && !hasOtherAdmin) {
    throw new apiError(400, "Assign another admin before leaving");
  }
  if (!hasOtherUsers) {
    await prisma.conversation.update({
      where: { id: convoId },
      data: { isActive: false }
    });
  }
  await prisma.$transaction([
    prisma.conversationParticipant.delete({
      where: {
        convoId_userId: { convoId, userId }
      }
    }),
    prisma.conversationByUser.update({
      where: {
        userId_convoId: { userId, convoId }
      },
      data: {
        isActive: false,
        leftAt: new Date()
      }
    })
  ]);
  await redis.sRem(`convo:${convoId}:participants`, userId);
  return res.status(200).json(
    new apiResponse(200, { convoId }, "Left group successfully")
  );
});

export const deleteChatForUser = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const { convoId } = req.params;

  if (!convoId) {
    throw new apiError(400, "convoId is required");
  }

  const conversation = await prisma.conversationByUser.findUnique({
    where: {
      userId_convoId: {
        userId,
        convoId,
      },
    },
    select: {
      lastMessageId: true,
    },
  });

  if (!conversation) {
    throw new apiError(404, "Conversation not found");
  }

  // Last message visible to this user before deleting the chat.
  const deletedMessageId = conversation.lastMessageId;

  await prisma.conversationByUser.update({
    where: {
      userId_convoId: {
        userId,
        convoId,
      },
    },
    data: {
      deletedAt: new Date(),
      deletedMessageId,

      isActive: false,
      unreadCount: 0,

      lastMessage: null,
      lastMessageSenderId: null,
      lastMessageAt: null,
      lastMessageId: null,
    },
  });

  return res.status(200).json(
    new apiResponse(
      200,
      {
        convoId,
        deletedMessageId,
      },
      "Chat deleted for this user"
    )
  );
});