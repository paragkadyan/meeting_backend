import { cassandra } from "../db/cassa";
import { asyncHandler } from "../utils/asyncHandler";
import { apiResponse } from "../utils/apiResponse";
import { apiError } from "../utils/apiError";
import { v4 as uuidv4 } from "uuid";
import { redis } from "../db/redis";
import { prisma } from '../db/post';

import cassandraType from 'cassandra-driver';


export const createDirectChat = asyncHandler(async (req, res) => {
  const { participants, creatorID } = req.body;

  if (!Array.isArray(participants) || participants.length !== 2) {
    throw new apiError(400, "Direct chat must have exactly 2 participants");
  }

  if (!participants.includes(creatorID)) {
    throw new apiError(400, "Creator must be a participant");
  }

  const [u1, u2] = [...participants].sort();
  const pairKey = `${u1}_${u2}`;

  const result = await prisma.$transaction(async (tx) => {
    const existing = await tx.directChatLookup.findUnique({
      where: { pairKey }
    });

    if (existing) {
      return { convoId: existing.convoId, existed: true };
    }

    const conversation = await tx.conversation.create({
      data: {
        type: "direct",

        creator: {
          connect: { id: creatorID },
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

    return { convoId: conversation.id, existed: false };
  });

  if (result.existed) {
    return res.status(200).json(
      new apiResponse(200, { convoId: result.convoId }, "Direct chat already exists")
    );
  }

  await redis.sAdd(`convo:${result.convoId}:participants`, participants);

  return res.status(201).json(
    new apiResponse(201, { convoId: result.convoId }, "Conversation created successfully")
  );
});

export const createGroupChat = asyncHandler(async (req, res) => {
  const {
    groupName,
    participants,
    avatarURL,
    description,
  } = req.body;

  const creatorID = req.user!.id;

  if (!groupName || !Array.isArray(participants)) {
    throw new apiError(400, "Invalid group chat data");
  }

  const uniqueParticipants = Array.from(
    new Set([...participants, creatorID])
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
        avatarURL: avatarURL ?? null,
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
  participants?: string[];

};

export const getConversations = asyncHandler(async (req, res) => {
  const userId = req.user!.id;

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
            where: { userId: { not: userId } },
            select: { userId: true },
          },
          name: true,
          avatarURL: true,
          description: true,
          creatorId: true,
        },
      },
    },
  });

  const conversations: ConversationDTO[] = rows.map((r) => ({
    convoId: r.convoId,
    convoName: r.convoName,
    convoType: r.convoType,
    lastMessage: r.lastMessage,
    lastMessageSenderId: r.lastMessageSenderId,
    lastMessageAt: r.lastMessageAt,
    unreadCount: r.unreadCount,
    lastOpenedAt: r.lastOpenedAt,
    isPinned: r.isPinned,
    isArchived: r.isArchived,
    participants: r.conversation?.participants?.map((p) => p.userId) ?? [],
    isActive: r.isActive,
    leftAt: r.leftAt,
    name: r.conversation?.name ?? null,
    avatarURL: r.conversation?.avatarURL ?? null,
    description: r.conversation?.description ?? null,
    creatorId: r.conversation?.creatorId ?? null,
  }));

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


export const getMessages = asyncHandler(async (req, res) => {
  const { convoId } = req.body;
  const unreadCount = await redis.get(`convo:${convoId}:user:${req.user!.id}:unreadCount`);
  const limit = Math.max((Number(unreadCount) + 10) || 50);

  if (!convoId) {
    return res.status(400).json(new apiResponse(400, null, "convoId is required"));
  }

  const dayMs = 24 * 60 * 60 * 1000;
  const nowBucket = Math.floor(Date.now() / dayMs);

  const msgs: any[] = [];
  const lookbackDays = Math.max(1, Number(req.query.lookbackDays) || 30);

  const query = `
    SELECT convoID, bucket, messageID, senderID, content, messageType, attachments,
           isEdited, editedAt, isDeleted, deletedAt, replyToMessageID, toTimestamp(messageID) AS createdat, systemType, actorID, targetUserID 
    FROM messages
    WHERE convoID = ?
      AND bucket = ?
    LIMIT ?;
  `;

  for (let i = 0; i < lookbackDays && msgs.length < limit; i++) {
    const bucket = nowBucket - i;
    if (bucket < 0) break;

    const remaining = limit - msgs.length;

    const result = await cassandra.execute(
      query,
      [convoId, bucket, remaining],
      { prepare: true }
    );
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

  const reactionQuery = `
    SELECT messageID, reaction, userID
    FROM message_reactions
    WHERE convoID = ?
      AND messageID = ?;
  `;

  const reactionMap = new Map<string, Record<string, string[]>>();

  await Promise.all(
    msgs.map(async (msg) => {
      const result = await cassandra.execute(
        reactionQuery,
        [convoId, msg.messageid],
        { prepare: true }
      );

      if (!reactionMap.has(msg.messageid.toString())) {
        reactionMap.set(msg.messageid.toString(), {});
      }

      const reactions = reactionMap.get(msg.messageid.toString())!;

      for (const row of result.rows) {
        if (!reactions[row.reaction]) {
          reactions[row.reaction] = [];
        }
        reactions[row.reaction].push(row.userid.toString());
      }
    })
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
    markmessagesAsRead(convoId, req.user!.id, messagesToRead);
  }

  return res.status(200).json(
    new apiResponse(200, messages, "Messages fetched")
  );
});


export const getUsersBatch = asyncHandler(async (req, res) => {
  const { userIds } = req.body;
  if (!Array.isArray(userIds) || userIds.length === 0) {
    throw new apiError(400, "No user IDs provided");
  }

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
  const { userIds } = req.body;

  if (!Array.isArray(userIds) || userIds.length === 0) {
    throw new apiError(400, "userIds is required");
  }

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

  const messageTimeUuid = cassandraType.types.TimeUuid.fromString(lastMessageId);

  const messages: any[] = [];
  let bucket = Number(lastBucket);
  let remaining = limit;

  const sameBucketQuery = `
    SELECT convoID, bucket, messageID, senderID, content, messageType, attachments,
           isEdited, editedAt, isDeleted, deletedAt, replyToMessageID, toTimestamp(messageID) AS createdat, systemType, actorID, targetUserID
    FROM messages
    WHERE convoID = ?
      AND bucket = ?
      AND messageID < ?
    LIMIT ?;
  `;

  const olderBucketQuery = `
    SELECT convoID, bucket, messageID, senderID, content, messageType, attachments,
           isEdited, editedAt, isDeleted, deletedAt, replyToMessageID,  toTimestamp(messageID) AS createdat, systemType, actorID, targetUserID
    FROM messages
    WHERE convoID = ?
      AND bucket = ?
    LIMIT ?;
  `;

  const sameBucketResult = await cassandra.execute(
    sameBucketQuery,
    [convoId, bucket, messageTimeUuid, remaining],
    { prepare: true }
  );

  for (const row of sameBucketResult.rows) {
    if (!row.isdeleted) {
      messages.push(row);
      remaining--;
    }
    if (remaining === 0) break;
  }

  while (remaining > 0 && bucket > 0) {
    bucket--;

    const olderResult = await cassandra.execute(
      olderBucketQuery,
      [convoId, bucket, remaining],
      { prepare: true }
    );

    if (olderResult.rows.length === 0) continue;

    for (const row of olderResult.rows) {
      if (!row.isdeleted) {
        messages.push(row);
        remaining--;
      }
      if (remaining === 0) break;
    }
  }

  const reactionsQuery = `
    SELECT reaction, userID
    FROM message_reactions
    WHERE convoID = ?
      AND messageID = ?;
  `;

  await Promise.all(
    messages.map(async (msg) => {
      const result = await cassandra.execute(
        reactionsQuery,
        [convoId, msg.messageid],
        { prepare: true }
      );

      const reactions: Record<string, string[]> = {};

      for (const row of result.rows) {
        if (!reactions[row.reaction]) {
          reactions[row.reaction] = [];
        }
        reactions[row.reaction].push(row.userid.toString());
      }

      msg.reactions = reactions;
    })
  );


  messages.sort(
    (a, b) =>
      b.messageid.getDate().getTime() - a.messageid.getDate().getTime()
  );

  return res.status(200).json(
    new apiResponse(200, messages, "Older messages fetched")
  );
});

export const groupUpdate = asyncHandler(async (req, res) => {
  const { convoId, groupName, avatarURL, description } = req.body;
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

  const user = await prisma.user.findFirst({
    where: { id: userId },
  });
  if (!user) {
    throw new apiError(403, "Not a participant of the group");
  }
  if (convo.creatorId !== userId) {
    throw new apiError(403, "Only group admin can update the group");
  }

  const updateData: any = {};
  if (groupName !== undefined) updateData.name = groupName;
  if (avatarURL !== undefined) updateData.avatarURL = avatarURL;
  if (description !== undefined) updateData.description = description;

  await prisma.conversation.update({
    where: { id: convoId },
    data: updateData,
  });

  return res.status(200).json(
    new apiResponse(200, { convoId }, "Group updated successfully")
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
    throw new apiError(403, "Only group admins can add new users");
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

  for (const id of newUserIds) {
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
    throw new apiError(403, "Only group admins can kick users");
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

  const messageTimeUuid = cassandraType.types.TimeUuid.fromString(messageId);

  const query = `
    SELECT userID, readAt
    FROM message_reads
    WHERE convoID = ? AND messageID = ?
  `;

  const result = await cassandra.execute(
    query,
    [convoId, messageTimeUuid],
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
