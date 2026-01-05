import { cassandra } from "../db/cassa";
import { asyncHandler } from "../utils/asyncHandler";
import { apiResponse } from "../utils/apiResponse";
import { apiError } from "../utils/apiError";
import { v4 as uuidv4 } from "uuid";
import { redis } from "../db/redis";
import { prisma } from '../db/post';


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
        creatorId: creatorID,
        participants: {
          createMany: {
            data: participants.map((userId) => ({ userId }))
          }
        },
        convoStates: {
          createMany: {
            data: participants.map((userId) => ({
              userId,
              convoType: "direct"
            }))
          }
        }
      }
    });

    await tx.directChatLookup.create({
      data: {
        pairKey,
        convoId: conversation.id
      }
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
  const { groupName, participants, creatorID, avatarURL, description } = req.body;

  if (!groupName || !Array.isArray(participants)) {
    throw new apiError(400, "Invalid group chat data");
  }

  if (participants.length < 2) {
    throw new apiError(400, "Group chat must have at least 2 participants");
  }

  if (!participants.includes(creatorID)) {
    participants.push(creatorID);
  }

  const conversation = await prisma.$transaction(async (tx) => {
    return tx.conversation.create({
      data: {
        type: "group",
        name: groupName,
        creatorId: creatorID,
        avatarURL: avatarURL ?? null,
        description: description ?? null,
        participants: {
          createMany: {
            data: participants.map((userId) => ({ userId }))
          }
        },
        convoStates: {
          createMany: {
            data: participants.map((userId) => ({
              userId,
              convoType: "group"
            }))
          }
        }
      }
    });
  });

  await redis.sAdd(
    `convo:${conversation.id}:participants`,
    participants
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

      conversation: {
        select: {
          participants: {
            where: { userId: { not: userId } },
            select: { userId: true },
          },
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
  }));

  return res
    .status(200)
    .json(new apiResponse(200, conversations, "Conversations fetched"));
});



export const getMessages = asyncHandler(async (req, res) => {
  const { convoId } = req.body;
  const limit = Math.min(Number(req.query.limit) || 20, 50);

  if (!convoId) {
    return res.status(400).json(new apiResponse(400, null, "convoId is required"));
  }

  const dayMs = 24 * 60 * 60 * 1000;
  const nowBucket = Math.floor(Date.now() / dayMs);

  const messages: any[] = [];
  const lookbackDays = Math.max(1, Number(req.query.lookbackDays) || 30); // safety cap

  const query = `
    SELECT convoID, bucket, messageID, senderID, content, messageType, attachments,
           isEdited, editedAt, isDeleted, deletedAt, replyToMessageID
    FROM messages
    WHERE convoID = ?
      AND bucket = ?
    LIMIT ?;
  `;

  for (let i = 0; i < lookbackDays && messages.length < limit; i++) {
    const bucket = nowBucket - i;
    if (bucket < 0) break;

    const remaining = limit - messages.length;

    const result = await cassandra.execute(
      query,
      [convoId, bucket, remaining],
      { prepare: true } 
    );

    messages.push(...result.rows);
  }

  messages.sort((a: any, b: any) => {
    const at = a.messageid?.getDate ? a.messageid.getDate().getTime() : 0;
    const bt = b.messageid?.getDate ? b.messageid.getDate().getTime() : 0;
    return bt - at;
  });

  return res.status(200).json(
    new apiResponse(200, messages.slice(0, limit), "Messages fetched")
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
