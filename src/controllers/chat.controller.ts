import { cassandra } from "../db/cassa";
import { asyncHandler } from "../utils/asyncHandler";
import { errorHandler } from "../middleware/errorHandler.middleware";
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
  const convoId = uuidv4();

  const lookupResult = await cassandra.execute(
    `
    INSERT INTO direct_chat_lookup (pairKey, convoID, createdAt)
    VALUES (?, ?, toTimestamp(now()))
    IF NOT EXISTS
    `,
    [pairKey, convoId],
    { prepare: true }
  );

  const applied = lookupResult.rows[0]["[applied]"];

  if (!applied) {
    const existingConvoID = lookupResult.rows[0].convoid;
    return res.status(200).json(new apiResponse(200, { convoId: existingConvoID }, "Direct chat already exists"));
  }

  try {
    await cassandra.execute(
      `
      INSERT INTO conversations
      (convoID, type, creatorID, participants, createdAt, isActive)
      VALUES (?, 'direct', ?, ?, toTimestamp(now()), true)
      `,
      [convoId, creatorID, participants],
      { prepare: true }
    );

    await cassandra.execute(
      `
      INSERT INTO conversations_by_user
      (userID, convoID, convoType, lastMessageAt, isPinned, isArchived)
      VALUES (?, ?, 'direct', toTimestamp(now()), false, false)
      `,
      [creatorID, convoId],
      { prepare: true }
    );
  } catch (err) {
    await cassandra.execute(
      `DELETE FROM direct_chat_lookup WHERE pairKey = ?`,
      [pairKey],
      { prepare: true }
    );
    throw new apiError(500, "Failed to create conversation");
  }

 await redis.sAdd(`convo:${convoId}:participants`, participants);

  return res.status(201).json(new apiResponse(201, { convoId }, "Conversation created successfully"));
});

export const createGroupChat = asyncHandler(async (req, res) => {
  const { groupName, participants, creatorID, avatarURL, descrption } = req.body;

  if (!groupName || !participants || !Array.isArray(participants)) {
    throw new apiError(400, "Invalid group chat data");
  }

  if (participants.length < 2) {
    throw new apiError(400, "Group chat must have at least 2 participants");
  }

  const convoId = uuidv4();

  await cassandra.execute(
    `INSERT INTO conversations (convoID, type, creatorID, name, participants, avatarURL, description, createdAt, isActive)
       VALUES (?, ?, ?, ?, ?, ?, ?, now(), true)`,
    [convoId, "group", creatorID, groupName, participants, avatarURL || null, descrption || null],
    { prepare: true }
  );

  await redis.sadd(`convo:${convoId}:participants`, ...participants);

  return res.status(201).json(new apiResponse(201, { convoId }, "Group conversation created successfully"));
});

export const getConversations = asyncHandler(async (req, res) => {

  interface Conversation {
    convoId: string;
    convoName: string | null;
    convoType: string;
    lastMessageAt: Date | null;
    lastMessage: string | null;
    lastMessageSenderId: string | null;
    unreadCount: number;
    lastOpenedAt: Date | null;
    isPinned: boolean;
    isArchived: boolean;
    participants?: string[];
  }

  const userId = req.user!.id;

  const result = await cassandra.execute(
    `
    SELECT 
      convoID,
      convoName,
      convoType,
      lastMessageAt,
      lastMessage,
      lastMessageSenderID,
      unreadCount,
      lastOpenedAt,
      isPinned,
      isArchived
    FROM conversations_by_user
    WHERE userID = ?
    `,
    [userId],
    { prepare: true }
  );

  console.log(result);
  

  const conversations: Conversation[] = result.rows.map(row => ({
    convoId: row.convoid.toString(),
    convoName: row.convoname,
    convoType: row.convotype,
    lastMessageAt: row.lastmessageat,
    lastMessage: row.lastmessage,
    lastMessageSenderId: row.lastmessagesenderid?.toString() || null,
    unreadCount: row.unreadcount || 0,
    lastOpenedAt: row.lastopenedat,
    isPinned: row.ispinned,
    isArchived: row.isarchived
  }));


  if (!conversations || conversations.length === 0) {
    return res.status(200).json(new apiResponse(200, [], "No conversations found"));
  }

  const convoParticipantsMap: Record<string, string[]> = {};

for (const convo of conversations) {
  for (const convo of conversations) {
  const participants = await redis.sMembers(
    `convo:${convo.convoId}:participants`
  );

  convo.participants = Array.isArray(participants)
    ? participants
        .map(String)
        .filter(id => id !== userId)
    : [];
}}

  return res.status(200).json(new apiResponse(200,  conversations, "User IDs fetched"));
});

export const getMessages = asyncHandler(async (req, res) => {
  const { convoId } = req.body;
  const limit = Math.min(Number(req.query.limit) || 20, 50);

  const nowBucket = Math.floor(Date.now() / (24 * 60 * 60 * 1000));
  let bucket = nowBucket;

  const messages: any[] = [];

  while (messages.length < limit && bucket >= 0) {
    const remaining = limit - messages.length;

    const result = await cassandra.execute(
      `
      SELECT *
      FROM messages
      WHERE convoID = ?
        AND bucket = ?
      LIMIT ?
      `,
      [convoId, bucket, remaining],
      { prepare: true }
    );

    messages.push(...result.rows);
    bucket--;
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
