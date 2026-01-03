import { cassandra } from "../db/cassa";
import { asyncHandler } from "../utils/asyncHandler";
import { errorHandler } from "../middleware/errorHandler.middleware";
import { apiResponse } from "../utils/apiResponse";
import { apiError } from "../utils/apiError";
import { v4 as uuidv4 } from "uuid";
import { redis } from "../db/redis";

export const createDirectChat = asyncHandler(async (req, res) => {
  const { participants, creatorID } = req.body;

  if (!participants || !Array.isArray(participants)) {
    throw new apiError(400, "Invalid conversation data");
  }

  if (participants.length !== 2) {
    throw new apiError(400, "Direct chat must have exactly 2 participants");
  }

  const convoId = uuidv4();

  try {
    await cassandra.execute(
      `INSERT INTO conversations 
     (convoID, type, creatorID, participants, createdAt, isActive)
     VALUES (?, ?, ?, ?, toTimestamp(now()), true)`,
      [convoId, "direct", creatorID, participants],
      { prepare: true }
    );
  } catch (e) {
    throw new apiError(500, "Failed to create conversation");
  }


  // await redis.sadd(`convo:${convoId}:participants`, ...participants);

  console.log("Participants added successfully");

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
  const userId = req.user?.id;

  try {
    const conversations = await cassandra.execute(
      `SELECT * FROM conversations WHERE creatorID = ? AND isActive = true ALLOW FILTERING`,
      [userId],
      { prepare: true }
    );

    return res.status(200).json(new apiResponse(200, conversations, "Conversations fetched successfully"));
  } catch (e) {
    console.error("Error fetching conversations:", e);
    throw new apiError(500, "Failed to fetch conversations");
  }
});
