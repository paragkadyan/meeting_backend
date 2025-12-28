import { cassandra } from "../db/cassa";
import { asyncHandler } from "../utils/asyncHandler";
import { errorHandler } from "../middleware/errorHandler.middleware";
import { apiResponse } from "../utils/apiResponse";
import { apiError } from "../utils/apiError";
import { v4 as uuidv4 } from "uuid";

export const createDirectChat = asyncHandler(async (req, res) => {
  const { participants, creatorID} = req.body;

    if (!participants || !Array.isArray(participants)) {
      throw new apiError(400, "Invalid conversation data");
    }

    const convoId = uuidv4();

    await cassandra.execute(
      `INSERT INTO conversations (convoID, type, creatorID, participants, createdAt, isActive)
       VALUES (?, ?, ?, ?, now(), true)`,
      [convoId, "direct", creatorID, participants],
      { prepare: true }
    );

    return res.status(201).json(new apiResponse(201, { convoId }, "Conversation created successfully"));
});

export const createGroupChat = asyncHandler(async (req, res) => {
  const { groupName, participants, creatorID, avatarURL, descrption } = req.body;

    if (!groupName || !participants || !Array.isArray(participants)) {
      throw new apiError(400, "Invalid group chat data");
    }

    const convoId = uuidv4();

    await cassandra.execute(
      `INSERT INTO conversations (convoID, type, creatorID, name, participants, avatarURL, description, createdAt, isActive)
       VALUES (?, ?, ?, ?, ?, ?, ?, now(), true)`,
      [convoId, "group", creatorID, groupName, participants, avatarURL || null, descrption || null],
      { prepare: true }
    );

    return res.status(201).json(new apiResponse(201, { convoId }, "Group conversation created successfully"));
});