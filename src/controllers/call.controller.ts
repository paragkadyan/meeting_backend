import { Request, Response } from "express";
import { asyncHandler } from "../utils/asyncHandler";
import { apiError } from "../utils/apiError";
import { apiResponse } from "../utils/apiResponse";
import {
  cancelCall,
  createCallParticipantToken,
  endCall,
  getOpenCallsForUser,
  joinCall,
  leaveCall,
  listConversationCalls,
  respondToCall,
  startCall,
} from "../services/call.service";

function authenticatedUserId(req: Request) {
  if (!req.user?.id) throw new apiError(401, "Unauthorized");
  return req.user.id;
}

const callIdParam = (req: Request) => String(req.params.callId);

export const startCallController = asyncHandler(async (req: Request, res: Response) => {
  const { conversationId, type = "AUDIO" } = req.body ?? {};
  if (typeof conversationId !== "string") throw new apiError(400, "conversationId is required");
  const callType = String(type).toUpperCase();
  if (callType !== "AUDIO" && callType !== "VIDEO") throw new apiError(400, "type must be AUDIO or VIDEO");

  const call = await startCall(conversationId, authenticatedUserId(req), callType as "AUDIO" | "VIDEO");
  res.status(call.existing ? 200 : 201).json(new apiResponse(call.existing ? 200 : 201, {
    callId: call.id,
    conversationId: call.convoId,
    type: call.type,
    status: call.status,
    isGroup: call.isGroup,
    // true when the conversation already had a call ringing/in progress; the client joins that one.
    existing: call.existing,
    initiatedBy: call.initiatedBy,
    participants: call.participants,
    createdAt: call.createdAt,
  }, call.existing ? "Call already in progress" : "Call started"));
});

export const joinCallController = asyncHandler(async (req: Request, res: Response) => {
  const data = await joinCall(callIdParam(req), authenticatedUserId(req));
  res.status(200).json(new apiResponse(200, data, "Joined call"));
});

export const leaveCallController = asyncHandler(async (req: Request, res: Response) => {
  const data = await leaveCall(callIdParam(req), authenticatedUserId(req));
  res.status(200).json(new apiResponse(200, data, "Left call"));
});

export const activeCallsController = asyncHandler(async (req: Request, res: Response) => {
  const data = await getOpenCallsForUser(authenticatedUserId(req));
  res.status(200).json(new apiResponse(200, data, "Open calls"));
});

export const callTokenController = asyncHandler(async (req: Request, res: Response) => {
  const data = await createCallParticipantToken(callIdParam(req), authenticatedUserId(req));
  res.status(200).json(new apiResponse(200, data, "Call token generated"));
});

export const acceptCallController = asyncHandler(async (req: Request, res: Response) => {
  const data = await respondToCall(callIdParam(req), authenticatedUserId(req), "accept");
  res.status(200).json(new apiResponse(200, data, "Call accepted"));
});

export const rejectCallController = asyncHandler(async (req: Request, res: Response) => {
  const data = await respondToCall(callIdParam(req), authenticatedUserId(req), "reject");
  res.status(200).json(new apiResponse(200, data, "Call rejected"));
});

export const busyCallController = asyncHandler(async (req: Request, res: Response) => {
  const data = await respondToCall(callIdParam(req), authenticatedUserId(req), "busy");
  res.status(200).json(new apiResponse(200, data, "Call marked busy"));
});

export const cancelCallController = asyncHandler(async (req: Request, res: Response) => {
  const data = await cancelCall(callIdParam(req), authenticatedUserId(req));
  res.status(200).json(new apiResponse(200, data, "Call cancelled"));
});

export const endCallController = asyncHandler(async (req: Request, res: Response) => {
  const data = await endCall(callIdParam(req), authenticatedUserId(req));
  res.status(200).json(new apiResponse(200, data, "Call ended"));
});

export const callHistoryController = asyncHandler(async (req: Request, res: Response) => {
  const conversationId = typeof req.query.conversationId === "string" ? req.query.conversationId : "";
  const calls = await listConversationCalls(conversationId, authenticatedUserId(req));
  res.status(200).json(new apiResponse(200, calls, "Call history"));
});
