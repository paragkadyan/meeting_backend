import { Request, Response } from "express";
import { asyncHandler } from "../utils/asyncHandler";
import { apiError } from "../utils/apiError";
import { apiResponse } from "../utils/apiResponse";
import {
  cancelCall,
  createCallParticipantToken,
  endCall,
  listConversationCalls,
  respondToCall,
  startCall,
} from "../services/call.service";

function authenticatedUserId(req: Request) {
  if (!req.user?.id) throw new apiError(401, "Unauthorized");
  return req.user.id;
}

export const startCallController = asyncHandler(async (req: Request, res: Response) => {
  const { conversationId } = req.body ?? {};
  if (typeof conversationId !== "string") throw new apiError(400, "conversationId is required");
  const call = await startCall(conversationId, authenticatedUserId(req));
  res.status(201).json(new apiResponse(201, {
    callId: call.id,
    conversationId: call.convoId,
    status: call.status,
    createdAt: call.createdAt,
  }, "Call started"));
});

export const callTokenController = asyncHandler(async (req: Request, res: Response) => {
  const data = await createCallParticipantToken(req.params.callId, authenticatedUserId(req));
  res.status(200).json(new apiResponse(200, data, "Call token generated"));
});

export const acceptCallController = asyncHandler(async (req: Request, res: Response) => {
  const data = await respondToCall(req.params.callId, authenticatedUserId(req), "accept");
  res.status(200).json(new apiResponse(200, data, "Call accepted"));
});

export const rejectCallController = asyncHandler(async (req: Request, res: Response) => {
  const data = await respondToCall(req.params.callId, authenticatedUserId(req), "reject");
  res.status(200).json(new apiResponse(200, data, "Call rejected"));
});

export const busyCallController = asyncHandler(async (req: Request, res: Response) => {
  const data = await respondToCall(req.params.callId, authenticatedUserId(req), "busy");
  res.status(200).json(new apiResponse(200, data, "Call marked busy"));
});

export const cancelCallController = asyncHandler(async (req: Request, res: Response) => {
  const data = await cancelCall(req.params.callId, authenticatedUserId(req));
  res.status(200).json(new apiResponse(200, data, "Call cancelled"));
});

export const endCallController = asyncHandler(async (req: Request, res: Response) => {
  const data = await endCall(req.params.callId, authenticatedUserId(req));
  res.status(200).json(new apiResponse(200, data, "Call ended"));
});

export const callHistoryController = asyncHandler(async (req: Request, res: Response) => {
  const conversationId = typeof req.query.conversationId === "string" ? req.query.conversationId : "";
  const calls = await listConversationCalls(conversationId, authenticatedUserId(req));
  res.status(200).json(new apiResponse(200, calls, "Call history"));
});
